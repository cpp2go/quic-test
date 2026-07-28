package quic

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
	"quic-test/quic/utils"
	"quic-test/quic/wire"
)

// ConnectionState holds information about the QUIC connection.
type ConnectionState struct {
	Version           protocol.Version
	SupportsDatagrams bool
}

// Connection represents a single QUIC connection.
type Connection struct {
	version protocol.Version

	// Connection IDs
	destConnID protocol.ConnectionID // destination connection ID (remote)
	srcConnID  protocol.ConnectionID // source connection ID (local)

	// UDP connection
	conn       net.PacketConn
	remoteAddr net.Addr

	// Stream management
	streams   map[protocol.StreamID]*Stream
	streamsMu sync.Mutex
	nextBidi  int64 // next outgoing bidirectional stream number
	nextUni   int64 // next outgoing unidirectional stream number

	// Accept channel for incoming streams
	acceptCh chan *Stream

	// Packet handling
	packetCh  chan []byte
	readyCh   chan struct{} // closed when first packet is received (client uses this to wait for server)
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	closeMu   sync.Mutex

	// Packet number management
	sendPN        atomic.Int64
	recvPN        protocol.PacketNumber
	largestRecvPN protocol.PacketNumber

	// Send queue
	sendMu  sync.Mutex
	sendBuf []byte

	// Flow control
	maxStreamsBidi int64
	maxStreamsUni  int64
	connMaxData    protocol.ByteCount
	connReadData   protocol.ByteCount

	// ACK handling
	recvPacketHistory        []protocol.PacketNumber
	sendPacketHistory        []sentPacket
	ackTimer                 *time.Timer
	immediateAckCh           chan struct{}
	ackElicitingSinceLastAck int
	lastAckTime              time.Time

	// RTT estimation & congestion control
	rttStats   *utils.RTTStats
	congestion utils.Controller

	// Retransmit queue
	retransmitQueue []sentPacket

	// Loss detection
	largestSentPN       protocol.PacketNumber
	largestAckedPN      protocol.PacketNumber
	detectedLostPackets []protocol.PacketNumber

	// Remote max stream data tracking
	remoteMaxStreamData map[protocol.StreamID]protocol.ByteCount

	// Local stream data limits
	localMaxStreamData map[protocol.StreamID]protocol.ByteCount

	// Connection state
	connected atomic.Bool
	closed    atomic.Bool

	// Current max packet size (starts at InitialPacketSize, may increase via MTU discovery)
	maxPacketSize protocol.ByteCount

	logf func(format string, args ...interface{})
}

type sentPacket struct {
	pn             protocol.PacketNumber
	data           []byte
	time           time.Time
	isAckEliciting bool
	lost           bool
	retransmitted  bool
}

func newServerConnection(conn net.PacketConn, remoteAddr net.Addr, destConnID, srcConnID protocol.ConnectionID, version protocol.Version, cfg *Config) *Connection {
	c := &Connection{
		version:             version,
		destConnID:          destConnID,
		srcConnID:           srcConnID,
		conn:                conn,
		remoteAddr:          remoteAddr,
		streams:             make(map[protocol.StreamID]*Stream),
		acceptCh:            make(chan *Stream, 100),
		packetCh:            make(chan []byte, 1000),
		readyCh:             make(chan struct{}),
		done:                make(chan struct{}),
		sendBuf:             make([]byte, 0, protocol.MaxPacketBufferSize),
		maxStreamsBidi:      100,
		maxStreamsUni:       100,
		connMaxData:         1048576, // 1MB initial
		recvPacketHistory:   make([]protocol.PacketNumber, 0),
		sendPacketHistory:   make([]sentPacket, 0),
		immediateAckCh:      make(chan struct{}, 100),
		rttStats:            utils.NewRTTStats(),
		congestion:          newController(cfg),
		retransmitQueue:     make([]sentPacket, 0),
		detectedLostPackets: make([]protocol.PacketNumber, 0),
		remoteMaxStreamData: make(map[protocol.StreamID]protocol.ByteCount),
		localMaxStreamData:  make(map[protocol.StreamID]protocol.ByteCount),
		maxPacketSize:       protocol.InitialPacketSize,
		logf: func(format string, args ...interface{}) {
			fmt.Printf("[server] "+format+"\n", args...)
		},
	}
	c.connected.Store(true)
	c.congestion.OnPacketSent(0) // initialize
	// Pass RTT stats to congestion controller
	c.initCongestionRTT()
	go c.run()
	return c
}

func (c *Connection) initCongestionRTT() {
	switch cc := c.congestion.(type) {
	case *utils.BBR:
		cc.SetRTTStats(c.rttStats)
	case *utils.Cubic:
		cc.SetRTT(c.rttStats.SmoothedRTT())
	}
}

func newClientConnection(conn net.PacketConn, remoteAddr net.Addr, destConnID, srcConnID protocol.ConnectionID, version protocol.Version, cfg *Config) *Connection {
	c := &Connection{
		version:             version,
		destConnID:          destConnID,
		srcConnID:           srcConnID,
		conn:                conn,
		remoteAddr:          remoteAddr,
		streams:             make(map[protocol.StreamID]*Stream),
		acceptCh:            make(chan *Stream, 100),
		packetCh:            make(chan []byte, 1000),
		readyCh:             make(chan struct{}),
		done:                make(chan struct{}),
		sendBuf:             make([]byte, 0, protocol.MaxPacketBufferSize),
		maxStreamsBidi:      100,
		maxStreamsUni:       100,
		connMaxData:         1048576,
		recvPacketHistory:   make([]protocol.PacketNumber, 0),
		sendPacketHistory:   make([]sentPacket, 0),
		immediateAckCh:      make(chan struct{}, 100),
		rttStats:            utils.NewRTTStats(),
		congestion:          newController(cfg),
		retransmitQueue:     make([]sentPacket, 0),
		detectedLostPackets: make([]protocol.PacketNumber, 0),
		remoteMaxStreamData: make(map[protocol.StreamID]protocol.ByteCount),
		localMaxStreamData:  make(map[protocol.StreamID]protocol.ByteCount),
		maxPacketSize:       protocol.InitialPacketSize,
		logf: func(format string, args ...interface{}) {
			fmt.Printf("[client] "+format+"\n", args...)
		},
	}
	c.connected.Store(true)
	c.congestion.OnPacketSent(0) // initialize
	c.initCongestionRTT()
	go c.run()
	go c.startReadLoop()
	return c
}

// startReadLoop reads UDP packets and feeds them to the connection's packet handler.
// This is used for client connections that own their own UDP socket.
func (c *Connection) startReadLoop() {
	buf := make([]byte, protocol.MaxPacketBufferSize*2)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := c.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-c.done:
				return
			default:
				c.logf("read error: %v", err)
				return
			}
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		c.handlePacket(data)
	}
}

// updateRemoteAddr updates the remote address (used for connection migration).
func (c *Connection) updateRemoteAddr(newAddr net.Addr) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	c.remoteAddr = newAddr
}

// WaitReady waits for the connection to receive its first packet.
func (c *Connection) WaitReady(ctx context.Context) error {
	select {
	case <-c.readyCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return c.getCloseErr()
	}
}

// LocalAddr returns the local address.
func (c *Connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote address.
func (c *Connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// AcceptStream blocks until a new stream is accepted from the peer.
func (c *Connection) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case s := <-c.acceptCh:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, c.getCloseErr()
	}
}

// OpenStream opens a new bidirectional stream.
func (c *Connection) OpenStream() (*Stream, error) {
	return c.openStream(protocol.StreamTypeBidi)
}

// OpenStreamSync opens a new bidirectional stream, blocking if needed.
func (c *Connection) OpenStreamSync(ctx context.Context) (*Stream, error) {
	return c.openStream(protocol.StreamTypeBidi)
}

func (c *Connection) openStream(stype protocol.StreamType) (*Stream, error) {
	if c.closed.Load() {
		return nil, io.ErrClosedPipe
	}

	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	var streamNum int64
	if stype == protocol.StreamTypeBidi {
		streamNum = c.nextBidi
		c.nextBidi++
	} else {
		streamNum = c.nextUni
		c.nextUni++
	}

	streamID := protocol.StreamIDFromParts(streamNum, stype, protocol.PerspectiveClient)
	s := newStream(streamID, c)
	c.streams[streamID] = s

	c.logf("opened stream %d", streamID)
	return s, nil
}

// CloseWithError closes the connection with an error.
func (c *Connection) CloseWithError(code protocol.ErrCode, reason string) error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeErr = fmt.Errorf("%s (code %d)", reason, code)

		// Send CONNECTION_CLOSE frame
		frame := &wire.ConnectionCloseFrame{
			IsApplication: true,
			ErrorCode:     code,
			ReasonPhrase:  reason,
		}
		c.sendFrame(frame)

		// Close all streams
		c.streamsMu.Lock()
		for _, s := range c.streams {
			s.mu.Lock()
			s.closed = true
			s.readCond.Broadcast()
			s.writeCond.Broadcast()
			s.mu.Unlock()
		}
		c.streamsMu.Unlock()

		close(c.done)
	})
	return nil
}

// Context returns a context that is cancelled when the connection is closed.
func (c *Connection) Context() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-c.done
		cancel()
	}()
	return ctx
}

func (c *Connection) getCloseErr() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return c.closeErr
}

// run is the main event loop for the connection.
func (c *Connection) run() {
	ackTicker := time.NewTicker(25 * time.Millisecond)
	defer ackTicker.Stop()

	for {
		select {
		case data := <-c.packetCh:
			c.handleReceivedPacket(data)
		case <-c.immediateAckCh:
			c.sendAckIfNeeded()
		case <-ackTicker.C:
			c.sendAckIfNeeded()
		case <-c.done:
			return
		}
	}
}

// handlePacket is called by the transport to deliver a packet.
func (c *Connection) handlePacket(data []byte) {
	select {
	case c.packetCh <- data:
	default:
		c.logf("packet channel full, dropping packet (%d bytes)", len(data))
	}
}

func (c *Connection) handleReceivedPacket(data []byte) {
	// Signal that we received the first packet (for client synchronization)
	select {
	case <-c.readyCh:
		// already signaled
	default:
		close(c.readyCh)
	}

	// Parse the packet
	hdr, payload, err := wire.ParsePacket(data)
	if err != nil {
		c.logf("error parsing packet: %v", err)
		return
	}

	if hdr != nil {
		// Long header packet
		c.handleLongHeaderPacket(hdr, payload)
	} else {
		// Short header packet - payload is the raw data
		consumed, pn, pnLen, err := wire.ParseShortHeader(payload, c.destConnID.Len())
		if err != nil {
			c.logf("error parsing short header: %v", err)
			return
		}
		// Decode packet number
		decodedPN := protocol.DecodePacketNumber(pnLen, c.largestRecvPN, pn)
		if decodedPN > c.largestRecvPN {
			c.largestRecvPN = decodedPN
		}
		c.recvPN = decodedPN

		// Record for ACK
		c.recordReceivedPacket(decodedPN)

		// Parse frames from payload
		frameData := payload[consumed:]
		c.parseAndHandleFrames(frameData)
	}
}

func (c *Connection) handleLongHeaderPacket(hdr *wire.Header, payload []byte) {
	// For our simplified QUIC without encryption, we process long header packets directly
	eh, err := hdr.ParseExtended(payload)
	if err != nil || eh == nil {
		return
	}

	decodedPN := protocol.DecodePacketNumber(eh.PacketNumberLen, c.largestRecvPN, eh.PacketNumber)
	if decodedPN > c.largestRecvPN {
		c.largestRecvPN = decodedPN
	}
	c.recvPN = decodedPN

	// Record for ACK
	c.recordReceivedPacket(decodedPN)

	// Parse frames from payload (after packet number)
	frameStart := int(eh.ParsedLen() - hdr.ParsedLen())
	if frameStart < len(payload) {
		frameData := payload[frameStart:]
		c.parseAndHandleFrames(frameData)
	}
}

func (c *Connection) parseAndHandleFrames(data []byte) {
	parser := &wire.FrameParser{}
	offset := 0

	for offset < len(data) {
		frame, consumed, err := parser.ParseNext(data[offset:])
		if err != nil {
			c.logf("error parsing frame: %v", err)
			break
		}
		offset += consumed
		c.handleFrame(frame)
	}
}

func (c *Connection) handleFrame(f wire.Frame) {
	switch ff := f.(type) {
	case *wire.StreamFrame:
		c.handleStreamFrame(ff)
	case *wire.AckFrame:
		c.handleAckFrame(ff)
	case *wire.PingFrame:
		// PING received - no response needed for our simplified QUIC
	case *wire.MaxDataFrame:
		c.handleMaxDataFrame(ff)
	case *wire.MaxStreamDataFrame:
		c.handleMaxStreamDataFrame(ff)
	case *wire.MaxStreamsFrame:
		c.handleMaxStreamsFrame(ff)
	case *wire.ConnectionCloseFrame:
		c.handleConnectionCloseFrame(ff)
	case *wire.ResetStreamFrame:
		c.handleResetStreamFrame(ff)
	case *wire.StopSendingFrame:
		c.handleStopSendingFrame(ff)
	case *wire.CryptoFrame:
		// Ignore crypto frames (no encryption)
	case *wire.DataBlockedFrame, *wire.StreamDataBlockedFrame, *wire.StreamsBlockedFrame:
		// These are informational, we can ignore them
	case *wire.PaddingFrame:
		// Padding is ignored
	case *wire.PathChallengeFrame:
		// Respond with PATH_RESPONSE to validate new path
		c.logf("received PATH_CHALLENGE, responding with PATH_RESPONSE")
		c.sendFrame(&wire.PathResponseFrame{Data: ff.Data})
	case *wire.PathResponseFrame:
		// New path validated, nothing else to do
		c.logf("received PATH_RESPONSE, new path validated")
	default:
		c.logf("unhandled frame type: %T", f)
	}
}

func (c *Connection) handleStreamFrame(f *wire.StreamFrame) {
	c.streamsMu.Lock()
	s, exists := c.streams[f.StreamID]
	if !exists {
		// New incoming stream
		s = newStream(f.StreamID, c)
		c.streams[f.StreamID] = s
		c.streamsMu.Unlock()

		// Set initial flow control for this stream
		c.localMaxStreamData[f.StreamID] = 65536
		c.sendMaxStreamData(f.StreamID, 65536)

		// Try to accept
		select {
		case c.acceptCh <- s:
		default:
			c.logf("accept channel full, dropping stream %d", f.StreamID)
		}
	} else {
		c.streamsMu.Unlock()
	}

	s.handleStreamData(f.Offset, f.Data, f.Fin)
}

func (c *Connection) handleAckFrame(f *wire.AckFrame) {
	largestAcked := f.AckRanges[0].Largest
	now := time.Now()

	// Track largest ACKed PN
	if largestAcked > c.largestAckedPN {
		c.largestAckedPN = largestAcked
	}

	// Update RTT using the largest newly acknowledged packet
	if largestAckedPN := int64(largestAcked); largestAckedPN >= 0 {
		for _, sp := range c.sendPacketHistory {
			if sp.pn == largestAcked && !sp.time.IsZero() {
				c.rttStats.UpdateRTT(sp.time, f.DelayTime, now)
				break
			}
		}
	}

	acknowledgedBytes := int64(0)
	var newHistory []sentPacket

	// Process each sent packet: check if acked or lost
	for _, sp := range c.sendPacketHistory {
		if sp.lost {
			continue
		}

		// Check if this packet is acknowledged
		acked := false
		for _, ar := range f.AckRanges {
			if sp.pn >= ar.Smallest && sp.pn <= ar.Largest {
				acked = true
				break
			}
		}

		if acked {
			// Update congestion: ack this packet
			packetSize := int64(len(sp.data))
			acknowledgedBytes += packetSize
			c.congestion.OnPacketAcked(packetSize, int64(sp.pn), now)
			sp.lost = true
		} else if !sp.retransmitted {
			// Check if this packet should be considered lost (time-based, RFC 9002)
			if sp.isAckEliciting && sp.pn < largestAcked {
				lossDelay := c.rttStats.LossDelay()
				if time.Since(sp.time) > lossDelay {
					c.logf("快速重传: pn=%d 超时=%v 已过=%v",
						sp.pn, lossDelay, time.Since(sp.time))
					sp.lost = true
					sp.retransmitted = true
					c.retransmitQueue = append(c.retransmitQueue, sp)
					c.congestion.OnPacketLost(int64(c.largestSentPN))
				}
			}
		}

		if !sp.lost && !sp.retransmitted {
			newHistory = append(newHistory, sp)
		}
	}

	c.sendPacketHistory = newHistory

	// Try to retransmit lost packets
	c.flushRetransmitQueue()
}

// flushRetransmitQueue retransmits any packets that were detected as lost.
func (c *Connection) flushRetransmitQueue() {
	if len(c.retransmitQueue) == 0 {
		return
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	var remaining []sentPacket
	for _, sp := range c.retransmitQueue {
		packetSize := int64(len(sp.data))
		// 正常发送路径已绕过拥塞窗口，重传也必须绕过，否则丢的包永远无法恢复
		if !c.congestion.CanSend(packetSize) {
			c.logf("重传拥塞告警: cwnd=%d inFlight=%d, 仍重传 pn=%d",
				c.congestion.Cwnd(), c.congestion.BytesInFlight(), sp.pn)
		}
		_, err := c.conn.WriteTo(sp.data, c.remoteAddr)
		if err != nil {
			c.logf("重传错误 pn=%d: %v", sp.pn, err)
			remaining = append(remaining, sp)
		} else {
			c.logf("重传 pn=%d 成功", sp.pn)
		}
	}
	c.retransmitQueue = remaining
}

func (c *Connection) handleMaxDataFrame(f *wire.MaxDataFrame) {
	// Update connection-level flow control
	c.connMaxData = f.MaximumData
}

func (c *Connection) handleMaxStreamDataFrame(f *wire.MaxStreamDataFrame) {
	c.streamsMu.Lock()
	s, exists := c.streams[f.StreamID]
	if exists {
		s.updateMaxData(f.MaximumStreamData)
	}
	c.streamsMu.Unlock()
}

func (c *Connection) handleMaxStreamsFrame(f *wire.MaxStreamsFrame) {
	if f.Type == protocol.StreamTypeBidi {
		c.maxStreamsBidi = f.MaxStreams
	} else {
		c.maxStreamsUni = f.MaxStreams
	}
}

func (c *Connection) handleConnectionCloseFrame(f *wire.ConnectionCloseFrame) {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeErr = fmt.Errorf("remote closed: %s (code %d)", f.ReasonPhrase, f.ErrorCode)

		c.streamsMu.Lock()
		for _, s := range c.streams {
			s.mu.Lock()
			s.closed = true
			s.readCond.Broadcast()
			s.writeCond.Broadcast()
			s.mu.Unlock()
		}
		c.streamsMu.Unlock()

		close(c.done)
	})
}

func (c *Connection) handleResetStreamFrame(f *wire.ResetStreamFrame) {
	c.streamsMu.Lock()
	s, exists := c.streams[f.StreamID]
	c.streamsMu.Unlock()
	if exists {
		s.mu.Lock()
		s.reset = true
		s.finalSize = f.FinalSize
		s.readCond.Broadcast()
		s.mu.Unlock()
	}
}

func (c *Connection) handleStopSendingFrame(f *wire.StopSendingFrame) {
	c.streamsMu.Lock()
	s, exists := c.streams[f.StreamID]
	c.streamsMu.Unlock()
	if exists {
		s.CancelWrite(f.ErrorCode)
	}
}

// sendStreamData sends data on a stream.
// sendStreamData sends stream data and returns the actual number of bytes sent
// (may be less than len(data) due to packet size truncation).
func (c *Connection) sendStreamData(streamID protocol.StreamID, offset protocol.ByteCount, data []byte, fin bool) int {
	frame := &wire.StreamFrame{
		StreamID:       streamID,
		Offset:         offset,
		Data:           data,
		Fin:            fin,
		DataLenPresent: true,
	}
	c.sendFrame(frame)
	// sendFrame 可能截断了 sf.Data，返回实际发送的字节数
	return len(frame.Data)
}

// sendMaxStreamData sends a MAX_STREAM_DATA frame.
func (c *Connection) sendMaxStreamData(streamID protocol.StreamID, maxData protocol.ByteCount) {
	frame := &wire.MaxStreamDataFrame{
		StreamID:          streamID,
		MaximumStreamData: maxData,
	}
	c.sendFrame(frame)
}

// sendFrame serializes and sends a frame.
func (c *Connection) sendFrame(frame wire.Frame) {
	if c.closed.Load() {
		return
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	// 计算实际包开销，精确截断流数据以避免超 MTU
	if sf, ok := frame.(*wire.StreamFrame); ok {
		// 短包头: 1(type) + connID + pnLen(最大4)
		shortHdrOverhead := 1 + c.destConnID.Len() + 4
		// 帧开销: 1(type) + streamID(varint) + [offset(varint)] + dataLen(varint)
		frameOverhead := 1
		frameOverhead += int(quicvarint.Len(uint64(sf.StreamID)))
		if sf.Offset > 0 {
			frameOverhead += int(quicvarint.Len(uint64(sf.Offset)))
		}
		frameOverhead += int(quicvarint.Len(uint64(len(sf.Data))))
		maxData := int(c.maxPacketSize) - shortHdrOverhead - frameOverhead
		if maxData < 0 {
			maxData = 0
		}
		if len(sf.Data) > maxData {
			sf.Data = sf.Data[:maxData]
			sf.DataLenPresent = true
		}
	}

	// Check congestion window (advisory - still send but log for diagnostics)
	frameLen := estimateFrameLength(frame, c.version)
	if !c.congestion.CanSend(frameLen) {
		c.logf("拥塞告警: cwnd=%d inFlight=%d, 仍发送", c.congestion.Cwnd(), c.congestion.BytesInFlight())
	}

	// Build packet
	nextPN := protocol.PacketNumber(c.sendPN.Add(1) - 1)
	if protocol.PacketNumber(nextPN) > c.largestSentPN {
		c.largestSentPN = protocol.PacketNumber(nextPN)
	}
	pnLen := protocol.PacketNumberLengthForHeader(nextPN, 0)

	// Use short header for established connections
	c.sendBuf = c.sendBuf[:0]
	c.sendBuf = wire.AppendShortHeader(c.sendBuf, c.destConnID, nextPN, pnLen)

	// Append frame
	var err error
	c.sendBuf, err = frame.Append(c.sendBuf, c.version)
	if err != nil {
		c.logf("error appending frame: %v", err)
		return
	}

	packetSize := int64(len(c.sendBuf))

	// Record for potential retransmission
	c.sendPacketHistory = append(c.sendPacketHistory, sentPacket{
		pn:             nextPN,
		data:           append([]byte{}, c.sendBuf...),
		time:           time.Now(),
		isAckEliciting: isAckElicitingFrame(frame),
	})

	// Update congestion tracker
	c.congestion.OnPacketSent(packetSize)

	// Send over UDP
	_, err = c.conn.WriteTo(c.sendBuf, c.remoteAddr)
	if err != nil {
		c.logf("error sending packet: %v", err)
	}
}

// MaxPacketSize returns the current maximum packet size.
func (c *Connection) MaxPacketSize() protocol.ByteCount {
	return c.maxPacketSize
}

// SetMaxPacketSize updates the maximum packet size (used by MTU discovery).
func (c *Connection) SetMaxPacketSize(size protocol.ByteCount) {
	if size > protocol.MaxPacketBufferSize {
		size = protocol.MaxPacketBufferSize
	}
	if size >= protocol.MinInitialPacketSize {
		c.maxPacketSize = size
	}
}

// estimateFrameLength estimates the wire length of a frame.
func estimateFrameLength(frame wire.Frame, version protocol.Version) int64 {
	return int64(frame.Length(version)) + 5 // +5 for short header overhead
}

// isAckElicitingFrame returns true if the frame should trigger an ACK from the peer.
func isAckElicitingFrame(frame wire.Frame) bool {
	switch frame.(type) {
	case *wire.PaddingFrame, *wire.AckFrame:
		return false
	default:
		return true
	}
}

// sendInitialPacket sends a long header Initial packet (used during connection setup).
func (c *Connection) sendInitialPacket(frame wire.Frame) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	nextPN := protocol.PacketNumber(c.sendPN.Add(1) - 1)
	pnLen := protocol.PacketNumberLen4

	// Build long header
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			Version:          c.version,
			SrcConnectionID:  c.srcConnID,
			DestConnectionID: c.destConnID,
		},
		PacketNumberLen: pnLen,
		PacketNumber:    nextPN,
	}

	// Serialize header
	c.sendBuf = c.sendBuf[:0]
	var err error
	c.sendBuf, err = hdr.Append(c.sendBuf, c.version)
	if err != nil {
		c.logf("error appending header: %v", err)
		return
	}

	// Save the length position
	// Header.Append writes placeholder length at a known position
	headerLen := len(c.sendBuf)

	// Append frame
	c.sendBuf, err = frame.Append(c.sendBuf, c.version)
	if err != nil {
		c.logf("error appending frame: %v", err)
		return
	}

	// Update length field (Length = PacketNumber + Payload)
	frameLen := len(c.sendBuf) - headerLen
	payloadLen := int(pnLen) + frameLen
	wire.SetLength(c.sendBuf, protocol.ByteCount(payloadLen))

	// Pad to minimum initial size if needed, but cap at InitialPacketSize
	for len(c.sendBuf) < protocol.MinInitialPacketSize {
		c.sendBuf = append(c.sendBuf, 0x00)
	}
	// Trim to maxPacketSize if it somehow exceeded
	if len(c.sendBuf) > int(c.maxPacketSize) {
		c.sendBuf = c.sendBuf[:c.maxPacketSize]
	}

	// Record
	c.sendPacketHistory = append(c.sendPacketHistory, sentPacket{
		pn:   nextPN,
		data: append([]byte{}, c.sendBuf...),
		time: time.Now(),
	})

	_, err = c.conn.WriteTo(c.sendBuf, c.remoteAddr)
	if err != nil {
		c.logf("error sending initial packet: %v", err)
	}
}

// SendPing sends a PING frame to keep the connection alive.

func (c *Connection) recordReceivedPacket(pn protocol.PacketNumber) {
	c.recvPacketHistory = append(c.recvPacketHistory, pn)
	// Keep only the last 1000 packet numbers
	if len(c.recvPacketHistory) > 1000 {
		c.recvPacketHistory = c.recvPacketHistory[100:]
	}

	// Signal immediate ACK to enable fast retransmit on peer
	select {
	case c.immediateAckCh <- struct{}{}:
	default:
	}
}

func (c *Connection) sendAckIfNeeded() {
	if len(c.recvPacketHistory) == 0 {
		return
	}

	// Smart ACK strategy (RFC 9000 §13.2):
	// - Send ACK immediately if we have 2+ ack-eliciting packets since last ACK
	// - Send ACK immediately if max_ack_delay (25ms) has passed
	// - Otherwise, let the timer fire later
	c.ackElicitingSinceLastAck++

	now := time.Now()
	maxDelay := time.Duration(protocol.DefaultMaxAckDelay) * time.Millisecond

	if c.ackElicitingSinceLastAck >= 2 || now.Sub(c.lastAckTime) >= maxDelay {
		// Build ACK ranges from history
		ranges := buildAckRanges(c.recvPacketHistory)
		if len(ranges) == 0 {
			return
		}

		frame := &wire.AckFrame{
			AckRanges: ranges,
			DelayTime: now.Sub(c.lastAckTime),
		}
		c.sendFrame(frame)

		// Reset counters
		c.ackElicitingSinceLastAck = 0
		c.lastAckTime = now

		// Clear history (already acked)
		c.recvPacketHistory = nil
	}
}

func buildAckRanges(packets []protocol.PacketNumber) []wire.AckRange {
	if len(packets) == 0 {
		return nil
	}

	// Sort descending
	sorted := make([]protocol.PacketNumber, len(packets))
	copy(sorted, packets)
	sortPacketNumbers(sorted)

	var ranges []wire.AckRange
	currentRange := wire.AckRange{
		Largest:  sorted[0],
		Smallest: sorted[0],
	}

	for i := 1; i < len(sorted); i++ {
		if sorted[i] == currentRange.Smallest-1 {
			currentRange.Smallest = sorted[i]
		} else if sorted[i] < currentRange.Smallest-1 {
			ranges = append(ranges, currentRange)
			currentRange = wire.AckRange{
				Largest:  sorted[i],
				Smallest: sorted[i],
			}
		}
	}
	ranges = append(ranges, currentRange)

	// Limit to max 5 ranges
	if len(ranges) > 5 {
		ranges = ranges[:5]
	}

	return ranges
}

func sortPacketNumbers(pns []protocol.PacketNumber) {
	n := len(pns)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if pns[j] > pns[i] {
				pns[i], pns[j] = pns[j], pns[i]
			}
		}
	}
}

// sendConnectionSetup sends the initial connection setup packets.
func (c *Connection) sendConnectionSetup() {
	// Send a PING in an Initial packet to establish the connection
	c.sendInitialPacket(&wire.PingFrame{})
	// Send initial flow control info
	c.sendInitialPacket(&wire.MaxDataFrame{MaximumData: c.connMaxData})
	c.sendInitialPacket(&wire.MaxStreamsFrame{
		Type:       protocol.StreamTypeBidi,
		MaxStreams: c.maxStreamsBidi,
	})
}
