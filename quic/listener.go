package quic

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"quic-test/quic/protocol"
	"quic-test/quic/utils"
	"quic-test/quic/wire"
)

// Listener listens for incoming QUIC connections.
type Listener struct {
	conns  []*net.UDPConn // UDP sockets (may be multiple for multi-addr)
	config *Config

	// Connection management
	connMap   map[string]*Connection // keyed by remote address string
	connIDMap map[string]*Connection // keyed by connection ID string
	connsMu   sync.Mutex
	acceptCh  chan *Connection

	// Close
	closeOnce sync.Once
	done      chan struct{}
}

// Congestion control algorithm names.
const (
	CongestionCUBIC   = "CUBIC"
	CongestionBBR     = "BBR"
	CongestionNewReno = "NewReno"
)

// Config holds QUIC configuration.
type Config struct {
	MaxIncomingStreams int64
	MaxIdleTimeout     time.Duration
	// CongestionControl selects the congestion control algorithm.
	// Options: "CUBIC" (default), "BBR", "NewReno".
	CongestionControl string
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		MaxIncomingStreams: 100,
		MaxIdleTimeout:     30 * time.Second,
		CongestionControl:  CongestionCUBIC,
	}
}

// ListenAddr creates a new listener on the given UDP address.
func ListenAddr(addr string, config *Config) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	return Listen(conn, config), nil
}

// Listen creates a new listener on the given UDP connection.
func Listen(conn *net.UDPConn, config *Config) *Listener {
	return ListenAddrs([]*net.UDPConn{conn}, config)
}

// ListenAddrs creates a listener on multiple UDP connections.
// All sockets share the same connection pool and accept channel.
func ListenAddrs(udpConns []*net.UDPConn, config *Config) *Listener {
	if config == nil {
		config = DefaultConfig()
	}

	l := &Listener{
		config:    config,
		connMap:   make(map[string]*Connection),
		connIDMap: make(map[string]*Connection),
		acceptCh:  make(chan *Connection, 100),
		done:      make(chan struct{}),
	}

	for _, c := range udpConns {
		l.conns = append(l.conns, c)
		go l.readLoop(c)
	}
	return l
}

// Accept blocks until a new connection is received.
func (l *Listener) Accept(ctx context.Context) (*Connection, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.done:
		return nil, fmt.Errorf("listener closed")
	}
}

// Close closes the listener and all UDP sockets.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		for _, c := range l.conns {
			c.Close()
		}
	})
	return nil
}

// newController creates a congestion controller based on config.
func newController(cfg *Config) utils.Controller {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	switch cfg.CongestionControl {
	case CongestionBBR:
		return utils.NewBBR()
	case CongestionNewReno:
		return utils.NewNewReno()
	default:
		return utils.NewCubic()
	}
}

// Addr returns the first listener's network address.
func (l *Listener) Addr() net.Addr {
	if len(l.conns) == 0 {
		return nil
	}
	return l.conns[0].LocalAddr()
}

// Addrs returns all listener addresses.
func (l *Listener) Addrs() []net.Addr {
	addrs := make([]net.Addr, 0, len(l.conns))
	for _, c := range l.conns {
		addrs = append(addrs, c.LocalAddr())
	}
	return addrs
}

// readLoop reads UDP packets from a socket and dispatches them.
func (l *Listener) readLoop(conn *net.UDPConn) {
	buf := make([]byte, protocol.MaxPacketBufferSize*2)

	for {
		select {
		case <-l.done:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-l.done:
				return
			default:
				fmt.Printf("read error: %v\n", err)
				continue
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		go l.dispatchPacket(data, remoteAddr)
	}
}

// dispatchPacket routes a packet to the appropriate connection.
func (l *Listener) dispatchPacket(data []byte, remoteAddr net.Addr) {
	if len(data) < 5 {
		return
	}

	addrKey := remoteAddr.String()

	// Check for existing connection by address (fast path)
	l.connsMu.Lock()
	conn, exists := l.connMap[addrKey]
	if exists && !conn.closed.Load() {
		l.connsMu.Unlock()
		conn.handlePacket(data)
		return
	}

	// If not found by address, try connection ID routing (supports migration)
	if !exists || conn.closed.Load() {
		if !wire.IsLongHeaderPacket(data[0]) {
			// Short header packet: extract dest connection ID and look up by connID
			destConnID, err := wire.ParseShortHeaderConnID(data)
			if err == nil {
				connIDKey := destConnID.String()
				if migConn, ok := l.connIDMap[connIDKey]; ok && !migConn.closed.Load() {
					// Connection migration detected: update address mappings
					oldAddrKey := migConn.RemoteAddr().String()
					if oldAddrKey != addrKey {
						delete(l.connMap, oldAddrKey)
						l.connMap[addrKey] = migConn
						fmt.Printf("连接迁移: %s -> %s\n", oldAddrKey, addrKey)
					}
					migConn.updateRemoteAddr(remoteAddr)
					l.connsMu.Unlock()
					migConn.handlePacket(data)
					// Send PATH_CHALLENGE to validate new path
					var challengeData [8]byte
					copy(challengeData[:], []byte("MIGRATE1"))
					migConn.sendFrame(&wire.PathChallengeFrame{Data: challengeData})
					return
				}
			}
			l.connsMu.Unlock()
			return
		}
		l.connsMu.Unlock()
	} else {
		l.connsMu.Unlock()
	}

	// No existing connection found - must be a long header Initial packet
	if !wire.IsLongHeaderPacket(data[0]) {
		return
	}

	hdr, _, err := wire.ParsePacket(data)
	if err != nil {
		fmt.Printf("error parsing new connection packet: %v\n", err)
		return
	}

	if hdr.Type != protocol.PacketTypeInitial {
		return
	}

	// Generate server connection IDs
	serverConnID, err := protocol.GenerateConnectionIDForInitial()
	if err != nil {
		fmt.Printf("error generating connection ID: %v\n", err)
		return
	}

	// Create a new server-side connection (use the first UDP socket)
	conn = newServerConnection(
		l.conns[0],
		remoteAddr,
		hdr.SrcConnectionID,
		serverConnID,
		hdr.Version,
		l.config,
	)

	// Register the connection atomically in both maps
	l.connsMu.Lock()
	if existing, ok := l.connMap[addrKey]; ok && !existing.closed.Load() {
		l.connsMu.Unlock()
		existing.handlePacket(data)
		return
	}
	l.connMap[addrKey] = conn
	l.connIDMap[serverConnID.String()] = conn
	l.connsMu.Unlock()

	// Send initial response and deliver the initial packet
	conn.sendConnectionSetup()
	conn.handlePacket(data)

	// Add to accept queue
	select {
	case l.acceptCh <- conn:
	default:
		fmt.Println("accept channel full")
	}
}

// Dial creates a client connection to the given address.
func Dial(ctx context.Context, addr string, config *Config) (*Connection, error) {
	return dialOne(ctx, addr, config)
}

// DialAddr is a convenience function to create a connection to an address.
func DialAddr(addr string, config *Config) (*Connection, error) {
	return Dial(context.Background(), addr, config)
}

// DialHappy implements Happy Eyeballs (RFC 8305) for QUIC.
// It tries multiple addresses concurrently with a 300ms offset,
// and returns the first connection that responds.
func DialHappy(ctx context.Context, addrs []string, config *Config) (*Connection, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses to dial")
	}
	if len(addrs) == 1 {
		return Dial(ctx, addrs[0], config)
	}

	type result struct {
		conn *Connection
		err  error
		idx  int
	}

	results := make(chan result, len(addrs))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i, addr := range addrs {
		i, addr := i, addr
		delay := time.Duration(i) * 300 * time.Millisecond
		if i == 0 {
			delay = 0
		}

		go func() {
			// Apply delay (except first)
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
			}

			// Check if another attempt already succeeded
			select {
			case <-ctx.Done():
				return
			default:
			}

			conn, err := dialOne(ctx, addr, config)
			select {
			case results <- result{conn, err, i}:
			case <-ctx.Done():
				if conn != nil {
					conn.CloseWithError(0, "happy cancelled")
				}
			}
		}()
	}

	// Wait for first successful result, or all failures
	var firstErr error
	for i := 0; i < len(addrs); i++ {
		r := <-results
		if r.conn != nil {
			fmt.Printf("Happy Eyeballs: 选用 #%d %s (%v)\n", r.idx, addrs[r.idx],
				time.Duration(r.idx)*300*time.Millisecond)
			return r.conn, nil
		}
		if firstErr == nil {
			firstErr = r.err
		}
	}

	return nil, firstErr
}

// dialOne is a helper that creates a single QUIC connection.
func dialOne(ctx context.Context, addr string, config *Config) (*Connection, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = DefaultConfig()
	}

	clientConnID, err := protocol.GenerateConnectionIDForInitial()
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	initialDestConnID, err := protocol.GenerateConnectionIDForInitial()
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	conn := newClientConnection(
		udpConn,
		udpAddr,
		initialDestConnID,
		clientConnID,
		protocol.Version1,
		config,
	)

	conn.sendConnectionSetup()

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := conn.WaitReady(waitCtx); err != nil {
		conn.CloseWithError(0, "handshake timeout")
		udpConn.Close()
		return nil, fmt.Errorf("handshake failed to %s: %w", addr, err)
	}

	return conn, nil
}
