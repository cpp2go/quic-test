package quic

import (
	"context"
	"io"
	"sync"
	"time"

	"quic-test/quic/protocol"
)

// StreamID is the type for stream identifiers.
type StreamID = protocol.StreamID

// Stream provides bidirectional QUIC stream I/O.
type Stream struct {
	streamID protocol.StreamID
	conn     *Connection

	mu            sync.Mutex
	readBuf       []byte
	readCond      *sync.Cond
	writeCond     *sync.Cond
	closed        bool
	reset         bool
	readDeadline  time.Time
	writeDeadline time.Time
	writeErr      error

	// Flow control
	readOffset  protocol.ByteCount
	writeOffset protocol.ByteCount
	maxData     protocol.ByteCount // max data we can send
	readMaxData protocol.ByteCount // max data remote can send

	finalSize protocol.ByteCount
	finRead   bool
	finSent   bool
}

func newStream(streamID protocol.StreamID, conn *Connection) *Stream {
	s := &Stream{
		streamID:    streamID,
		conn:        conn,
		maxData:     65536, // initial flow control limit
		readMaxData: 65536, // initial flow control limit
	}
	s.readCond = sync.NewCond(&s.mu)
	s.writeCond = sync.NewCond(&s.mu)
	return s
}

// StreamID returns the stream ID.
func (s *Stream) StreamID() protocol.StreamID {
	return s.streamID
}

// Read reads data from the stream.
func (s *Stream) Read(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		// Check for EOF
		if s.finRead && len(s.readBuf) == 0 {
			return 0, io.EOF
		}
		if s.reset {
			return 0, io.ErrUnexpectedEOF
		}
		if s.closed && len(s.readBuf) == 0 {
			return 0, io.EOF
		}

		if len(s.readBuf) > 0 {
			n := copy(b, s.readBuf)
			s.readBuf = s.readBuf[n:]
			s.readOffset += protocol.ByteCount(n)

			// Send MAX_STREAM_DATA update periodically
			if s.readOffset > s.readMaxData/2 {
				s.readMaxData += 65536
				s.conn.sendMaxStreamData(s.streamID, s.readMaxData)
			}
			return n, nil
		}

		// Wait for data
		if !s.readDeadline.IsZero() {
			timer := time.NewTimer(time.Until(s.readDeadline))
			defer timer.Stop()
			go func() {
				<-timer.C
				s.readCond.Broadcast()
			}()
		}
		s.readCond.Wait()
		if !s.readDeadline.IsZero() && time.Now().After(s.readDeadline) {
			return 0, context.DeadlineExceeded
		}
	}
}

// Write writes data to the stream.
func (s *Stream) Write(b []byte) (int, error) {
	s.mu.Lock()
	if s.writeErr != nil {
		err := s.writeErr
		s.mu.Unlock()
		return 0, err
	}
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	s.mu.Unlock()

	written := 0
	for written < len(b) {
		chunkSize := len(b) - written
		if chunkSize > 1024 {
			chunkSize = 1024
		}

		s.mu.Lock()
		// Flow control: wait until we can send
		for s.writeOffset+protocol.ByteCount(chunkSize) > s.maxData && !s.closed {
			if s.writeErr != nil {
				err := s.writeErr
				s.mu.Unlock()
				return written, err
			}
			if !s.writeDeadline.IsZero() {
				timer := time.NewTimer(time.Until(s.writeDeadline))
				defer timer.Stop()
				go func() {
					<-timer.C
					s.writeCond.Broadcast()
				}()
			}
			s.writeCond.Wait()
			if !s.writeDeadline.IsZero() && time.Now().After(s.writeDeadline) {
				s.mu.Unlock()
				return written, context.DeadlineExceeded
			}
		}
		if s.closed {
			s.mu.Unlock()
			return written, io.ErrClosedPipe
		}
		s.mu.Unlock()

		chunk := b[written : written+chunkSize]
		s.mu.Lock()
		s.conn.sendStreamData(s.streamID, s.writeOffset, chunk, false)
		s.writeOffset += protocol.ByteCount(len(chunk))
		s.mu.Unlock()
		written += chunkSize
	}

	return written, nil
}

// Close closes the stream for writing.
func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finSent {
		return nil
	}
	s.finSent = true
	s.conn.sendStreamData(s.streamID, s.writeOffset, nil, true)
	return nil
}

// CancelRead cancels reading from the stream.
func (s *Stream) CancelRead(code protocol.ErrCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reset = true
	s.readBuf = nil
	s.readCond.Broadcast()
}

// CancelWrite cancels writing to the stream.
func (s *Stream) CancelWrite(code protocol.ErrCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeErr = io.ErrClosedPipe
	s.writeCond.Broadcast()
}

// SetReadDeadline sets the read deadline.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	s.readCond.Broadcast()
	return nil
}

// SetWriteDeadline sets the write deadline.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDeadline = t
	s.writeCond.Broadcast()
	return nil
}

// SetDeadline sets both read and write deadlines.
func (s *Stream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	_ = s.SetWriteDeadline(t)
	return nil
}

// handleStreamData processes incoming stream data.
func (s *Stream) handleStreamData(offset protocol.ByteCount, data []byte, fin bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.finRead || s.reset {
		return
	}

	// 丢弃重复/已消耗的数据（重传包会携带相同偏移量的数据）
	if offset+protocol.ByteCount(len(data)) <= s.readOffset {
		// 如果当前包还带 FIN，确保 finRead 被设置
		if fin && s.readBuf == nil {
			s.finRead = true
			s.readCond.Broadcast()
		}
		return
	}

	// Handle out-of-order data by appending to buffer
	// For simplicity, we assume in-order delivery for now
	if offset == s.readOffset {
		s.readBuf = append(s.readBuf, data...)
		s.readOffset = offset + protocol.ByteCount(len(data))
		if fin {
			s.finRead = true
		}
		s.readCond.Broadcast()
	} else {
		// Out-of-order data; store for later reassembly
		// Simple approach: just append and sort later
		s.readBuf = append(s.readBuf, data...)
		s.readCond.Broadcast()
	}
}

// updateMaxData updates the flow control limit.
func (s *Stream) updateMaxData(maxData protocol.ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if maxData > s.maxData {
		s.maxData = maxData
		s.writeCond.Broadcast()
	}
}
