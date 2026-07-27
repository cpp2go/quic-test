package wire

import (
	"fmt"
	"io"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
)

// ConnectionCloseFrame is a QUIC CONNECTION_CLOSE frame.
type ConnectionCloseFrame struct {
	IsApplication bool
	ErrorCode     protocol.ErrCode
	ReasonPhrase  string
}

func parseConnectionCloseFrame(data []byte) (*ConnectionCloseFrame, int, error) {
	if len(data) < 1 {
		return nil, 0, io.ErrUnexpectedEOF
	}

	firstByte := data[0]
	f := &ConnectionCloseFrame{}

	switch firstByte {
	case 0x1c:
		f.IsApplication = false
	case 0x1d:
		f.IsApplication = true
	default:
		return nil, 0, fmt.Errorf("not a CONNECTION_CLOSE frame: 0x%02x", firstByte)
	}

	offset := 1

	// Error code (for transport close, this is followed by frame type)
	ec, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.ErrorCode = protocol.ErrCode(ec)
	offset += consumed

	if !f.IsApplication {
		// Triggering frame type (skip)
		_, consumed, err := quicvarint.Parse(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += consumed
	}

	// Reason phrase
	reasonLen, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += consumed

	if offset+int(reasonLen) > len(data) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	f.ReasonPhrase = string(data[offset : offset+int(reasonLen)])
	offset += int(reasonLen)

	return f, offset, nil
}

func (f *ConnectionCloseFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	if f.IsApplication {
		b = append(b, 0x1d)
	} else {
		b = append(b, 0x1c)
	}

	b = quicvarint.Append(b, uint64(f.ErrorCode))

	if !f.IsApplication {
		b = quicvarint.Append(b, 0) // triggering frame type = 0
	}

	b = quicvarint.Append(b, uint64(len(f.ReasonPhrase)))
	b = append(b, []byte(f.ReasonPhrase)...)
	return b, nil
}

func (f *ConnectionCloseFrame) Length(version protocol.Version) protocol.ByteCount {
	length := protocol.ByteCount(1)
	length += protocol.ByteCount(quicvarint.Len(uint64(f.ErrorCode)))
	if !f.IsApplication {
		length += protocol.ByteCount(quicvarint.Len(0))
	}
	length += protocol.ByteCount(quicvarint.Len(uint64(len(f.ReasonPhrase))))
	length += protocol.ByteCount(len(f.ReasonPhrase))
	return length
}
