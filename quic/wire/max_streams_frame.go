package wire

import (
	"fmt"
	"io"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
)

// MaxStreamsFrame is a QUIC MAX_STREAMS frame.
type MaxStreamsFrame struct {
	Type       protocol.StreamType
	MaxStreams int64
}

func parseMaxStreamsFrame(data []byte) (*MaxStreamsFrame, int, error) {
	if len(data) < 1 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	f := &MaxStreamsFrame{}
	firstByte := data[0]
	if firstByte == 0x12 {
		f.Type = protocol.StreamTypeBidi
	} else if firstByte == 0x13 {
		f.Type = protocol.StreamTypeUni
	} else {
		return nil, 0, fmt.Errorf("not a MAX_STREAMS frame: 0x%02x", firstByte)
	}
	offset := 1
	val, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.MaxStreams = int64(val)
	offset += consumed
	return f, offset, nil
}

func (f *MaxStreamsFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	if f.Type == protocol.StreamTypeBidi {
		b = append(b, 0x12)
	} else {
		b = append(b, 0x13)
	}
	b = quicvarint.Append(b, uint64(f.MaxStreams))
	return b, nil
}

func (f *MaxStreamsFrame) Length(version protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.MaxStreams)))
}
