package wire

import (
	"fmt"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
)

// MaxStreamDataFrame is a QUIC MAX_STREAM_DATA frame.
type MaxStreamDataFrame struct {
	StreamID          protocol.StreamID
	MaximumStreamData protocol.ByteCount
}

func parseMaxStreamDataFrame(data []byte) (*MaxStreamDataFrame, int, error) {
	if len(data) < 1 || data[0] != 0x11 {
		return nil, 0, fmt.Errorf("not a MAX_STREAM_DATA frame")
	}
	f := &MaxStreamDataFrame{}
	offset := 1
	sid, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.StreamID = protocol.StreamID(sid)
	offset += consumed
	val, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.MaximumStreamData = protocol.ByteCount(val)
	offset += consumed
	return f, offset, nil
}

func (f *MaxStreamDataFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	b = append(b, 0x11)
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.MaximumStreamData))
	return b, nil
}

func (f *MaxStreamDataFrame) Length(version protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.StreamID))+quicvarint.Len(uint64(f.MaximumStreamData)))
}
