package wire

import (
	"fmt"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
)

// MaxDataFrame is a QUIC MAX_DATA frame.
type MaxDataFrame struct {
	MaximumData protocol.ByteCount
}

func parseMaxDataFrame(data []byte) (*MaxDataFrame, int, error) {
	if len(data) < 1 || data[0] != 0x10 {
		return nil, 0, fmt.Errorf("not a MAX_DATA frame")
	}
	f := &MaxDataFrame{}
	offset := 1
	val, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.MaximumData = protocol.ByteCount(val)
	offset += consumed
	return f, offset, nil
}

func (f *MaxDataFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	b = append(b, 0x10)
	b = quicvarint.Append(b, uint64(f.MaximumData))
	return b, nil
}

func (f *MaxDataFrame) Length(version protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.MaximumData)))
}
