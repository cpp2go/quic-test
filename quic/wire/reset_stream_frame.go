package wire

import (
	"fmt"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
)

// ResetStreamFrame is a QUIC RESET_STREAM frame.
type ResetStreamFrame struct {
	StreamID  protocol.StreamID
	ErrorCode protocol.ErrCode
	FinalSize protocol.ByteCount
}

func parseResetStreamFrame(data []byte) (*ResetStreamFrame, int, error) {
	if len(data) < 1 || data[0] != 0x04 {
		return nil, 0, fmt.Errorf("not a RESET_STREAM frame")
	}
	f := &ResetStreamFrame{}
	offset := 1

	sid, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.StreamID = protocol.StreamID(sid)
	offset += consumed

	ec, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.ErrorCode = protocol.ErrCode(ec)
	offset += consumed

	fs, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.FinalSize = protocol.ByteCount(fs)
	offset += consumed

	return f, offset, nil
}

func (f *ResetStreamFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	b = append(b, 0x04)
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.ErrorCode))
	b = quicvarint.Append(b, uint64(f.FinalSize))
	return b, nil
}

func (f *ResetStreamFrame) Length(version protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(
		quicvarint.Len(uint64(f.StreamID))+
			quicvarint.Len(uint64(f.ErrorCode))+
			quicvarint.Len(uint64(f.FinalSize)),
	)
}
