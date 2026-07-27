package wire

import (
	"fmt"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
)

// StopSendingFrame is a QUIC STOP_SENDING frame.
type StopSendingFrame struct {
	StreamID  protocol.StreamID
	ErrorCode protocol.ErrCode
}

func parseStopSendingFrame(data []byte) (*StopSendingFrame, int, error) {
	if len(data) < 1 || data[0] != 0x05 {
		return nil, 0, fmt.Errorf("not a STOP_SENDING frame")
	}
	f := &StopSendingFrame{}
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

	return f, offset, nil
}

func (f *StopSendingFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	b = append(b, 0x05)
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.ErrorCode))
	return b, nil
}

func (f *StopSendingFrame) Length(version protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.StreamID))+quicvarint.Len(uint64(f.ErrorCode)))
}
