package wire

import (
	"fmt"
	"io"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
)

// Frame is the interface for all QUIC frames.
type Frame interface {
	Append(b []byte, version protocol.Version) ([]byte, error)
	Length(version protocol.Version) protocol.ByteCount
}

// FrameParser parses QUIC frames.
type FrameParser struct{}

// ParseNext parses the next frame from data. It returns the frame and the number of bytes consumed.
func (p *FrameParser) ParseNext(data []byte) (Frame, int, error) {
	if len(data) == 0 {
		return nil, 0, io.ErrUnexpectedEOF
	}

	switch data[0] {
	case 0x00:
		// PADDING - skip
		i := 0
		for i < len(data) && data[i] == 0x00 {
			i++
		}
		return &PaddingFrame{PadLength: i}, i, nil
	case 0x01:
		return parsePingFrame(data)
	case 0x02, 0x03:
		return parseAckFrame(data)
	case 0x04:
		return parseResetStreamFrame(data)
	case 0x05:
		return parseStopSendingFrame(data)
	case 0x06:
		return parseCryptoFrame(data)
	case 0x07:
		return nil, 0, fmt.Errorf("NEW_TOKEN frame not supported")
	case 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f:
		return parseStreamFrame(data)
	case 0x10:
		return parseMaxDataFrame(data)
	case 0x11:
		return parseMaxStreamDataFrame(data)
	case 0x12, 0x13:
		return parseMaxStreamsFrame(data)
	case 0x14:
		return parseDataBlockedFrame(data)
	case 0x15:
		return parseStreamDataBlockedFrame(data)
	case 0x16, 0x17:
		return parseStreamsBlockedFrame(data)
	case 0x18:
		return nil, 0, fmt.Errorf("NEW_CONNECTION_ID frame not supported")
	case 0x19:
		return nil, 0, fmt.Errorf("RETIRE_CONNECTION_ID frame not supported")
	case 0x1a:
		return parsePathChallengeFrame(data)
	case 0x1b:
		return parsePathResponseFrame(data)
	case 0x1c, 0x1d:
		return parseConnectionCloseFrame(data)
	case 0x1e:
		return nil, 0, fmt.Errorf("HANDSHAKE_DONE frame not supported")
	case 0x30, 0x31:
		return nil, 0, fmt.Errorf("DATAGRAM frame not supported")
	default:
		return nil, 0, fmt.Errorf("unknown frame type: 0x%02x", data[0])
	}
}

// PaddingFrame
type PaddingFrame struct {
	PadLength int
}

func (f *PaddingFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	for i := 0; i < f.PadLength; i++ {
		b = append(b, 0x00)
	}
	return b, nil
}

func (f *PaddingFrame) Length(version protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(f.PadLength)
}

// PingFrame
type PingFrame struct{}

func parsePingFrame(data []byte) (*PingFrame, int, error) {
	if len(data) < 1 || data[0] != 0x01 {
		return nil, 0, fmt.Errorf("not a PING frame")
	}
	return &PingFrame{}, 1, nil
}

func (f *PingFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	return append(b, 0x01), nil
}

func (f *PingFrame) Length(version protocol.Version) protocol.ByteCount {
	return 1
}

// CryptoFrame
type CryptoFrame struct {
	Offset protocol.ByteCount
	Data   []byte
}

func parseCryptoFrame(data []byte) (*CryptoFrame, int, error) {
	if len(data) < 1 || data[0] != 0x06 {
		return nil, 0, fmt.Errorf("not a CRYPTO frame")
	}
	f := &CryptoFrame{}
	offset := 1

	o, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.Offset = protocol.ByteCount(o)
	offset += consumed

	length, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += consumed

	if offset+int(length) > len(data) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	f.Data = make([]byte, length)
	copy(f.Data, data[offset:offset+int(length)])
	offset += int(length)

	return f, offset, nil
}

func (f *CryptoFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	b = append(b, 0x06)
	b = quicvarint.Append(b, uint64(f.Offset))
	b = quicvarint.Append(b, uint64(len(f.Data)))
	b = append(b, f.Data...)
	return b, nil
}

func (f *CryptoFrame) Length(version protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.Offset))+quicvarint.Len(uint64(len(f.Data)))) + protocol.ByteCount(len(f.Data))
}

// DataBlockedFrame
type DataBlockedFrame struct {
	MaxData protocol.ByteCount
}

func parseDataBlockedFrame(data []byte) (*DataBlockedFrame, int, error) {
	if len(data) < 1 || data[0] != 0x14 {
		return nil, 0, fmt.Errorf("not a DATA_BLOCKED frame")
	}
	f := &DataBlockedFrame{}
	offset := 1
	val, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.MaxData = protocol.ByteCount(val)
	offset += consumed
	return f, offset, nil
}

func (f *DataBlockedFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	b = append(b, 0x14)
	b = quicvarint.Append(b, uint64(f.MaxData))
	return b, nil
}

func (f *DataBlockedFrame) Length(version protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.MaxData)))
}

// StreamDataBlockedFrame
type StreamDataBlockedFrame struct {
	StreamID          protocol.StreamID
	MaximumStreamData protocol.ByteCount
}

func parseStreamDataBlockedFrame(data []byte) (*StreamDataBlockedFrame, int, error) {
	if len(data) < 1 || data[0] != 0x15 {
		return nil, 0, fmt.Errorf("not a STREAM_DATA_BLOCKED frame")
	}
	f := &StreamDataBlockedFrame{}
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

func (f *StreamDataBlockedFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	b = append(b, 0x15)
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.MaximumStreamData))
	return b, nil
}

func (f *StreamDataBlockedFrame) Length(version protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.StreamID))+quicvarint.Len(uint64(f.MaximumStreamData)))
}

// StreamsBlockedFrame
type StreamsBlockedFrame struct {
	Type    protocol.StreamType
	Streams int64
}

func parseStreamsBlockedFrame(data []byte) (*StreamsBlockedFrame, int, error) {
	if len(data) < 1 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	f := &StreamsBlockedFrame{}
	firstByte := data[0]
	if firstByte == 0x16 {
		f.Type = protocol.StreamTypeBidi
	} else if firstByte == 0x17 {
		f.Type = protocol.StreamTypeUni
	} else {
		return nil, 0, fmt.Errorf("not a STREAMS_BLOCKED frame")
	}
	offset := 1
	val, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.Streams = int64(val)
	offset += consumed
	return f, offset, nil
}

func (f *StreamsBlockedFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	if f.Type == protocol.StreamTypeBidi {
		b = append(b, 0x16)
	} else {
		b = append(b, 0x17)
	}
	b = quicvarint.Append(b, uint64(f.Streams))
	return b, nil
}

func (f *StreamsBlockedFrame) Length(version protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.Streams)))
}

// PathChallengeFrame
type PathChallengeFrame struct {
	Data [8]byte
}

func parsePathChallengeFrame(data []byte) (*PathChallengeFrame, int, error) {
	if len(data) < 9 || data[0] != 0x1a {
		return nil, 0, fmt.Errorf("not a PATH_CHALLENGE frame")
	}
	f := &PathChallengeFrame{}
	copy(f.Data[:], data[1:9])
	return f, 9, nil
}

func (f *PathChallengeFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	b = append(b, 0x1a)
	b = append(b, f.Data[:]...)
	return b, nil
}

func (f *PathChallengeFrame) Length(version protocol.Version) protocol.ByteCount {
	return 9
}

// PathResponseFrame
type PathResponseFrame struct {
	Data [8]byte
}

func parsePathResponseFrame(data []byte) (*PathResponseFrame, int, error) {
	if len(data) < 9 || data[0] != 0x1b {
		return nil, 0, fmt.Errorf("not a PATH_RESPONSE frame")
	}
	f := &PathResponseFrame{}
	copy(f.Data[:], data[1:9])
	return f, 9, nil
}

func (f *PathResponseFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	b = append(b, 0x1b)
	b = append(b, f.Data[:]...)
	return b, nil
}

func (f *PathResponseFrame) Length(version protocol.Version) protocol.ByteCount {
	return 9
}
