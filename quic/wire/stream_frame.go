package wire

import (
	"fmt"
	"io"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
)

// StreamFrame is a QUIC STREAM frame.
type StreamFrame struct {
	StreamID       protocol.StreamID
	Offset         protocol.ByteCount
	Data           []byte
	Fin            bool
	DataLenPresent bool
}

func parseStreamFrame(data []byte) (*StreamFrame, int, error) {
	if len(data) < 1 {
		return nil, 0, io.ErrUnexpectedEOF
	}

	firstByte := data[0]
	if firstByte&0xf8 != 0x08 {
		return nil, 0, fmt.Errorf("not a STREAM frame: 0x%02x", firstByte)
	}

	f := &StreamFrame{
		Fin:            firstByte&0x01 > 0,
		DataLenPresent: firstByte&0x02 > 0,
	}
	hasOffset := firstByte&0x04 > 0

	offset := 1

	// Stream ID
	sid, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.StreamID = protocol.StreamID(sid)
	offset += consumed

	// Offset
	if hasOffset {
		o, consumed, err := quicvarint.Parse(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		f.Offset = protocol.ByteCount(o)
		offset += consumed
	}

	// Data length
	var dataLen uint64
	if f.DataLenPresent {
		dl, consumed, err := quicvarint.Parse(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		dataLen = dl
		offset += consumed
	} else {
		dataLen = uint64(len(data) - offset)
	}

	if offset+int(dataLen) > len(data) {
		return nil, 0, io.ErrUnexpectedEOF
	}

	f.Data = make([]byte, dataLen)
	copy(f.Data, data[offset:offset+int(dataLen)])
	offset += int(dataLen)

	return f, offset, nil
}

func (f *StreamFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	firstByte := byte(0x08)
	if f.Fin {
		firstByte |= 0x01
	}
	if f.DataLenPresent {
		firstByte |= 0x02
	}
	if f.Offset > 0 {
		firstByte |= 0x04
	}
	b = append(b, firstByte)

	b = quicvarint.Append(b, uint64(f.StreamID))

	if f.Offset > 0 {
		b = quicvarint.Append(b, uint64(f.Offset))
	}

	if f.DataLenPresent {
		b = quicvarint.Append(b, uint64(len(f.Data)))
	}

	b = append(b, f.Data...)
	return b, nil
}

func (f *StreamFrame) Length(version protocol.Version) protocol.ByteCount {
	length := 1 + protocol.ByteCount(quicvarint.Len(uint64(f.StreamID)))
	if f.Offset > 0 {
		length += protocol.ByteCount(quicvarint.Len(uint64(f.Offset)))
	}
	if f.DataLenPresent {
		length += protocol.ByteCount(quicvarint.Len(uint64(len(f.Data))))
	}
	length += protocol.ByteCount(len(f.Data))
	return length
}

// MaxDataLen returns the maximum data length that fits in maxSize.
func (f *StreamFrame) MaxDataLen(maxSize protocol.ByteCount, version protocol.Version) protocol.ByteCount {
	// Calculate header overhead without data length varint
	baseHeaderLen := protocol.ByteCount(1 + quicvarint.Len(uint64(f.StreamID)))
	if f.Offset > 0 {
		baseHeaderLen += protocol.ByteCount(quicvarint.Len(uint64(f.Offset)))
	}
	// Try different data lengths and check if they fit with their varint prefix
	for dataLen := maxSize - baseHeaderLen - 1; dataLen > 0; dataLen-- {
		dataLenLen := protocol.ByteCount(quicvarint.Len(uint64(dataLen)))
		if baseHeaderLen+dataLenLen+dataLen <= maxSize {
			return dataLen
		}
	}
	return 0
}

// DataLen returns the length of the data.
func (f *StreamFrame) DataLen() protocol.ByteCount {
	return protocol.ByteCount(len(f.Data))
}

// MaybeSplitOffFrame splits the frame at maxSize, returning the split-off part.
func (f *StreamFrame) MaybeSplitOffFrame(maxSize protocol.ByteCount, version protocol.Version) (*StreamFrame, bool) {
	if maxSize >= f.Length(version) {
		return nil, false
	}

	maxDataLen := f.MaxDataLen(maxSize, version)
	if maxDataLen == 0 {
		return nil, false
	}

	newDataLen := int(maxDataLen)
	newFrame := &StreamFrame{
		StreamID:       f.StreamID,
		Offset:         f.Offset + protocol.ByteCount(newDataLen),
		Data:           f.Data[newDataLen:],
		Fin:            f.Fin,
		DataLenPresent: f.DataLenPresent,
	}

	f.Data = f.Data[:newDataLen]
	f.Fin = false

	return newFrame, true
}
