package wire

import (
	"fmt"
	"io"
	"time"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
)

// AckRange represents a continuous range of packet numbers.
type AckRange struct {
	Smallest protocol.PacketNumber
	Largest  protocol.PacketNumber
}

// Len returns the number of packets in this range.
func (r AckRange) Len() protocol.PacketNumber {
	return r.Largest - r.Smallest + 1
}

// AckFrame is a QUIC ACK frame.
type AckFrame struct {
	AckRanges []AckRange
	DelayTime time.Duration
}

func parseAckFrame(data []byte) (*AckFrame, int, error) {
	if len(data) < 1 {
		return nil, 0, io.ErrUnexpectedEOF
	}

	firstByte := data[0]
	if firstByte != 0x02 && firstByte != 0x03 {
		return nil, 0, fmt.Errorf("not an ACK frame: 0x%02x", firstByte)
	}

	f := &AckFrame{}
	offset := 1

	// Largest Acknowledged
	largestAcked, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += consumed

	// ACK Delay
	delay, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	f.DelayTime = time.Duration(delay) * time.Millisecond
	offset += consumed

	// ACK Range Count (number of additional ranges)
	numRanges, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += consumed

	// First ACK Range
	firstRange, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, 0, err
	}
	offset += consumed

	// Build the first range
	f.AckRanges = append(f.AckRanges, AckRange{
		Largest:  protocol.PacketNumber(largestAcked),
		Smallest: protocol.PacketNumber(largestAcked - firstRange),
	})

	// Additional ranges
	for i := uint64(0); i < numRanges; i++ {
		// Gap
		gap, consumed, err := quicvarint.Parse(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += consumed

		// Block length
		blockLen, consumed, err := quicvarint.Parse(data[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += consumed

		prevRange := f.AckRanges[len(f.AckRanges)-1]
		newRange := AckRange{
			Largest:  prevRange.Smallest - protocol.PacketNumber(gap) - 2,
			Smallest: prevRange.Smallest - protocol.PacketNumber(gap) - 2 - protocol.PacketNumber(blockLen),
		}
		f.AckRanges = append(f.AckRanges, newRange)
	}

	return f, offset, nil
}

func (f *AckFrame) Append(b []byte, version protocol.Version) ([]byte, error) {
	if len(f.AckRanges) == 0 {
		return nil, fmt.Errorf("ACK frame must have at least one range")
	}

	b = append(b, 0x02) // ACK frame type (without ECN)

	// Largest Acknowledged
	largestAcked := uint64(f.AckRanges[0].Largest)
	b = quicvarint.Append(b, largestAcked)

	// ACK Delay (in milliseconds)
	delayMs := uint64(f.DelayTime.Milliseconds())
	b = quicvarint.Append(b, delayMs)

	// Number of additional ranges
	numRanges := uint64(len(f.AckRanges) - 1)
	b = quicvarint.Append(b, numRanges)

	// First ACK Range
	firstRangeLen := uint64(f.AckRanges[0].Largest - f.AckRanges[0].Smallest)
	b = quicvarint.Append(b, firstRangeLen)

	// Additional ranges
	for i := 1; i < len(f.AckRanges); i++ {
		gap := uint64(f.AckRanges[i-1].Smallest - f.AckRanges[i].Largest - 2)
		b = quicvarint.Append(b, gap)

		blockLen := uint64(f.AckRanges[i].Largest - f.AckRanges[i].Smallest)
		b = quicvarint.Append(b, blockLen)
	}

	return b, nil
}

func (f *AckFrame) Length(version protocol.Version) protocol.ByteCount {
	length := 1 // type byte
	length += quicvarint.Len(uint64(f.AckRanges[0].Largest))
	length += quicvarint.Len(uint64(f.DelayTime.Milliseconds()))
	length += quicvarint.Len(uint64(len(f.AckRanges) - 1))
	length += quicvarint.Len(uint64(f.AckRanges[0].Largest - f.AckRanges[0].Smallest))
	for i := 1; i < len(f.AckRanges); i++ {
		length += quicvarint.Len(uint64(f.AckRanges[i-1].Smallest - f.AckRanges[i].Largest - 2))
		length += quicvarint.Len(uint64(f.AckRanges[i].Largest - f.AckRanges[i].Smallest))
	}
	return protocol.ByteCount(length)
}
