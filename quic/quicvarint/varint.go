// Package quicvarint implements QUIC variable-length integer encoding as
// defined in RFC 9000, Section 16.
package quicvarint

import (
	"encoding/binary"
	"io"
)

// The maximum value that can be encoded.
const MaxVarint = 1<<62 - 1

// Read reads a variable-length integer from r.
func Read(r io.ByteReader) (uint64, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	// The top two bits encode the length
	switch firstByte >> 6 {
	case 0:
		return uint64(firstByte), nil
	case 1:
		second, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		return uint64(firstByte&0x3f)<<8 | uint64(second), nil
	case 2:
		b := make([]byte, 4)
		b[0] = firstByte & 0x3f
		_, err := io.ReadFull(r.(io.Reader), b[1:])
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(b) >> 32, nil
	default:
		b := make([]byte, 8)
		b[0] = firstByte & 0x3f
		_, err := io.ReadFull(r.(io.Reader), b[1:])
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(b), nil
	}
}

// Parse parses a variable-length integer from b, returning the value and
// the number of bytes consumed.
func Parse(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	firstByte := b[0]
	switch firstByte >> 6 {
	case 0:
		return uint64(firstByte), 1, nil
	case 1:
		if len(b) < 2 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return uint64(firstByte&0x3f)<<8 | uint64(b[1]), 2, nil
	case 2:
		if len(b) < 4 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		val := uint32(firstByte&0x3f)<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		return uint64(val), 4, nil
	default:
		if len(b) < 8 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return binary.BigEndian.Uint64(b) & 0x3fffffffffffffff, 8, nil
	}
}

// Append appends a variable-length integer to b.
func Append(b []byte, i uint64) []byte {
	switch {
	case i <= 63:
		return append(b, byte(i))
	case i <= 16383:
		return append(b, byte(i>>8)|0x40, byte(i))
	case i <= 1073741823:
		return append(b, byte(i>>24)|0x80, byte(i>>16), byte(i>>8), byte(i))
	default:
		return append(b,
			byte(i>>56)|0xc0,
			byte(i>>48),
			byte(i>>40),
			byte(i>>32),
			byte(i>>24),
			byte(i>>16),
			byte(i>>8),
			byte(i),
		)
	}
}

// AppendWithLen appends a variable-length integer to b using exactly length bytes.
func AppendWithLen(b []byte, i uint64, length int) []byte {
	switch length {
	case 1:
		return append(b, byte(i))
	case 2:
		return append(b, byte(i>>8)|0x40, byte(i))
	case 4:
		return append(b, byte(i>>24)|0x80, byte(i>>16), byte(i>>8), byte(i))
	case 8:
		return append(b,
			byte(i>>56)|0xc0,
			byte(i>>48),
			byte(i>>40),
			byte(i>>32),
			byte(i>>24),
			byte(i>>16),
			byte(i>>8),
			byte(i),
		)
	}
	panic("invalid length")
}

// Len returns the number of bytes needed to encode i as a variable-length integer.
func Len(i uint64) int {
	switch {
	case i <= 63:
		return 1
	case i <= 16383:
		return 2
	case i <= 1073741823:
		return 4
	default:
		return 8
	}
}
