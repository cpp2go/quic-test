package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// PacketType represents the type of a QUIC long header packet.
type PacketType uint8

const (
	PacketTypeInitial   PacketType = 1
	PacketTypeRetry     PacketType = 2
	PacketTypeHandshake PacketType = 3
	PacketType0RTT      PacketType = 4
)

// ByteCount is a count of bytes.
type ByteCount int64

const MaxByteCount = ByteCount(1<<62 - 1)

// MaxPacketBufferSize is the maximum UDP payload size we use.
const MaxPacketBufferSize = 1452

// MinInitialPacketSize is the minimum size of an Initial packet (RFC 9000).
const MinInitialPacketSize = 1200

// MaxConnIDLen is the maximum connection ID length.
const MaxConnIDLen = 20

// MinConnectionIDLenInitial is the minimum connection ID length for Initial packets.
const MinConnectionIDLenInitial = 8

// DefaultActiveConnectionIDLimit is from RFC 9000.
const DefaultActiveConnectionIDLimit = 2

// DefaultMaxAckDelay is the default max ACK delay.
const DefaultMaxAckDelay = 25 // milliseconds

// ConnectionID is a QUIC connection ID.
type ConnectionID struct {
	b [20]byte
	l uint8
}

// ParseConnectionID parses a connection ID from b.
func ParseConnectionID(b []byte) ConnectionID {
	if len(b) > MaxConnIDLen {
		panic(fmt.Sprintf("invalid connection ID length: %d", len(b)))
	}
	var c ConnectionID
	c.l = uint8(len(b))
	copy(c.b[:], b)
	return c
}

// GenerateConnectionID generates a random connection ID of the given length.
func GenerateConnectionID(l int) (ConnectionID, error) {
	if l > MaxConnIDLen {
		return ConnectionID{}, fmt.Errorf("invalid connection ID length: %d", l)
	}
	var c ConnectionID
	c.l = uint8(l)
	if _, err := rand.Read(c.b[:l]); err != nil {
		return ConnectionID{}, err
	}
	return c, nil
}

// GenerateConnectionIDForInitial generates a connection ID for Initial packets (8-20 bytes).
func GenerateConnectionIDForInitial() (ConnectionID, error) {
	return GenerateConnectionID(8)
}

// Len returns the length of the connection ID.
func (c ConnectionID) Len() int {
	return int(c.l)
}

// Bytes returns the connection ID bytes.
func (c ConnectionID) Bytes() []byte {
	return c.b[:c.l]
}

// String returns the hex string representation.
func (c ConnectionID) String() string {
	return fmt.Sprintf("%x", c.b[:c.l])
}

// PacketNumber is a QUIC packet number.
type PacketNumber int64

const InvalidPacketNumber PacketNumber = -1

// PacketNumberLen is the length of a packet number in bytes (1-4).
type PacketNumberLen uint8

const (
	PacketNumberLen1 PacketNumberLen = 1
	PacketNumberLen2 PacketNumberLen = 2
	PacketNumberLen3 PacketNumberLen = 3
	PacketNumberLen4 PacketNumberLen = 4
)

// DecodePacketNumber decodes a truncated packet number (RFC 9000, Appendix A.3).
func DecodePacketNumber(length PacketNumberLen, largest PacketNumber, truncated PacketNumber) PacketNumber {
	expected := largest + 1
	win := PacketNumber(1 << (length * 8))
	hwin := win / 2
	mask := win - 1
	candidate := (expected & ^mask) | truncated
	if candidate <= expected-hwin && candidate < 1<<62-win {
		return candidate + win
	}
	if candidate > expected+hwin && candidate >= win {
		return candidate - win
	}
	return candidate
}

// PacketNumberLengthForHeader chooses the minimum packet number length.
func PacketNumberLengthForHeader(pn, largestAcked PacketNumber) PacketNumberLen {
	if pn <= 0x7f && largestAcked <= 0x7f {
		return PacketNumberLen1
	}
	diff := pn - largestAcked
	switch {
	case diff <= 0x7fff:
		return PacketNumberLen2
	case diff <= 0x7fffff:
		return PacketNumberLen3
	default:
		return PacketNumberLen4
	}
}

// StreamID is a QUIC stream ID.
type StreamID int64

// StreamType represents the type of a stream (bidirectional or unidirectional).
type StreamType uint8

const (
	StreamTypeBidi StreamType = 0
	StreamTypeUni  StreamType = 1
)

const (
	StreamIDMaxBidi = 1<<60 - 1
	StreamIDMaxUni  = 1<<60 - 2
)

// Version is a QUIC version number.
type Version uint32

const (
	Version1 Version = 0x00000001
	Version2 Version = 0x6b3343cf
)

// SupportedVersions lists all supported versions.
var SupportedVersions = []Version{Version1, Version2}

// Perspective indicates whether the endpoint is a client or server.
type Perspective uint8

const (
	PerspectiveServer Perspective = 1
	PerspectiveClient Perspective = 2
)

func (p Perspective) Opposite() Perspective {
	return 3 - p
}

// ErrCode is a QUIC transport error code.
type ErrCode uint64

const (
	ErrCodeNoError                 ErrCode = 0
	ErrCodeInternal                ErrCode = 1
	ErrCodeConnectionRefused       ErrCode = 2
	ErrCodeFlowControlError        ErrCode = 3
	ErrCodeStreamLimitError        ErrCode = 4
	ErrCodeStreamStateError        ErrCode = 5
	ErrCodeFinalSizeError          ErrCode = 6
	ErrCodeFrameEncodingError      ErrCode = 7
	ErrCodeTransportParameterError ErrCode = 8
	ErrCodeConnectionIDLimitError  ErrCode = 9
	ErrCodeProtocolViolation       ErrCode = 10
	ErrCodeInvalidToken            ErrCode = 11
	ErrCodeApplicationError        ErrCode = 12
	ErrCodeCryptoBufferExceeded    ErrCode = 13
	ErrCodeKeyUpdateError          ErrCode = 14
	ErrCodeAEADLimitReached        ErrCode = 15
	ErrCodeNoViablePath            ErrCode = 16
)

// StreamType returns the type of a stream (bidi or uni).
func (s StreamID) StreamType() StreamType {
	if s%4 >= 2 {
		return StreamTypeUni
	}
	return StreamTypeBidi
}

// InitiatedBy returns the perspective that initiated the stream.
func (s StreamID) InitiatedBy() Perspective {
	if s%2 == 0 {
		return PerspectiveClient
	}
	return PerspectiveServer
}

// StreamNum returns the stream number (0-based).
func (s StreamID) StreamNum() int64 {
	return int64(s) / 4
}

// StreamIDFromParts constructs a StreamID from its components.
func StreamIDFromParts(streamNum int64, streamType StreamType, pers Perspective) StreamID {
	id := streamNum * 4
	if streamType == StreamTypeUni {
		id += 2
	}
	if pers == PerspectiveServer {
		id += 1
	}
	return StreamID(id)
}

// EncodePacketNumber encodes a packet number into a slice of the given length.
func EncodePacketNumber(pn PacketNumber, pnLen PacketNumberLen) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(pn))
	return b[4-uint8(pnLen):]
}

// AppendPacketNumber appends the encoded packet number to b.
func AppendPacketNumber(b []byte, pn PacketNumber, pnLen PacketNumberLen) []byte {
	switch pnLen {
	case PacketNumberLen1:
		return append(b, byte(pn))
	case PacketNumberLen2:
		return append(b, byte(pn>>8), byte(pn))
	case PacketNumberLen3:
		return append(b, byte(pn>>16), byte(pn>>8), byte(pn))
	case PacketNumberLen4:
		return append(b, byte(pn>>24), byte(pn>>16), byte(pn>>8), byte(pn))
	default:
		panic(fmt.Sprintf("invalid packet number length: %d", pnLen))
	}
}
