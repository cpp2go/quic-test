package wire

import (
	"encoding/binary"
	"fmt"
	"io"

	"quic-test/quic/protocol"
	"quic-test/quic/quicvarint"
)

// IsLongHeaderPacket checks if the first byte indicates a long header packet.
func IsLongHeaderPacket(firstByte byte) bool {
	return firstByte&0x80 > 0
}

// IsPotentialQUICPacket checks if the first byte looks like a QUIC packet.
func IsPotentialQUICPacket(firstByte byte) bool {
	return firstByte&0x40 > 0
}

// IsVersionNegotiationPacket checks if the packet is a version negotiation packet.
func IsVersionNegotiationPacket(b []byte) bool {
	return len(b) >= 5 && IsLongHeaderPacket(b[0]) && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0
}

// Header represents a QUIC long header packet header.
type Header struct {
	typeByte         byte
	Type             protocol.PacketType
	Version          protocol.Version
	SrcConnectionID  protocol.ConnectionID
	DestConnectionID protocol.ConnectionID
	Length           protocol.ByteCount
	Token            []byte
	parsedLen        protocol.ByteCount
}

// ParsedLen returns the number of bytes consumed during parsing.
func (h *Header) ParsedLen() protocol.ByteCount {
	return h.parsedLen
}

// ParsePacket parses a QUIC packet and returns the header and the payload.
// For long header packets, it returns the header and payload.
// For short header packets, it returns nil for header (use ParseShortHeader).
func ParsePacket(data []byte) (*Header, []byte, error) {
	if len(data) == 0 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	if !IsLongHeaderPacket(data[0]) {
		// Short header packet
		return nil, data, nil
	}
	return parseLongHeaderPacket(data)
}

func parseLongHeaderPacket(data []byte) (*Header, []byte, error) {
	h := &Header{}
	if len(data) < 5 {
		return nil, nil, io.ErrUnexpectedEOF
	}

	// Byte 0: first byte
	firstByte := data[0]
	h.typeByte = firstByte
	// Wire format (Version 1): bits 5-4 encode packet type
	// 00=Initial, 01=0-RTT, 10=Handshake, 11=Retry
	wireType := (firstByte >> 4) & 0x3
	switch wireType {
	case 0:
		h.Type = protocol.PacketTypeInitial
	case 1:
		h.Type = protocol.PacketType0RTT
	case 2:
		h.Type = protocol.PacketTypeHandshake
	case 3:
		h.Type = protocol.PacketTypeRetry
	}

	// Bytes 1-4: Version
	h.Version = protocol.Version(binary.BigEndian.Uint32(data[1:5]))
	offset := 5

	if IsVersionNegotiationPacket(data) {
		return nil, nil, fmt.Errorf("version negotiation packet not supported")
	}

	if offset >= len(data) {
		return nil, nil, io.ErrUnexpectedEOF
	}

	// Destination Connection ID Length
	destCIDLen := int(data[offset])
	offset++
	if offset+destCIDLen > len(data) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	if destCIDLen > 0 && destCIDLen <= protocol.MaxConnIDLen {
		h.DestConnectionID = protocol.ParseConnectionID(data[offset : offset+destCIDLen])
	}
	offset += destCIDLen

	if offset >= len(data) {
		return nil, nil, io.ErrUnexpectedEOF
	}

	// Source Connection ID Length
	srcCIDLen := int(data[offset])
	offset++
	if offset+srcCIDLen > len(data) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	if srcCIDLen > 0 && srcCIDLen <= protocol.MaxConnIDLen {
		h.SrcConnectionID = protocol.ParseConnectionID(data[offset : offset+srcCIDLen])
	}
	offset += srcCIDLen

	// Token (only for Initial packets)
	if h.Type == protocol.PacketTypeInitial {
		if offset >= len(data) {
			return nil, nil, io.ErrUnexpectedEOF
		}
		tokenLen, consumed, err := quicvarint.Parse(data[offset:])
		if err != nil {
			return nil, nil, err
		}
		offset += consumed
		if offset+int(tokenLen) > len(data) {
			return nil, nil, io.ErrUnexpectedEOF
		}
		h.Token = make([]byte, tokenLen)
		copy(h.Token, data[offset:offset+int(tokenLen)])
		offset += int(tokenLen)
	}

	// Length
	if offset >= len(data) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	length, consumed, err := quicvarint.Parse(data[offset:])
	if err != nil {
		return nil, nil, err
	}
	h.Length = protocol.ByteCount(length)
	offset += consumed

	h.parsedLen = protocol.ByteCount(offset)

	// Payload starts at offset
	payloadEnd := offset + int(length)
	if payloadEnd > len(data) {
		payloadEnd = len(data)
	}
	payload := data[offset:payloadEnd]

	return h, payload, nil
}

// ExtendedHeader extends Header with packet number information.
type ExtendedHeader struct {
	Header
	PacketNumberLen protocol.PacketNumberLen
	PacketNumber    protocol.PacketNumber
	parsedLen       protocol.ByteCount
}

// ParsedLen returns the total parsed length including header and packet number.
func (h *ExtendedHeader) ParsedLen() protocol.ByteCount {
	return h.parsedLen
}

// ParseExtended parses an extended header (header + packet number) from the beginning of the payload.
// firstByte is the first byte of the packet (contains pnLen in bits 1-0).
func (h *Header) ParseExtended(payload []byte) (*ExtendedHeader, error) {
	return h.parseExtendedFromPayload(payload, h.typeByte)
}

// parseExtendedFromPayload parses the packet number from the payload using the type byte.
func (h *Header) parseExtendedFromPayload(payload []byte, typeByte byte) (*ExtendedHeader, error) {
	eh := &ExtendedHeader{
		Header: *h,
	}

	// For long header: bits 1-0 of the packet's first byte encode packet number length - 1
	pnLen := (typeByte & 0x03) + 1
	eh.PacketNumberLen = protocol.PacketNumberLen(pnLen)

	eh.parsedLen = h.parsedLen

	// Read packet number from payload (starts right after Length field)
	if int(pnLen) > len(payload) {
		return nil, io.ErrUnexpectedEOF
	}

	var pn uint32
	switch pnLen {
	case 1:
		pn = uint32(payload[0])
	case 2:
		pn = binary.BigEndian.Uint32([]byte{0, 0, payload[0], payload[1]})
	case 3:
		pn = binary.BigEndian.Uint32([]byte{0, payload[0], payload[1], payload[2]})
	case 4:
		pn = binary.BigEndian.Uint32(payload[0:4])
	}
	eh.PacketNumber = protocol.PacketNumber(pn)

	// Total parsed = header offset + pnLen bytes
	eh.parsedLen += protocol.ByteCount(pnLen)

	return eh, nil
}

// Append appends the extended header to b.
func (h *ExtendedHeader) Append(b []byte, version protocol.Version) ([]byte, error) {
	// Map internal types to wire format (Version 1)
	// 00=Initial, 01=0-RTT, 10=Handshake, 11=Retry
	var wireType uint8
	switch h.Type {
	case protocol.PacketTypeInitial:
		wireType = 0
	case protocol.PacketType0RTT:
		wireType = 1
	case protocol.PacketTypeHandshake:
		wireType = 2
	case protocol.PacketTypeRetry:
		wireType = 3
	}
	// First byte: 0xc0 | wire_type<<4 | (pnLen-1)
	firstByte := byte(0xc0) | wireType<<4 | byte(h.PacketNumberLen-1)
	b = append(b, firstByte)

	// Version
	ver := make([]byte, 4)
	binary.BigEndian.PutUint32(ver, uint32(version))
	b = append(b, ver...)

	// Dest Connection ID
	b = append(b, byte(h.DestConnectionID.Len()))
	b = append(b, h.DestConnectionID.Bytes()...)

	// Source Connection ID
	b = append(b, byte(h.SrcConnectionID.Len()))
	b = append(b, h.SrcConnectionID.Bytes()...)

	// Token (Initial only)
	if h.Type == protocol.PacketTypeInitial && len(h.Token) > 0 {
		b = quicvarint.Append(b, uint64(len(h.Token)))
		b = append(b, h.Token...)
	} else if h.Type == protocol.PacketTypeInitial {
		b = quicvarint.Append(b, 0)
	}

	// Length placeholder (will be filled after payload is built)
	// We use a fixed-length encoding (2 bytes) for simplicity
	b = append(b, 0x40, 0) // 2-byte varint, value 0 placeholder

	// Packet number
	b = protocol.AppendPacketNumber(b, h.PacketNumber, h.PacketNumberLen)

	return b, nil
}

// SetLength updates the length field in the serialized packet.
func SetLength(b []byte, length protocol.ByteCount) {
	// Find the length field - it's after the source connection ID
	offset := 5 // first byte + version

	// Destination Connection ID
	destCIDLen := int(b[offset])
	offset += 1 + destCIDLen

	// Source Connection ID
	srcCIDLen := int(b[offset])
	offset += 1 + srcCIDLen

	// Token (Initial only) - skip token
	firstByte := b[0]
	packetType := protocol.PacketType((firstByte >> 4) & 0x7)
	if packetType == protocol.PacketTypeInitial {
		tokenLen, consumed, _ := quicvarint.Parse(b[offset:])
		offset += consumed + int(tokenLen)
	}

	// Length field at offset, 2 bytes
	b[offset] = byte(length>>8) | 0x40
	b[offset+1] = byte(length)
}

// PacketNumberStart returns the offset where the packet number starts.
func (h *ExtendedHeader) PacketNumberStart() protocol.ByteCount {
	return h.parsedLen - protocol.ByteCount(h.PacketNumberLen)
}

// ParseShortHeaderConnID extracts the destination connection ID from a short header packet.
// Uses the default connection ID length (8 bytes).
func ParseShortHeaderConnID(data []byte) (protocol.ConnectionID, error) {
	if len(data) < 1 {
		return protocol.ConnectionID{}, io.ErrUnexpectedEOF
	}
	if IsLongHeaderPacket(data[0]) {
		return protocol.ConnectionID{}, fmt.Errorf("not a short header packet")
	}
	// Short header: first byte flags, then connID (8 bytes default), then packet number
	const defaultConnIDLen = 8
	if len(data) < 1+defaultConnIDLen {
		return protocol.ConnectionID{}, io.ErrUnexpectedEOF
	}
	return protocol.ParseConnectionID(data[1 : 1+defaultConnIDLen]), nil
}

// ParseShortHeader parses a short header packet.
// Returns: bytes consumed, packet number, packet number length, key phase, error
func ParseShortHeader(data []byte, connIDLen int) (int, protocol.PacketNumber, protocol.PacketNumberLen, error) {
	if len(data) < 1 {
		return 0, 0, 0, io.ErrUnexpectedEOF
	}

	firstByte := data[0]
	if firstByte&0x80 > 0 {
		return 0, 0, 0, fmt.Errorf("not a short header packet")
	}

	// Bits 1-0: packet number length - 1
	pnLen := protocol.PacketNumberLen((firstByte & 0x03) + 1)

	// After first byte: connection ID, then packet number
	offset := 1 + connIDLen

	if offset+int(pnLen) > len(data) {
		return 0, 0, 0, io.ErrUnexpectedEOF
	}

	var pn uint32
	switch pnLen {
	case 1:
		pn = uint32(data[offset])
	case 2:
		pn = binary.BigEndian.Uint32([]byte{0, 0, data[offset], data[offset+1]})
	case 3:
		pn = binary.BigEndian.Uint32([]byte{0, data[offset], data[offset+1], data[offset+2]})
	case 4:
		pn = binary.BigEndian.Uint32(data[offset : offset+4])
	}

	consumed := offset + int(pnLen)
	return consumed, protocol.PacketNumber(pn), pnLen, nil
}

// AppendShortHeader appends a short header packet prefix to b.
func AppendShortHeader(b []byte, connID protocol.ConnectionID, pn protocol.PacketNumber, pnLen protocol.PacketNumberLen) []byte {
	// First byte: 0x40 | (pnLen-1)
	firstByte := byte(0x40) | byte(pnLen-1)
	b = append(b, firstByte)
	b = append(b, connID.Bytes()...)
	b = protocol.AppendPacketNumber(b, pn, pnLen)
	return b
}
