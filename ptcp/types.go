// Package ptcp implements the Dahua PTCP (PhonyTCP) protocol.
// PTCP encapsulates TCP packets within UDP for NAT traversal.
package ptcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Magic is the PTCP header magic bytes
var Magic = []byte("PTCP")

// Packet types
const (
	TypeSync      byte = 0x00 // SYN packet, body is always 0x00030100
	TypePayload   byte = 0x10 // TCP data payload
	TypeBind      byte = 0x11 // Binding port request
	TypeStatus    byte = 0x12 // Connection status (CONN/DISC)
	TypeHeartbeat byte = 0x13 // Heartbeat, len is always 0

	// Types 0x17-0x1B carry the handshake command exchange (sign request,
	// auth, auth response, auth ack). They are written as literals in
	// dh.Handshake and parsed here as BodyTypeCommand.
)

// Status values
const (
	StatusConnect    = "CONN"
	StatusDisconnect = "DISC"
)

// Errors
var (
	ErrInvalidMagic    = errors.New("invalid PTCP magic")
	ErrPacketTooShort  = errors.New("packet too short")
	ErrInvalidPadding  = errors.New("invalid padding")
	ErrInvalidLength   = errors.New("invalid payload length")
	ErrInvalidBodyType = errors.New("invalid body type")
)

// Header represents the PTCP packet header (24 bytes)
type Header struct {
	Sent uint32 // Number of bytes sent
	Recv uint32 // Number of bytes received
	PID  uint32 // Packet ID
	LMID uint32 // Local Message ID
	RMID uint32 // Remote Message ID (of previously received packet)
}

// HeaderSize is the size of the PTCP header
const HeaderSize = 24

// Serialize serializes the header to bytes
func (h *Header) Serialize() []byte {
	buf := make([]byte, HeaderSize)
	copy(buf[0:4], Magic)
	binary.BigEndian.PutUint32(buf[4:8], h.Sent)
	binary.BigEndian.PutUint32(buf[8:12], h.Recv)
	binary.BigEndian.PutUint32(buf[12:16], h.PID)
	binary.BigEndian.PutUint32(buf[16:20], h.LMID)
	binary.BigEndian.PutUint32(buf[20:24], h.RMID)
	return buf
}

// ParseHeader parses a PTCP header from bytes
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, ErrPacketTooShort
	}
	if string(data[0:4]) != string(Magic) {
		return nil, ErrInvalidMagic
	}
	return &Header{
		Sent: binary.BigEndian.Uint32(data[4:8]),
		Recv: binary.BigEndian.Uint32(data[8:12]),
		PID:  binary.BigEndian.Uint32(data[12:16]),
		LMID: binary.BigEndian.Uint32(data[16:20]),
		RMID: binary.BigEndian.Uint32(data[20:24]),
	}, nil
}

// BodyType represents the type of PTCP body
type BodyType int

const (
	BodyTypeEmpty BodyType = iota
	BodyTypeSync
	BodyTypeCommand
	BodyTypePayload
	BodyTypeBind
	BodyTypeStatus
	BodyTypeHeartbeat
)

// Body represents the PTCP packet body
type Body struct {
	Type    BodyType
	Realm   uint32
	Data    []byte
	Status  string // For status body type
	Port    uint32 // For bind body type
	Command []byte // For command body type
}

// NewEmptyBody creates an empty body
func NewEmptyBody() *Body {
	return &Body{Type: BodyTypeEmpty}
}

// NewSyncBody creates a sync body
func NewSyncBody() *Body {
	return &Body{Type: BodyTypeSync}
}

// NewHeartbeatBody creates a heartbeat body
func NewHeartbeatBody() *Body {
	return &Body{Type: BodyTypeHeartbeat}
}

// NewPayloadBody creates a payload body
func NewPayloadBody(realm uint32, data []byte) *Body {
	return &Body{
		Type:  BodyTypePayload,
		Realm: realm,
		Data:  data,
	}
}

// NewBindBody creates a bind body
func NewBindBody(realm uint32, port uint32) *Body {
	return &Body{
		Type:  BodyTypeBind,
		Realm: realm,
		Port:  port,
	}
}

// NewStatusBody creates a status body
func NewStatusBody(realm uint32, status string) *Body {
	return &Body{
		Type:   BodyTypeStatus,
		Realm:  realm,
		Status: status,
	}
}

// NewCommandBody creates a command body
func NewCommandBody(command []byte) *Body {
	return &Body{
		Type:    BodyTypeCommand,
		Command: command,
	}
}

// Len returns the length of the body when serialized
func (b *Body) Len() int {
	switch b.Type {
	case BodyTypeEmpty:
		return 0
	case BodyTypeSync:
		return 4
	case BodyTypeCommand:
		return len(b.Command)
	case BodyTypePayload:
		return len(b.Data) + 12
	case BodyTypeBind:
		return 20
	case BodyTypeStatus:
		return len(b.Status) + 12
	case BodyTypeHeartbeat:
		return 12
	default:
		return 0
	}
}

// Serialize serializes the body to bytes
func (b *Body) Serialize() []byte {
	switch b.Type {
	case BodyTypeEmpty:
		return nil
	case BodyTypeSync:
		return []byte{0x00, 0x03, 0x01, 0x00}
	case BodyTypeCommand:
		return b.Command
	case BodyTypePayload:
		length := uint32(len(b.Data))
		header := 0x10000000 | length
		buf := make([]byte, 12+len(b.Data))
		binary.BigEndian.PutUint32(buf[0:4], header)
		binary.BigEndian.PutUint32(buf[4:8], b.Realm)
		binary.BigEndian.PutUint32(buf[8:12], 0) // padding
		copy(buf[12:], b.Data)
		return buf
	case BodyTypeBind:
		buf := make([]byte, 20)
		dataLen := uint32(8) // port (4) + IP (4)
		binary.BigEndian.PutUint32(buf[0:4], uint32(TypeBind)<<24|dataLen)
		binary.BigEndian.PutUint32(buf[4:8], b.Realm)
		binary.BigEndian.PutUint32(buf[12:16], b.Port)
		buf[16], buf[17], buf[18], buf[19] = 0x7f, 0x00, 0x00, 0x01
		return buf
	case BodyTypeStatus:
		// The length field stays zero even though CONN/DISC follows: both the
		// device and the DMSS app send 12 000000 <realm> <pad> "CONN", so the
		// four bytes are found by position, not by the length. The body still
		// counts as 16 towards the byte counters.
		buf := make([]byte, 12+len(b.Status))
		binary.BigEndian.PutUint32(buf[0:4], uint32(TypeStatus)<<24)
		binary.BigEndian.PutUint32(buf[4:8], b.Realm)
		copy(buf[12:], b.Status)
		return buf
	case BodyTypeHeartbeat:
		buf := make([]byte, 12)
		buf[0] = TypeHeartbeat
		return buf
	default:
		return nil
	}
}

// ParseBody parses a PTCP body from bytes
func ParseBody(data []byte) (*Body, error) {
	if len(data) == 0 {
		return NewEmptyBody(), nil
	}

	if len(data) < 4 {
		return nil, ErrPacketTooShort
	}

	switch data[0] {
	case TypeSync:
		return NewSyncBody(), nil
	case TypePayload:
		if len(data) < 12 {
			return nil, ErrPacketTooShort
		}
		header := binary.BigEndian.Uint32(data[0:4])
		// Body header is type(1 byte) + length(3 bytes).
		length := header & 0xFFFFFF
		realm := binary.BigEndian.Uint32(data[4:8])
		padding := binary.BigEndian.Uint32(data[8:12])
		if padding != 0 {
			return nil, ErrInvalidPadding
		}
		payloadData := data[12:]
		if uint32(len(payloadData)) != length {
			return nil, ErrInvalidLength
		}
		return NewPayloadBody(realm, payloadData), nil
	case TypeBind:
		if len(data) < 16 {
			return nil, ErrPacketTooShort
		}
		realm := binary.BigEndian.Uint32(data[4:8])
		port := binary.BigEndian.Uint32(data[12:16])
		return NewBindBody(realm, port), nil
	case TypeStatus:
		if len(data) < 12 {
			return nil, ErrPacketTooShort
		}
		realm := binary.BigEndian.Uint32(data[4:8])
		status := strings.TrimRight(string(data[12:]), "\x00")
		return NewStatusBody(realm, status), nil
	case TypeHeartbeat:
		return NewHeartbeatBody(), nil
	default:
		// Treat as command
		return NewCommandBody(data), nil
	}
}

// Packet represents a complete PTCP packet (header + body)
type Packet struct {
	Header *Header
	Body   *Body
}

// NewPacket creates a new packet
func NewPacket(header *Header, body *Body) *Packet {
	return &Packet{Header: header, Body: body}
}

// Serialize serializes the packet to bytes
func (p *Packet) Serialize() []byte {
	headerBytes := p.Header.Serialize()
	bodyBytes := p.Body.Serialize()
	result := make([]byte, len(headerBytes)+len(bodyBytes))
	copy(result, headerBytes)
	copy(result[len(headerBytes):], bodyBytes)
	return result
}

// ParsePacket parses a PTCP packet from bytes
func ParsePacket(data []byte) (*Packet, error) {
	header, err := ParseHeader(data)
	if err != nil {
		return nil, err
	}
	body, err := ParseBody(data[HeaderSize:])
	if err != nil {
		return nil, err
	}
	return NewPacket(header, body), nil
}

// String returns a string representation of the packet
func (p *Packet) String() string {
	return fmt.Sprintf("Packet{sent=%d, recv=%d, pid=0x%08X, lmid=0x%08X, rmid=0x%08X, body=%v}",
		p.Header.Sent, p.Header.Recv, p.Header.PID, p.Header.LMID, p.Header.RMID, p.Body.Type)
}
