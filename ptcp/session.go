package ptcp

import (
	"sync"
)

// Session manages the PTCP session state
type Session struct {
	mu    sync.Mutex
	sent  uint32 // Total bytes sent
	recv  uint32 // Total bytes received
	count uint32 // Packet counter (excluding sync/empty)
	id    uint32 // Local message ID counter
	rmid  uint32 // Remote message ID (from last received packet)

	// The peer's view of the same conversation, taken from the last packet
	// it sent us. peerRecv/peerRMID are its acknowledgement of our data;
	// peerSent is how much it believes it has sent us.
	peerSent uint32
	peerRecv uint32
	peerRMID uint32
}

// Stats is a snapshot of both endpoints' counters, used to detect loss.
type Stats struct {
	Sent uint32 // body bytes we have sent
	Recv uint32 // body bytes we have counted as received
	LMID uint32 // messages we have sent

	PeerSent uint32 // body bytes the device says it has sent
	PeerRecv uint32 // body bytes the device says it has received from us
	PeerRMID uint32 // last message of ours the device acknowledged
}

// delta subtracts two wrapping uint32 counters as a signed value, so a
// counter that has run slightly ahead reads as a small negative number
// rather than ~4 billion.
func delta(a, b uint32) int64 { return int64(int32(a - b)) }

// OutBytes is our data the device has not acknowledged. It is normally a
// small in-flight amount that keeps returning to 0; a value that only grows
// means outbound packets are being lost.
func (t Stats) OutBytes() int64 { return delta(t.Sent, t.PeerRecv) }

// OutMsgs is the same signal at message rather than byte granularity. It
// settles at a steady non-zero lag, because the device advances RMID more
// slowly than we emit coalesced ACKs; only growth indicates loss.
func (t Stats) OutMsgs() int64 { return delta(t.LMID, t.PeerRMID) }

// InBytes is data the device claims to have sent that we never counted.
// Slightly negative is normal and means the opposite: the device's Sent in
// the header we are reading predates packets we have already consumed, so we
// are up to one packet ahead of its snapshot. Only sustained growth is loss.
func (t Stats) InBytes() int64 { return delta(t.PeerSent, t.Recv) }

// Stats returns a snapshot of both endpoints' counters.
func (s *Session) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{
		Sent: s.sent, Recv: s.recv, LMID: s.id,
		PeerSent: s.peerSent, PeerRecv: s.peerRecv, PeerRMID: s.peerRMID,
	}
}

// NewSession creates a new PTCP session
func NewSession() *Session {
	return &Session{}
}

// Send creates a packet for the given body and updates session state
func (s *Session) Send(body *Body) *Packet {
	s.mu.Lock()
	defer s.mu.Unlock()

	header := &Header{
		Sent: s.sent,
		Recv: s.recv,
		LMID: s.id,
		RMID: s.rmid,
	}

	// Calculate PID based on body type. The counter is masked to 16 bits so
	// the high half stays zero: without the mask, PID underflows past
	// 0x0000FFFF after 65536 packets (~20min of streaming, since coalesced
	// ACKs run at up to 50/s) and sets bits the device never sees us use.
	switch body.Type {
	case BodyTypeSync:
		header.PID = 0x0002FFFF
	default:
		header.PID = 0x0000FFFF - (s.count & 0xFFFF)
	}

	// Update counters
	s.sent += uint32(body.Len())
	s.id++

	// Increment count for all non-sync packets so each gets a unique PID.
	// The device uses PID for deduplication and will discard duplicate PIDs.
	if body.Type != BodyTypeSync {
		s.count++
	}

	return NewPacket(header, body)
}

// Recv processes a received packet and updates session state
func (s *Session) Recv(packet *Packet) *Packet {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.recv += uint32(packet.Body.Len())
	s.rmid = packet.Header.LMID

	s.peerSent = packet.Header.Sent
	s.peerRecv = packet.Header.Recv
	s.peerRMID = packet.Header.RMID

	return packet
}
