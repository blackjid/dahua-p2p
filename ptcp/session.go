package ptcp

import (
	"sync"
	"time"
)

// Session manages the PTCP session state
type Session struct {
	mu   sync.Mutex
	sent uint32 // Total bytes sent
	recv uint32 // Total bytes received
	rmid uint32 // Remote message ID (from last received packet)

	// lastPIDRecv is s.recv as of our previous transmission. PID reports the
	// bytes taken in since then; see pid.
	lastPIDRecv uint32

	// clock supplies LMID. Both endpoints put a millisecond clock there, not
	// a counter; see lmid.
	clock  func() uint32
	epoch  time.Time
	origin uint32

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
	LMID uint32 // our millisecond clock as of the last packet sent

	PeerSent uint32 // body bytes the device says it has sent
	PeerRecv uint32 // body bytes the device says it has received from us
	PeerRMID uint32 // our clock as of the last packet the device acknowledged
}

// delta subtracts two wrapping uint32 counters as a signed value, so a
// counter that has run slightly ahead reads as a small negative number
// rather than ~4 billion.
func delta(a, b uint32) int64 { return int64(int32(a - b)) }

// OutBytes is our data the device has not acknowledged. It is normally a
// small in-flight amount that keeps returning to 0; a value that only grows
// means outbound packets are being lost.
func (t Stats) OutBytes() int64 { return delta(t.Sent, t.PeerRecv) }

// OutLagMillis is how far our clock has run on past the last reading of it
// the device echoed back: the round trip plus whatever the device spent
// before answering. Unlike OutBytes it keeps growing while the tunnel is
// idle, because the clock advances whether or not we send anything, so only
// compare it against the moment a packet was last sent.
func (t Stats) OutLagMillis() int64 { return delta(t.LMID, t.PeerRMID) }

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
		Sent: s.sent, Recv: s.recv, LMID: s.lmid(),
		PeerSent: s.peerSent, PeerRecv: s.peerRecv, PeerRMID: s.peerRMID,
	}
}

// processStart anchors the LMID clock. Both endpoints carry an uptime in that
// field — 24 million for the app in the capture, 143 million for the device —
// so the clock belongs to the process, not to one session, and a tunnel
// rebuilt an hour in carries on from where the last one left off.
var processStart = time.Now()

// lmidBase keeps the clock clear of 0, which is the value RMID carries before
// anything has been received.
const lmidBase = 60_000

// lmidMask holds the clock below 2^31, where a peer storing it signed would
// read it as negative. Seeding it from the wall clock put it there outright;
// plain uptime gets there too, after 24.8 days. Neither endpoint in the
// capture emits anything near that — the app carried 24 million and the device
// 143 million — so the clock wraps at 24.8 days of uptime rather than ever
// leaving the band they use. RMID deltas are computed as wrapping signed
// values, so the wrap costs one stale reading, not a stuck one.
const lmidMask = 0x7FFFFFFF

// NewSession creates a new PTCP session
func NewSession() *Session {
	return newSessionAt(processStart)
}

func newSessionAt(start time.Time) *Session {
	s := &Session{epoch: start, origin: lmidBase}
	s.clock = func() uint32 {
		ms := uint32(time.Since(s.epoch).Milliseconds() & lmidMask)
		return (s.origin + quantizeLMID(ms)) & lmidMask
	}
	return s
}

// lmidTick is the granularity the endpoints quantize their clock to. Every
// LMID in a capture is a multiple of it (offset by a per-endpoint constant),
// so packets sent inside the same tick share one.
const lmidTick = 10

func quantizeLMID(ms uint32) uint32 { return ms - ms%lmidTick }

// lmid is the millisecond clock both endpoints carry in the LMID field.
// Measured against a DMSS capture it advances at exactly 1.000 units per
// millisecond in both directions across 15.7s, and 1573 of 2610 consecutive
// packets repeat the previous value. It is a timestamp, not a sequence
// number: nothing downstream may assume it is unique per packet or that it
// counts anything.
//
// Must be called with s.mu held.
func (s *Session) lmid() uint32 { return s.clock() }

// pid fills the PID field, which the DMSS capture shows is not a packet
// identifier: three BINDs for three different realms went out 10ms apart
// carrying pid=63345 and the device granted all three, and the device itself
// used only 83 distinct values across 4776 packets. The low 16 bits hold
// 0xFFFF minus a small byte count derived from what has been received, never
// straying more than ~4000 below 0xFFFF.
//
// We report the bytes taken in since our previous transmission, which matches
// the capture on about half its packets and, more to the point, keeps the
// field in the band the device produces. The old monotonic packet counter
// left that band after ~4000 packets and wrapped every ~65536, sweeping a
// field the device reads as a receive-side quantity.
//
// Must be called with s.mu held.
func (s *Session) pid() uint32 {
	taken := s.recv - s.lastPIDRecv
	if taken > 0xFFFF {
		taken = 0xFFFF
	}
	return 0x0000FFFF - taken
}

// Send creates a packet for the given body and updates session state
func (s *Session) Send(body *Body) *Packet {
	s.mu.Lock()
	defer s.mu.Unlock()

	header := &Header{
		Sent: s.sent,
		Recv: s.recv,
		LMID: s.lmid(),
		RMID: s.rmid,
	}

	if body.Type == BodyTypeSync {
		header.PID = 0x0002FFFF
	} else {
		header.PID = s.pid()
		s.lastPIDRecv = s.recv
	}

	s.sent += uint32(body.Len())

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
