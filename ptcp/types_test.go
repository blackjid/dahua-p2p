package ptcp

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

func TestHeaderRoundTrip(t *testing.T) {
	h := &Header{
		Sent: 0x11223344,
		Recv: 0x55667788,
		PID:  0x99AABBCC,
		LMID: 0xDDEEFF00,
		RMID: 0x12345678,
	}
	data := h.Serialize()
	if len(data) != HeaderSize {
		t.Fatalf("header size: got %d, want %d", len(data), HeaderSize)
	}
	if string(data[:4]) != string(Magic) {
		t.Fatalf("bad magic: got %q", data[:4])
	}

	parsed, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *parsed != *h {
		t.Fatalf("roundtrip mismatch: got %+v, want %+v", parsed, h)
	}
}

func TestParseHeaderTooShort(t *testing.T) {
	if _, err := ParseHeader(make([]byte, HeaderSize-1)); err != ErrPacketTooShort {
		t.Fatalf("expected ErrPacketTooShort, got %v", err)
	}
}

func TestParseHeaderBadMagic(t *testing.T) {
	buf := make([]byte, HeaderSize)
	copy(buf, []byte("XXXX"))
	if _, err := ParseHeader(buf); err != ErrInvalidMagic {
		t.Fatalf("expected ErrInvalidMagic, got %v", err)
	}
}

func TestBodyRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		body *Body
	}{
		{"sync", NewSyncBody()},
		{"heartbeat", NewHeartbeatBody()},
		{"payload", NewPayloadBody(0xDEADBEEF, []byte("hello RTSP world"))},
		{"bind", NewBindBody(0xCAFEBABE, 554)},
		{"status_conn", NewStatusBody(0x12345678, StatusConnect)},
		{"status_disc", NewStatusBody(0x12345678, StatusDisconnect)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.body.Serialize()
			if got, want := len(data), tc.body.Len(); got != want {
				t.Fatalf("Len()=%d but Serialize() produced %d bytes", want, got)
			}
			parsed, err := ParseBody(data)
			if err != nil {
				t.Fatalf("ParseBody: %v", err)
			}
			if parsed.Type != tc.body.Type {
				t.Fatalf("type: got %v, want %v", parsed.Type, tc.body.Type)
			}
			if parsed.Realm != tc.body.Realm {
				t.Fatalf("realm: got %x, want %x", parsed.Realm, tc.body.Realm)
			}
			if tc.body.Type == BodyTypePayload && !bytes.Equal(parsed.Data, tc.body.Data) {
				t.Fatalf("payload data mismatch: got %q, want %q", parsed.Data, tc.body.Data)
			}
			if tc.body.Type == BodyTypeBind && parsed.Port != tc.body.Port {
				t.Fatalf("port: got %d, want %d", parsed.Port, tc.body.Port)
			}
			if tc.body.Type == BodyTypeStatus && parsed.Status != tc.body.Status {
				t.Fatalf("status: got %q, want %q", parsed.Status, tc.body.Status)
			}
		})
	}
}

func TestParseBodyEmpty(t *testing.T) {
	b, err := ParseBody(nil)
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if b.Type != BodyTypeEmpty {
		t.Fatalf("expected BodyTypeEmpty, got %v", b.Type)
	}
}

func TestParsePayloadRejectsBadPadding(t *testing.T) {
	// Craft a payload body with non-zero padding bytes.
	buf := []byte{
		0x10, 0x00, 0x00, 0x04, // type=payload, length=4
		0x00, 0x00, 0x00, 0x01, // realm
		0x00, 0x00, 0x00, 0x01, // non-zero padding
		0x41, 0x42, 0x43, 0x44,
	}
	if _, err := ParseBody(buf); err != ErrInvalidPadding {
		t.Fatalf("expected ErrInvalidPadding, got %v", err)
	}
}

func TestParsePayloadRejectsShortData(t *testing.T) {
	buf := []byte{
		0x10, 0x00, 0x00, 0x08, // type=payload, claimed length=8
		0x00, 0x00, 0x00, 0x01, // realm
		0x00, 0x00, 0x00, 0x00, // padding
		0x41, 0x42, // only 2 bytes follow
	}
	if _, err := ParseBody(buf); err != ErrInvalidLength {
		t.Fatalf("expected ErrInvalidLength, got %v", err)
	}
}

func TestPacketRoundTrip(t *testing.T) {
	original := NewPacket(&Header{
		Sent: 100, Recv: 200, PID: 0x0000FFFD, LMID: 5, RMID: 3,
	}, NewPayloadBody(0xABCDEF01, []byte("payload bytes")))

	data := original.Serialize()
	parsed, err := ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if *parsed.Header != *original.Header {
		t.Fatalf("header mismatch: got %+v, want %+v", parsed.Header, original.Header)
	}
	if parsed.Body.Type != BodyTypePayload {
		t.Fatalf("body type: got %v, want %v", parsed.Body.Type, BodyTypePayload)
	}
	if parsed.Body.Realm != 0xABCDEF01 {
		t.Fatalf("realm: got %x, want %x", parsed.Body.Realm, uint32(0xABCDEF01))
	}
	if !bytes.Equal(parsed.Body.Data, []byte("payload bytes")) {
		t.Fatalf("data mismatch: got %q", parsed.Body.Data)
	}
}

// Bodies lifted byte-for-byte from a DMSS capture. The STAT length field is
// the subtle one: it stays zero even though CONN/DISC follows it, so the
// trailer is found by position.
func TestBodyWireShapeMatchesCapture(t *testing.T) {
	for _, tc := range []struct {
		name string
		body *Body
		want string
	}{
		{"disc", NewStatusBody(0xffd2c46c, StatusDisconnect), "12000000ffd2c46c0000000044495343"},
		{"conn", NewStatusBody(0x5f7f1ce8, StatusConnect), "120000005f7f1ce800000000434f4e4e"},
		{"bind", NewBindBody(0xfffffe91, 37777), "11000008fffffe9100000000000093917f000001"},
		{"heartbeat", NewHeartbeatBody(), "130000000000000000000000"},
		{"sync", NewSyncBody(), "00030100"},
	} {
		if got := hex.EncodeToString(tc.body.Serialize()); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, got, tc.want)
		}
	}
}

// PID is not a packet identifier. In a DMSS capture three BINDs for three
// different realms went out ten milliseconds apart all carrying pid=63345 and
// the device granted every one, and the device itself used 83 distinct values
// across 4776 packets. What it carries is 0xFFFF minus the bytes taken in
// since the previous transmission.
func TestSessionPIDReportsBytesTakenSinceLastSend(t *testing.T) {
	s := NewSession()

	if got := s.Send(NewEmptyBody()).Header.PID; got != 0xFFFF {
		t.Fatalf("PID with nothing received = %#x, want 0xFFFF", got)
	}

	// A heartbeat body counts 12 towards the receive counter.
	s.Recv(NewPacket(&Header{}, NewHeartbeatBody()))
	if got := s.Send(NewEmptyBody()).Header.PID; got != 0xFFFF-12 {
		t.Fatalf("PID after 12 bytes in = %#x, want %#x", got, 0xFFFF-12)
	}

	// Nothing new since, so the field reports zero rather than carrying on
	// down: it describes the gap, not how many packets we have sent.
	if got := s.Send(NewEmptyBody()).Header.PID; got != 0xFFFF {
		t.Fatalf("PID with nothing new received = %#x, want 0xFFFF", got)
	}
}

// The old scheme decremented a packet counter, which left the narrow band the
// device ever emits (never more than ~4000 below 0xFFFF) after a few thousand
// packets and wrapped every 65536. Sending forever must not do either.
func TestSessionPIDStaysInBand(t *testing.T) {
	s := NewSession()
	for i := 0; i < 70000; i++ {
		s.Recv(NewPacket(&Header{}, NewHeartbeatBody()))
		pkt := s.Send(NewHeartbeatBody())
		if pkt.Header.PID > 0x0000FFFF {
			t.Fatalf("packet %d: PID %#08x exceeds 16 bits", i, pkt.Header.PID)
		}
		if pkt.Header.PID != 0xFFFF-12 {
			t.Fatalf("packet %d: PID %#x drifted, want a steady %#x", i, pkt.Header.PID, 0xFFFF-12)
		}
	}
}

// LMID is a millisecond clock, not a sequence number: measured over a DMSS
// capture it advances at 1.000 units per millisecond in both directions, and
// 1573 of 2610 consecutive packets repeat the previous value. Packets sent
// inside one tick must therefore share an LMID rather than each taking a new
// one.
func TestSessionLMIDIsAClock(t *testing.T) {
	start := time.Now()
	s := newSessionAt(start)

	first := s.Send(NewHeartbeatBody()).Header.LMID
	for i := 0; i < 20; i++ {
		if got := s.Send(NewHeartbeatBody()).Header.LMID; got != first {
			t.Fatalf("packet %d in the same tick has LMID %d, want %d", i, got, first)
		}
	}
	if first == 0 {
		t.Fatal("LMID started at 0, the value RMID uses for 'nothing received yet'")
	}
	if first%lmidTick != 0 {
		t.Fatalf("LMID %d is not a multiple of the %d tick", first, lmidTick)
	}

	time.Sleep(3 * lmidTick * time.Millisecond)
	later := s.Send(NewHeartbeatBody()).Header.LMID
	elapsed := uint32(time.Since(start) / time.Millisecond)
	if later <= first {
		t.Fatalf("LMID %d did not advance past %d after sleeping", later, first)
	}
	if drift := int64(later-first) - int64(elapsed); drift > lmidTick || drift < -2*lmidTick {
		t.Fatalf("LMID advanced %d over %dms elapsed, want it to track the clock",
			later-first, elapsed)
	}
}

// The clock has to stay an uptime. Seeding it from the wall clock put the
// field above 2^31, where a peer storing it signed reads it as negative; the
// app in the capture carried 24 million and the device 143 million, and a
// bridge running for a year stays well under both.
func TestSessionLMIDStaysInTheRangeBothEndpointsUse(t *testing.T) {
	for _, uptime := range []time.Duration{
		time.Minute, 7 * 24 * time.Hour, 60 * 24 * time.Hour, 500 * 24 * time.Hour,
	} {
		s := newSessionAt(time.Now().Add(-uptime))
		got := s.Send(NewHeartbeatBody()).Header.LMID

		if got == 0 {
			t.Errorf("uptime %s: LMID is 0, the value RMID uses for 'nothing received yet'", uptime)
		}
		if got >= 1<<31 {
			t.Errorf("uptime %s: LMID %d is above 2^31 and reads as %d to a peer storing it signed",
				uptime, got, int32(got))
		}
	}

	// Inside the wrap it is still a clock, not a constant.
	s := newSessionAt(time.Now().Add(-time.Hour))
	if got, want := s.Send(NewHeartbeatBody()).Header.LMID, uint32(time.Hour.Milliseconds()); got < want {
		t.Fatalf("LMID %d after an hour of uptime, want at least %d: not tracking uptime", got, want)
	}
}

func TestSessionSyncHasFixedPID(t *testing.T) {
	s := NewSession()
	p := s.Send(NewSyncBody())
	if p.Header.PID != 0x0002FFFF {
		t.Fatalf("SYNC PID: got %#x, want 0x0002FFFF", p.Header.PID)
	}
}

// TestParsePayloadLongLength covers the 3-byte length field in the body
// header. A 2-byte mask silently truncates anything over 65535.
func TestParsePayloadLongLength(t *testing.T) {
	data := make([]byte, 70000)
	body := NewPayloadBody(0xDEADBEEF, data)

	got, err := ParseBody(body.Serialize())
	if err != nil {
		t.Fatalf("ParseBody: %v", err)
	}
	if len(got.Data) != len(data) {
		t.Fatalf("payload length: got %d, want %d", len(got.Data), len(data))
	}
	if got.Realm != 0xDEADBEEF {
		t.Fatalf("realm: got 0x%08X", got.Realm)
	}
}

// TestStatsDeltaSigned: counters wrap at 2^32 and our recv legitimately runs
// a packet ahead of the device's last reported Sent, so the gaps must read as
// small signed numbers rather than ~4 billion.
func TestStatsDeltaSigned(t *testing.T) {
	cases := []struct {
		name string
		st   Stats
		out  int64
		in   int64
	}{
		{"in flight", Stats{Sent: 100, PeerRecv: 88, PeerSent: 500, Recv: 500}, 12, 0},
		{"we are ahead", Stats{Sent: 100, PeerRecv: 100, PeerSent: 4000, Recv: 5292}, 0, -1292},
		{"wrapped", Stats{Sent: 10, PeerRecv: ^uint32(0) - 5, PeerSent: 0, Recv: 0}, 16, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.st.OutBytes(); got != c.out {
				t.Errorf("OutBytes = %d, want %d", got, c.out)
			}
			if got := c.st.InBytes(); got != c.in {
				t.Errorf("InBytes = %d, want %d", got, c.in)
			}
		})
	}
}
