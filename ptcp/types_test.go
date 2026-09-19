package ptcp

import (
	"bytes"
	"testing"
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

func TestSessionPIDUniqueness(t *testing.T) {
	// Regression for commit e35d592: every non-SYNC packet must get a unique
	// PID, or the device deduplicates and drops our ACKs.
	s := NewSession()
	seen := map[uint32]bool{}
	for i := 0; i < 10; i++ {
		p := s.Send(NewEmptyBody())
		if seen[p.Header.PID] {
			t.Fatalf("duplicate PID %#x on packet %d", p.Header.PID, i)
		}
		seen[p.Header.PID] = true
	}
}

func TestSessionLMIDMonotonic(t *testing.T) {
	s := NewSession()
	prev := uint32(0)
	for i := 0; i < 5; i++ {
		p := s.Send(NewHeartbeatBody())
		if i > 0 && p.Header.LMID <= prev {
			t.Fatalf("LMID not monotonic: packet %d has LMID %d, prev %d", i, p.Header.LMID, prev)
		}
		prev = p.Header.LMID
	}
}

func TestSessionSyncHasFixedPID(t *testing.T) {
	s := NewSession()
	p := s.Send(NewSyncBody())
	if p.Header.PID != 0x0002FFFF {
		t.Fatalf("SYNC PID: got %#x, want 0x0002FFFF", p.Header.PID)
	}
}

// TestSessionPIDNoUnderflow guards the 16-bit mask on the PID counter. The
// device dedupes on PID and the high half is always zero in observed traffic;
// without the mask the subtraction underflows after 65536 packets (~20min of
// streaming) and starts setting those bits.
func TestSessionPIDNoUnderflow(t *testing.T) {
	s := NewSession()
	for i := 0; i < 70000; i++ {
		pkt := s.Send(NewHeartbeatBody())
		if pkt.Header.PID > 0x0000FFFF {
			t.Fatalf("packet %d: PID 0x%08X exceeds 16 bits", i, pkt.Header.PID)
		}
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
