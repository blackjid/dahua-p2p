package dh

import (
	"net"
	"strings"
	"testing"
)

func TestParseResponseCRLF(t *testing.T) {
	raw := "DHP2P/1.0 200 OK\r\n" +
		"CSeq: 1\r\n" +
		"Content-Type: text/xml\r\n" +
		"\r\n" +
		"<body><US>p2p.example.com:443</US></body>"
	r, err := ParseResponse(raw)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if r.Code != 200 {
		t.Fatalf("code: got %d, want 200", r.Code)
	}
	if r.Status != "OK" {
		t.Fatalf("status: got %q, want OK", r.Status)
	}
	if got := r.Body["body/US"]; got != "p2p.example.com:443" {
		t.Fatalf("body/US: got %q", got)
	}
	if got := r.Headers["CSeq"]; got != "1" {
		t.Fatalf("CSeq: got %q", got)
	}
}

func TestParseResponseLFOnly(t *testing.T) {
	// Some servers emit bare LFs. ParseResponse should accept them.
	raw := "DHP2P/1.0 200 OK\n" +
		"CSeq: 2\n" +
		"\n" +
		"<body><Token>abcdef</Token></body>"
	r, err := ParseResponse(raw)
	if err != nil {
		t.Fatalf("ParseResponse(LF): %v", err)
	}
	if r.Code != 200 {
		t.Fatalf("code: got %d, want 200", r.Code)
	}
	if got := r.Body["body/Token"]; got != "abcdef" {
		t.Fatalf("body/Token: got %q", got)
	}
}

func TestParseResponseBadFormat(t *testing.T) {
	if _, err := ParseResponse("not a response"); err != ErrInvalidResponse {
		t.Fatalf("expected ErrInvalidResponse, got %v", err)
	}
}

func TestParseResponseShortStatusLine(t *testing.T) {
	raw := "BAD\r\n\r\n"
	if _, err := ParseResponse(raw); err != ErrInvalidResponse {
		t.Fatalf("expected ErrInvalidResponse, got %v", err)
	}
}

func TestFormatIdentifyFixedWidth(t *testing.T) {
	// All bytes must render as exactly two hex digits so the device sees
	// consistent field widths.
	got := formatIdentify([]byte{0x00, 0x0f, 0xff, 0x05})
	want := "00 0f ff 05"
	if got != want {
		t.Fatalf("formatIdentify: got %q, want %q", got, want)
	}

	// Every field between spaces must be exactly 2 chars.
	for _, part := range strings.Split(got, " ") {
		if len(part) != 2 {
			t.Fatalf("non-2-char part %q in %q", part, got)
		}
	}
}

func TestIPToBytes(t *testing.T) {
	got, err := ipToBytes("192.168.1.10:554")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 {
		t.Fatalf("length: got %d, want 6", len(got))
	}
	// Output is the inverted bytes: port (big-endian) then IP.
	// 554 = 0x022A → before invert: 0x02, 0x2A
	// Inverted: ~0x02, ~0x2A, ~192, ~168, ~1, ~10
	want := []byte{^byte(0x02), ^byte(0x2A), ^byte(192), ^byte(168), ^byte(1), ^byte(10)}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d: got %#x, want %#x", i, got[i], want[i])
		}
	}
}

func TestIPToBytesBadInput(t *testing.T) {
	for _, address := range []string{"no-colon", "not-an-ip:554", "192.168.1.10:0", "192.168.1.10:99999"} {
		if _, err := ipToBytes(address); err != ErrInvalidResponse {
			t.Fatalf("ipToBytes(%q) error = %v, want ErrInvalidResponse", address, err)
		}
	}
}

func TestSameUDPAddr(t *testing.T) {
	a, err := net.ResolveUDPAddr("udp", "192.0.2.1:8800")
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.ResolveUDPAddr("udp", "192.0.2.1:8800")
	if err != nil {
		t.Fatal(err)
	}
	other, err := net.ResolveUDPAddr("udp", "192.0.2.2:8800")
	if err != nil {
		t.Fatal(err)
	}
	if !sameUDPAddr(a, b) || sameUDPAddr(a, other) || sameUDPAddr(a, nil) {
		t.Fatal("sameUDPAddr did not enforce exact peer identity")
	}
}

func TestRandomBytesLength(t *testing.T) {
	for _, n := range []int{1, 4, 8, 16, 64} {
		b := RandomBytes(n)
		if len(b) != n {
			t.Fatalf("RandomBytes(%d) returned %d bytes", n, len(b))
		}
	}
}

func TestRandomBytesNotConstant(t *testing.T) {
	// crypto/rand must produce variability; same-length successive calls
	// should not be equal.
	a := RandomBytes(16)
	b := RandomBytes(16)
	equal := true
	for i := range a {
		if a[i] != b[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Fatalf("two successive RandomBytes(16) were identical: %x", a)
	}
}
