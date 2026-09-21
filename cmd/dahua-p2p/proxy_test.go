package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/blackjid/dahua-p2p"
)

func TestSuperviseRestartsBridgeCycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	wantErr := errors.New("tunnel failed")

	err := supervise(ctx, backoff{}, func(context.Context) error {
		calls++
		if calls == 2 {
			cancel()
			return nil
		}
		return wantErr
	})
	if err != nil {
		t.Fatalf("supervise() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("run cycle calls = %d, want 2", calls)
	}
}

func TestNextBackoff(t *testing.T) {
	tests := []struct {
		name    string
		current time.Duration
		max     time.Duration
		want    time.Duration
	}{
		{name: "double", current: time.Second, max: 30 * time.Second, want: 2 * time.Second},
		{name: "cap", current: 16 * time.Second, max: 30 * time.Second, want: 30 * time.Second},
		{name: "stay capped", current: 30 * time.Second, max: 30 * time.Second, want: 30 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextBackoff(tt.current, tt.max); got != tt.want {
				t.Errorf("nextBackoff(%s, %s) = %s, want %s", tt.current, tt.max, got, tt.want)
			}
		})
	}
}

func TestCopyRTSPMessage(t *testing.T) {
	tests := []struct {
		name    string
		message string
		wantErr bool
	}{
		{
			name:    "request without body",
			message: "OPTIONS rtsp://bridge/ RTSP/1.0\r\nCSeq: 1\r\n\r\n",
		},
		{
			name:    "response with body",
			message: "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 4\r\n\r\ntest",
		},
		{
			name:    "invalid content length",
			message: "RTSP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "duplicate content length",
			message: "RTSP/1.0 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "body too large",
			message: "RTSP/1.0 200 OK\r\nContent-Length: 1048577\r\n\r\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dst bytes.Buffer
			_, err := copyRTSPMessage(&dst, bufio.NewReader(strings.NewReader(tt.message)))
			if (err != nil) != tt.wantErr {
				t.Fatalf("copyRTSPMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && dst.String() != tt.message {
				t.Fatalf("copied message = %q, want %q", dst.String(), tt.message)
			}
		})
	}
}

func TestProxyRTSPTransitionsToInterleavedData(t *testing.T) {
	upstreamClient, upstreamBridge := net.Pipe()
	deviceBridge, deviceServer := net.Pipe()
	defer upstreamClient.Close()
	defer upstreamBridge.Close()
	defer deviceBridge.Close()
	defer deviceServer.Close()

	deadline := time.Now().Add(2 * time.Second)
	for _, conn := range []net.Conn{upstreamClient, upstreamBridge, deviceBridge, deviceServer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}

	firstRequest := "OPTIONS rtsp://bridge/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
	finished := make(chan struct{}, 1)
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyRTSP(
			upstreamBridge,
			bufio.NewReader(upstreamBridge),
			deviceBridge,
			[]byte(firstRequest),
			"OPTIONS rtsp://bridge/ RTSP/1.0",
			func() { finished <- struct{}{} },
		)
	}()

	deviceReader := bufio.NewReader(deviceServer)
	var got bytes.Buffer
	if _, err := copyRTSPMessage(&got, deviceReader); err != nil {
		t.Fatal(err)
	}
	if got.String() != firstRequest {
		t.Fatalf("first request = %q, want %q", got.String(), firstRequest)
	}
	writeErr := asyncWrite(deviceServer, "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")

	upstreamReader := bufio.NewReader(upstreamClient)
	got.Reset()
	if _, err := copyRTSPMessage(&got, upstreamReader); err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	play := "PLAY rtsp://bridge/ RTSP/1.0\r\nCSeq: 2\r\n\r\n"
	writeErr = asyncWrite(upstreamClient, play)
	got.Reset()
	if _, err := copyRTSPMessage(&got, deviceReader); err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if got.String() != play {
		t.Fatalf("PLAY request = %q, want %q", got.String(), play)
	}
	writeErr = asyncWrite(deviceServer, "RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n$raw")
	got.Reset()
	if _, err := copyRTSPMessage(&got, upstreamReader); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 4)
	if _, err := io.ReadFull(upstreamReader, raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) != "$raw" {
		t.Fatalf("interleaved bytes = %q, want %q", raw, "$raw")
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}

	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("negotiation callback was not called")
	}
	closeConn(upstreamClient)
	closeConn(deviceServer)
	select {
	case <-proxyErr:
	case <-time.After(time.Second):
		t.Fatal("proxyRTSP did not stop after its connections closed")
	}
}

func asyncWrite(dst io.Writer, value string) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(dst, value)
		done <- err
	}()
	return done
}

func TestNegotiationFinished(t *testing.T) {
	tests := []struct {
		request  string
		response string
		want     bool
	}{
		{"PLAY rtsp://bridge/ RTSP/1.0", "RTSP/1.0 200 OK", true},
		{"RECORD rtsp://bridge/ RTSP/1.0", "RTSP/1.0 201 Created", true},
		{"PLAY rtsp://bridge/ RTSP/1.0", "RTSP/1.0 401 Unauthorized", false},
		{"SETUP rtsp://bridge/track1 RTSP/1.0", "RTSP/1.0 200 OK", false},
	}
	for _, tt := range tests {
		if got := negotiationFinished(tt.request, tt.response); got != tt.want {
			t.Errorf("negotiationFinished(%q, %q) = %v, want %v", tt.request, tt.response, got, tt.want)
		}
	}
}

func TestValidRTSPRequest(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"OPTIONS rtsp://bridge/ RTSP/1.0", true},
		{"DESCRIBE /stream RTSP/1.0", true},
		{"RTSP/1.0 200 OK", false},
		{"GET / HTTP/1.1", false},
		{"OPTIONS RTSP/1.0", false},
	}
	for _, tt := range tests {
		if got := validRTSPRequest(tt.line); got != tt.want {
			t.Errorf("validRTSPRequest(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestClientConfig(t *testing.T) {
	b := &bridge{config: config{
		serial:    "device",
		username:  "user",
		password:  "pass",
		p2pPort:   5000,
		maxRealms: 8,
		timeout:   10 * time.Second,
	}}

	cfg := b.clientConfig()
	if cfg.MaxRealms != 8 {
		t.Fatalf("MaxRealms = %d, want 8", cfg.MaxRealms)
	}
	if cfg.Serial != b.config.serial || cfg.Username != b.config.username || cfg.Password != b.config.password {
		t.Fatal("clientConfig did not preserve device credentials")
	}
}

func TestTallyGroupsRefusalsByReason(t *testing.T) {
	var tl tally

	// The first refusal reports immediately, so a lone failure is never
	// silently swallowed.
	if got := tl.add("realm capacity", time.Minute); got == nil || got["realm capacity"] != 1 {
		t.Fatalf("first add() = %v, want the realm capacity count", got)
	}

	// Everything inside the interval accumulates instead of printing.
	for i := 0; i < 3; i++ {
		if got := tl.add("negotiate lock busy", time.Minute); got != nil {
			t.Fatalf("add() reported %v inside the interval, want nil", got)
		}
	}
	if got := tl.add("realm capacity", time.Minute); got != nil {
		t.Fatalf("add() reported %v inside the interval, want nil", got)
	}

	// The next report carries every reason seen since the last one, so no
	// refusal is lost, only delayed.
	got := tl.add("tunnel retired", 0)
	want := map[string]int{"negotiate lock busy": 3, "realm capacity": 1, "tunnel retired": 1}
	if len(got) != len(want) {
		t.Fatalf("add() = %v, want %v", got, want)
	}
	for reason, n := range want {
		if got[reason] != n {
			t.Fatalf("add()[%q] = %d, want %d (full: %v)", reason, got[reason], n, got)
		}
	}

	// Counts reset after a report rather than accumulating forever.
	if got := tl.add("realm capacity", 0); len(got) != 1 || got["realm capacity"] != 1 {
		t.Fatalf("add() after a report = %v, want a fresh count", got)
	}
}

func TestRefusalReasonNamesSentinels(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: %w", errAdmitTimeout, context.DeadlineExceeded), "negotiate lock busy"},
		{fmt.Errorf("%w: %d/%d", errRealmCapacity, 8, 8), "realm capacity"},
		{fmt.Errorf("dial P2P realm: %w", dahua.ErrDialTimeout), "device refusing realms"},
		{fmt.Errorf("dial P2P realm: %w", dahua.ErrTunnelRetired), "tunnel retired"},
		{fmt.Errorf("dial P2P realm: %w", dahua.ErrTunnelClosed), "tunnel closed"},
	}
	for _, tt := range tests {
		if got := refusalReason(tt.err); got != tt.want {
			t.Errorf("refusalReason(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}

	// An unclassified failure still has to say what went wrong.
	if got := refusalReason(errors.New("boom")); !strings.Contains(got, "boom") {
		t.Errorf("refusalReason of an unknown error = %q, want it to carry the message", got)
	}
}

// A tunnel that died without reaching the device leaves the device holding the
// session and its realms, because the teardown never arrived. Rebuilding
// straight away stacks a second session on the first, which is how the device
// ends up refusing every BIND while we believe we hold no realms.
func TestBackoffWaitsOutTheDeviceAfterLosingContact(t *testing.T) {
	b := backoff{min: time.Second, max: time.Hour, lostContact: 30 * time.Second}

	// However short the current delay, losing contact jumps to the floor.
	if got := b.next(b.min, errLostContact); got != b.lostContact {
		t.Fatalf("next(%s, lost contact) = %s, want %s", b.min, got, b.lostContact)
	}
	// Wrapped the way runBridge returns it.
	wrapped := fmt.Errorf("bridge cycle: %w", errLostContact)
	if got := b.next(b.min, wrapped); got != b.lostContact {
		t.Fatalf("next(%s, wrapped lost contact) = %s, want %s", b.min, got, b.lostContact)
	}
	// Losing contact repeatedly keeps backing off rather than sticking.
	if got := b.next(b.lostContact, errLostContact); got <= b.lostContact {
		t.Fatalf("next(%s, lost contact) = %s, want more than %s", b.lostContact, got, b.lostContact)
	}

	// A healthy session that simply ended still retries promptly: waiting
	// there would cost a reconnecting dashboard its streams for no reason.
	if got := b.next(b.lostContact, nil); got != b.min {
		t.Fatalf("next(%s, nil) = %s, want %s", b.lostContact, got, b.min)
	}

	// An ordinary failure backs off, but is not held to the lost-contact floor.
	if got := b.next(b.min, errors.New("handshake failed")); got != 2*time.Second {
		t.Fatalf("next(%s, failure) = %s, want 2s", b.min, got)
	}
}

func TestLostContactFloorExceedsTheOrdinaryDelay(t *testing.T) {
	// A collapsed tunnel must not be rebuilt on the prompt-retry path, or it
	// races the session the device has not expired yet.
	if lostContactDelay <= reconnectMinDelay {
		t.Fatalf("lostContactDelay %s must exceed reconnectMinDelay %s",
			lostContactDelay, reconnectMinDelay)
	}
}

// Realm setup runs several negotiations at once, so capacity has to account
// for the BINDs still in flight. Going by granted realms alone would let every
// concurrent admission see the same free slot.
func TestRealmSlotsAccountForBindsInFlight(t *testing.T) {
	b := &bridge{config: config{maxRealms: 3}}

	// Three claims against an empty tunnel fit; the fourth does not, even
	// though not one realm has been granted yet.
	for i := 0; i < 3; i++ {
		if _, ok := b.claimRealmSlot(0); !ok {
			t.Fatalf("claim %d of 3 refused on an empty tunnel", i+1)
		}
	}
	if n, ok := b.claimRealmSlot(0); ok {
		t.Fatalf("claim 4 of 3 admitted at count %d, want a refusal", n)
	}

	// A refused claim is given back rather than leaking capacity.
	b.releaseRealmSlot()
	if _, ok := b.claimRealmSlot(0); !ok {
		t.Fatal("claim refused after a slot was released")
	}

	// Granted realms count too: two in flight against one already granted
	// fills the tunnel.
	b = &bridge{config: config{maxRealms: 3}}
	if _, ok := b.claimRealmSlot(1); !ok {
		t.Fatal("first claim against one granted realm refused")
	}
	if _, ok := b.claimRealmSlot(1); !ok {
		t.Fatal("second claim against one granted realm refused")
	}
	if n, ok := b.claimRealmSlot(1); ok {
		t.Fatalf("third claim against one granted realm admitted at count %d", n)
	}
}
