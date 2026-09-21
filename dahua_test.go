package dahua

import (
	"errors"
	"testing"
	"time"

	"github.com/blackjid/dahua-p2p/tunnel"
)

func TestFindAvailableSessionUsesReservations(t *testing.T) {
	key := sessionKeyFor(Config{Serial: "device", MaxRealms: 2})
	client := &Client{tunnel: &tunnel.Tunnel{}}
	session := &managedSession{client: client, refCount: 2, maxRealms: 2}
	manager := NewSessionManager()
	manager.sessions[key] = []*managedSession{session}

	if got := manager.findAvailableSession(key); got != nil {
		t.Fatal("full session was returned before its reserved realms were dialed")
	}

	session.refCount--
	if got := manager.findAvailableSession(key); got != session {
		t.Fatal("session with a free reservation was not returned")
	}
}

func TestClosedSessionManagerRejectsAcquire(t *testing.T) {
	manager := NewSessionManager()
	manager.CloseAll()

	if _, err := manager.Acquire(Config{}); !errors.Is(err, ErrSessionManagerClosed) {
		t.Fatalf("Acquire after CloseAll = %v, want ErrSessionManagerClosed", err)
	}
}

func TestFixedPortAtCapacityDoesNotOpenSecondTunnel(t *testing.T) {
	cfg := Config{Serial: "device", P2PPort: 5000, MaxRealms: 1}
	key := sessionKeyFor(cfg)
	manager := NewSessionManager()
	manager.sessions[key] = []*managedSession{{
		client:    &Client{tunnel: &tunnel.Tunnel{}},
		refCount:  1,
		maxRealms: 1,
	}}

	if _, err := manager.Acquire(cfg); !errors.Is(err, ErrFixedPortCapacity) {
		t.Fatalf("Acquire at fixed-port capacity = %v, want ErrFixedPortCapacity", err)
	}
}

func TestSessionKeyIncludesTunnelConfiguration(t *testing.T) {
	base := Config{Serial: "device", Username: "user", Password: "pass", P2PPort: 5000, MaxRealms: 4}
	want := sessionKeyFor(base)

	tests := []Config{
		{Serial: "other", Username: "user", Password: "pass", P2PPort: 5000, MaxRealms: 4},
		{Serial: "device", Username: "other", Password: "pass", P2PPort: 5000, MaxRealms: 4},
		{Serial: "device", Username: "user", Password: "other", P2PPort: 5000, MaxRealms: 4},
		{Serial: "device", Username: "user", Password: "pass", P2PPort: 5001, MaxRealms: 4},
		{Serial: "device", Username: "user", Password: "pass", P2PPort: 5000, MaxRealms: 5},
	}
	for _, cfg := range tests {
		if got := sessionKeyFor(cfg); got == want {
			t.Fatalf("configuration did not change session key: %+v", cfg)
		}
	}
}

// The device goes silent for seconds after granting a realm. Each unanswered
// BIND has to widen the gap before the next one: asking sooner does not get a
// realm, it just spends another dial budget under the negotiate lock and
// takes every queued stream down with it.
func TestSettleBacksOffWhileTheDeviceIgnoresBinds(t *testing.T) {
	// A healthy tunnel keeps the short gap, so a cold start still brings
	// eight streams up in about a second.
	if got := settleFor(0, true); got != minNegotiateSettle {
		t.Fatalf("settleFor(0, responsive) = %s, want %s", got, minNegotiateSettle)
	}
	if got := settleFor(0, false); got != NegotiateSettle {
		t.Fatalf("settleFor(0, quiet) = %s, want %s", got, NegotiateSettle)
	}

	last := time.Duration(0)
	for failures := 1; failures <= 6; failures++ {
		got := settleFor(failures, true)
		if got <= last && got != maxNegotiateSettle {
			t.Fatalf("settleFor(%d) = %s, want more than %s", failures, got, last)
		}
		if got > maxNegotiateSettle {
			t.Fatalf("settleFor(%d) = %s, want at most the %s cap", failures, got, maxNegotiateSettle)
		}
		last = got
	}

	// Ignored BINDs outrank responsiveness: the device answers heartbeats
	// perfectly well while refusing every realm, which is the whole reason
	// liveness cannot be used to pace this.
	if got := settleFor(3, true); got <= NegotiateSettle {
		t.Fatalf("settleFor(3, responsive) = %s, want more than %s", got, NegotiateSettle)
	}

	// Stays capped rather than overflowing into a negative or absurd wait.
	for _, failures := range []int{20, 64, 1000} {
		if got := settleFor(failures, true); got != maxNegotiateSettle {
			t.Fatalf("settleFor(%d) = %s, want the %s cap", failures, got, maxNegotiateSettle)
		}
	}
}

func TestRetireOnlyAfterTheSettleHasBeenCappedForAWhile(t *testing.T) {
	// Retiring rebuilds the tunnel, which costs a cloud handshake and strands
	// the session on the device. A handful of ignored BINDs is normal, so the
	// threshold has to sit well past the point the settle reaches its cap.
	capped := 0
	for failures := 1; failures <= maxBindFailures; failures++ {
		if settleFor(failures, true) == maxNegotiateSettle {
			capped++
		}
	}
	if capped < 3 {
		t.Fatalf("settle is capped for only %d of %d attempts before retiring; "+
			"the tunnel gives up before waiting is given a fair chance", capped, maxBindFailures)
	}
}
