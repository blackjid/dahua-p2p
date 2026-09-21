package dahua

import (
	"context"
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

// A DMSS capture shows the device answering three or four overlapping BINDs
// in 10-30ms each while opening seventeen realms, so realm setup is not paced
// and several negotiations may be in flight at once. The bound exists only so
// a stream that cannot be served is refused while its client is still there.
func TestNegotiationsRunConcurrentlyButBounded(t *testing.T) {
	if MaxConcurrentNegotiations < 2 {
		t.Fatalf("MaxConcurrentNegotiations = %d, want realm setup to overlap",
			MaxConcurrentNegotiations)
	}

	c := &Client{negotiateSem: make(chan struct{}, MaxConcurrentNegotiations)}
	ctx := context.Background()
	for i := 0; i < MaxConcurrentNegotiations; i++ {
		if err := c.LockNegotiate(ctx); err != nil {
			t.Fatalf("LockNegotiate %d of %d: %v", i+1, MaxConcurrentNegotiations, err)
		}
	}

	// Past the bound a caller waits rather than piling on, and gives up with
	// its context rather than wedging.
	full, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := c.LockNegotiate(full); err == nil {
		t.Fatal("LockNegotiate past the bound returned nil, want the context error")
	}

	c.UnlockNegotiate()
	if err := c.LockNegotiate(ctx); err != nil {
		t.Fatalf("LockNegotiate after a release: %v", err)
	}
}
