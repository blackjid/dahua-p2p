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

// A stream queued for the negotiate lock has an RTSP client counting against
// it. Once the tunnel retires, its turn will only bring a refusal, so waiting
// it out spends the client's whole budget to learn nothing.
func TestLockNegotiateGivesUpOnRetiredTunnel(t *testing.T) {
	client := &Client{tunnel: &tunnel.Tunnel{}, negotiateSem: make(chan struct{}, 1)}
	if err := client.LockNegotiate(context.Background()); err != nil {
		t.Fatalf("uncontended lock: %v", err)
	}

	queued := make(chan error, 1)
	go func() { queued <- client.LockNegotiate(context.Background()) }()

	client.Retire()

	select {
	case err := <-queued:
		if !errors.Is(err, ErrTunnelRetired) {
			t.Fatalf("queued lock = %v, want ErrTunnelRetired", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued caller kept waiting for a tunnel that had retired")
	}
}

// A reserve tunnel is only worth holding if it is a tunnel of its own. Room
// left on a live tunnel is not a reserve: it disappears the moment that
// tunnel goes deaf to BINDs. The fixed port makes the test observable without
// a handshake, because a second tunnel cannot bind it.
func TestAcquireFreshIgnoresRoomOnLiveTunnels(t *testing.T) {
	cfg := Config{Serial: "device", P2PPort: 5000, MaxRealms: 4}
	key := sessionKeyFor(cfg)
	client := &Client{tunnel: &tunnel.Tunnel{}}
	manager := NewSessionManager()
	manager.sessions[key] = []*managedSession{{client: client, maxRealms: 4}}

	if got, err := manager.Acquire(cfg); err != nil || got != client {
		t.Fatalf("Acquire with room to spare = %v, %v; want the live tunnel", got, err)
	}
	if _, err := manager.AcquireFresh(cfg); !errors.Is(err, ErrFixedPortCapacity) {
		t.Fatalf("AcquireFresh = %v, want ErrFixedPortCapacity rather than the live tunnel", err)
	}
}

func TestClosedSessionManagerRejectsAcquireFresh(t *testing.T) {
	manager := NewSessionManager()
	manager.CloseAll()

	if _, err := manager.AcquireFresh(Config{}); !errors.Is(err, ErrSessionManagerClosed) {
		t.Fatalf("AcquireFresh after CloseAll = %v, want ErrSessionManagerClosed", err)
	}
}
