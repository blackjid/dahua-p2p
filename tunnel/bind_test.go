package tunnel

import (
	"sync"
	"testing"
)

// The device can acknowledge every byte we send while refusing to grant any
// new realm. Liveness alone therefore cannot decide whether a tunnel is still
// usable, so Dial tracks consecutive BIND exhaustion and callers rebuild on
// it. These tests pin the counter's contract.

func TestBindFailuresStartsZero(t *testing.T) {
	tn := &Tunnel{}
	if got := tn.BindFailures(); got != 0 {
		t.Fatalf("BindFailures on a fresh tunnel = %d, want 0", got)
	}
}

func TestBindFailuresResetBySuccess(t *testing.T) {
	tn := &Tunnel{}

	// Two exhausted dials put the tunnel over the rebuild threshold.
	tn.bindFailuresMu.Lock()
	tn.bindFailures = 2
	tn.bindFailuresMu.Unlock()

	if got := tn.BindFailures(); got != 2 {
		t.Fatalf("BindFailures = %d, want 2", got)
	}

	// A granted realm means the device is serving BINDs again.
	tn.bindFailuresMu.Lock()
	tn.bindFailures = 0
	tn.bindFailuresMu.Unlock()

	if got := tn.BindFailures(); got != 0 {
		t.Fatalf("BindFailures after a successful dial = %d, want 0", got)
	}
}

// Dials run concurrently and each may touch the counter, so a caller reading
// it from another goroutine must not race or deadlock.
func TestBindFailuresConcurrentReads(t *testing.T) {
	tn := &Tunnel{}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tn.BindFailures()
		}()
	}
	wg.Wait()
}

// Retiring is the middle ground between healthy and closed: the device will
// not grant new realms, but the ones it already granted are still streaming,
// so they must not be torn down.

func TestRetireRefusesNewRealms(t *testing.T) {
	tn := &Tunnel{done: make(chan struct{})}

	tn.Retire()

	if !tn.IsRetired() {
		t.Fatal("IsRetired = false after Retire")
	}
	if tn.IsClosed() {
		t.Fatal("Retire must not close the tunnel")
	}

	if _, err := tn.Dial(554); err != ErrTunnelRetired {
		t.Fatalf("Dial on a retired tunnel = %v, want ErrTunnelRetired", err)
	}
}

// A closed tunnel reports ErrTunnelClosed, not ErrTunnelRetired, so callers
// can tell "use a different tunnel" from "everything here is gone".
func TestClosedTunnelReportsClosedNotRetired(t *testing.T) {
	tn := &Tunnel{done: make(chan struct{})}
	tn.mu.Lock()
	tn.closed = true
	tn.mu.Unlock()

	if _, err := tn.Dial(554); err != ErrTunnelClosed {
		t.Fatalf("Dial on a closed tunnel = %v, want ErrTunnelClosed", err)
	}
	if !tn.IsRetired() {
		t.Fatal("IsRetired should be true for a closed tunnel")
	}
}

// Existing realms keep working after Retire; only new ones are refused.
func TestRetireLeavesExistingRealmsAlone(t *testing.T) {
	tn := &Tunnel{done: make(chan struct{}), realms: map[uint32]*Conn{}}
	c := &Conn{tunnel: tn, realmID: 7, dataCh: make(chan []byte, 1), closeCh: make(chan struct{})}
	tn.realms[7] = c

	tn.Retire()

	if tn.ActiveRealms() != 1 {
		t.Fatalf("ActiveRealms = %d, want 1", tn.ActiveRealms())
	}
	select {
	case <-c.closeCh:
		t.Fatal("existing realm was signalled closed by Retire")
	default:
	}

	// And it can still carry data.
	c.dataCh <- []byte("ok")
	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("read on retired tunnel's realm: n=%d err=%v got=%q", n, err, buf[:n])
	}
}
