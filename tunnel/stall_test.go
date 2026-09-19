package tunnel

import (
	"testing"
	"time"

	"github.com/blackjid/dahua-p2p/ptcp"
)

// ackFrom builds a packet carrying the device's view of how much of our data
// it has consumed, which is the only thing outboundStalled cares about.
func ackFrom(peerRecv uint32) *ptcp.Packet {
	return ptcp.NewPacket(&ptcp.Header{Recv: peerRecv}, ptcp.NewEmptyBody())
}

func newStallTunnel() *Tunnel {
	return &Tunnel{session: ptcp.NewSession()}
}

// A tunnel with nothing outstanding cannot be stalled.
func TestOutboundStalledIdleTunnel(t *testing.T) {
	tn := newStallTunnel()
	if tn.outboundStalled() {
		t.Fatal("idle tunnel reported as stalled")
	}
}

// The first observation of undrained data starts the clock rather than
// firing immediately, so a single slow round never tears a tunnel down.
func TestOutboundStalledFirstObservationStartsClock(t *testing.T) {
	tn := newStallTunnel()
	tn.session.Send(ptcp.NewHeartbeatBody()) // 12 bytes outstanding

	if tn.outboundStalled() {
		t.Fatal("stalled on first observation of outstanding data")
	}
	if tn.lastDrainTime.IsZero() {
		t.Fatal("clock was not started")
	}
}

// This is the production failure: the device keeps sending us packets, so
// inbound liveness stays true, while its Recv counter never advances.
func TestOutboundStalledFiresWhenPeerRecvFrozen(t *testing.T) {
	tn := newStallTunnel()
	tn.session.Send(ptcp.NewHeartbeatBody())

	tn.outboundStalled() // start the clock
	tn.lastDrainTime = time.Now().Add(-outboundStallTimeout - time.Second)

	if !tn.outboundStalled() {
		t.Fatal("frozen peerRecv with outstanding data did not report a stall")
	}
}

// A device that consumes anything at all resets the clock.
func TestOutboundStalledResetsOnDrain(t *testing.T) {
	tn := newStallTunnel()
	tn.session.Send(ptcp.NewHeartbeatBody())
	tn.session.Send(ptcp.NewHeartbeatBody()) // 24 bytes outstanding

	tn.outboundStalled()
	tn.lastDrainTime = time.Now().Add(-outboundStallTimeout - time.Second)

	// Device acknowledges 12 of the 24 bytes: still behind, but draining.
	tn.session.Recv(ackFrom(12))

	if tn.outboundStalled() {
		t.Fatal("stall reported although the device consumed data")
	}
	if time.Since(tn.lastDrainTime) > time.Second {
		t.Fatal("clock was not reset on drain")
	}
}

// Fully caught up clears the condition even if the clock had been running.
func TestOutboundStalledClearsWhenFullyAcked(t *testing.T) {
	tn := newStallTunnel()
	tn.session.Send(ptcp.NewHeartbeatBody())

	tn.outboundStalled()
	tn.lastDrainTime = time.Now().Add(-outboundStallTimeout - time.Second)

	tn.session.Recv(ackFrom(12)) // consumed everything we sent

	if tn.outboundStalled() {
		t.Fatal("stall reported with no outstanding data")
	}
}
