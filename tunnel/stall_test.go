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

// writePayload simulates a realm writing data, which is what the device is
// expected to consume. sendPacketFor counts these; the test bypasses the
// socket and counts by hand.
func writePayload(tn *Tunnel) {
	tn.session.Send(ptcp.NewPayloadBody(1, []byte("data")))
	tn.payloadWrites.Add(1)
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
	writePayload(tn) // outstanding realm data

	if tn.outboundStalled() {
		t.Fatal("stalled on first observation of outstanding data")
	}
	if tn.lastDrainTime.IsZero() {
		t.Fatal("clock was not started")
	}
}

// This is the production failure: the device keeps sending us packets, so
// inbound liveness stays true, while its Recv counter never advances and the
// realm data we keep writing goes nowhere.
func TestOutboundStalledFiresWhenPeerRecvFrozen(t *testing.T) {
	tn := newStallTunnel()
	writePayload(tn)

	tn.outboundStalled() // start the clock
	tn.lastDrainTime = time.Now().Add(-outboundStallTimeout - time.Second)
	writePayload(tn) // still writing, still unacknowledged

	if !tn.outboundStalled() {
		t.Fatal("frozen peerRecv with outstanding data did not report a stall")
	}
}

// A tunnel nobody is writing to cannot be stalled, however long its Recv
// counter stays put: the device only advances it for data it was given, and
// heartbeats alone do not move it. Concluding otherwise closed tunnels that
// were serving live realms perfectly well.
func TestOutboundStalledIgnoresFrozenPeerRecvWithoutWrites(t *testing.T) {
	tn := newStallTunnel()
	writePayload(tn)

	tn.outboundStalled() // start the clock
	tn.lastDrainTime = time.Now().Add(-outboundStallTimeout - time.Second)
	tn.session.Send(ptcp.NewHeartbeatBody()) // only the tunnel's own traffic

	if tn.outboundStalled() {
		t.Fatal("idle tunnel reported as stalled")
	}
	if time.Since(tn.lastDrainTime) > time.Second {
		t.Fatal("clock was not restarted for the idle tunnel")
	}
}

// A device that consumes anything at all resets the clock.
func TestOutboundStalledResetsOnDrain(t *testing.T) {
	tn := newStallTunnel()
	writePayload(tn)
	writePayload(tn) // 32 bytes outstanding

	tn.outboundStalled()
	tn.lastDrainTime = time.Now().Add(-outboundStallTimeout - time.Second)

	// Device acknowledges 16 of the 32 bytes: still behind, but draining.
	tn.session.Recv(ackFrom(16))

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
	writePayload(tn)

	tn.outboundStalled()
	tn.lastDrainTime = time.Now().Add(-outboundStallTimeout - time.Second)

	tn.session.Recv(ackFrom(16)) // consumed everything we sent

	if tn.outboundStalled() {
		t.Fatal("stall reported with no outstanding data")
	}
}
