// Package tunnel provides TCP tunneling over PTCP protocol
package tunnel

import (
	"errors"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blackjid/dahua-p2p/dh"
	"github.com/blackjid/dahua-p2p/ptcp"
)

// nopLog is the zero value for the Trace/Error hooks, so call sites never
// need a nil check.
func nopLog(string, ...any) {}

// Errors
var (
	ErrTunnelClosed  = errors.New("tunnel is closed")
	ErrTunnelRetired = errors.New("tunnel retired: no new realms")
	ErrDialTimeout   = errors.New("dial timeout: device not responding")
)

// Tunnel health thresholds
const (
	maxConsecutiveReadErrors = 10
	maxConsecutiveSendErrors = 5
	maxMissedHeartbeats      = 24 // 2 minutes; RTSP read timeout provides faster detection
)

// Tunnel represents a P2P tunnel to a Dahua device
type Tunnel struct {
	mu       sync.RWMutex
	client   *dh.UDPClient
	session  *ptcp.Session
	rtspPort uint32
	closed   bool
	// retired tunnels refuse new realms but keep serving the ones they
	// already have, so a device that stops granting BINDs does not take
	// working streams down with it.
	retired bool
	// retiredCh is closed once the tunnel stops granting realms, by Retire
	// or by Close. Callers queued for something it can no longer give them
	// wait on this rather than on the queue. Created on first use, like
	// sendPermit, so a zero-value Tunnel behaves like a live one.
	retiredCh  chan struct{}
	retiredMu  sync.Mutex
	retireOnce sync.Once
	done       chan struct{} // closed on shutdown; used by reader and heartbeat

	// sendPermit serializes outbound packets so that session.Send (which
	// assigns LMID/PID) and client.Send (UDP write) happen atomically. A
	// channel is used instead of a mutex so a queued Conn.Write can be
	// interrupted by its deadline or Close.
	sendOnce   sync.Once
	sendPermit chan struct{}
	// writeDeadlineMu lets SetWriteDeadline update the socket when this realm
	// currently owns the serialized UDP write.
	writeDeadlineMu sync.Mutex
	activeWriter    *Conn

	// Realms map connection IDs to their Conn. Realm IDs are random uint32
	// values, matching DMSS app behavior.
	realms   map[uint32]*Conn
	realmsMu sync.RWMutex

	// For connection establishment
	connCh   map[uint32]chan bool
	connChMu sync.Mutex
	dialMu   sync.Mutex // serializes Dial calls so BINDs don't overlap

	// Heartbeat
	heartbeatTicker *time.Ticker

	// Health tracking
	missedHeartbeats   int
	missedHeartbeatsMu sync.Mutex

	// consecutiveReadErrs is touched only by the reader goroutine.
	consecutiveReadErrs int

	lastAckTime   time.Time
	lastAckTimeMu sync.Mutex

	// Outbound drain tracking. The device can keep sending us packets while
	// it has stopped consuming ours; inbound liveness therefore says nothing
	// about whether the tunnel still works. peerRecv advancing does.
	lastDrain     uint32
	lastDrainTime time.Time
	// drainPayload is payloadWrites as of the last drain, so the stall check
	// can tell a device that consumes nothing from one that has simply been
	// asked to consume nothing.
	drainPayload uint64

	// payloadWrites counts packets realms have written, as distinct from the
	// heartbeats the tunnel emits on its own.
	payloadWrites atomic.Uint64

	// ACK coalescing: batch multiple received packets into a single ACK.
	// ackMu also guards consecutiveSendErrs, which only flushACK touches.
	ackPending          bool
	ackTimer            *time.Timer
	consecutiveSendErrs int
	ackMu               sync.Mutex

	trace  func(format string, v ...any)
	errorf func(format string, v ...any)

	// onClose is called once when the tunnel closes (heartbeat timeout,
	// errors, explicit Close). Guarded by mu: it is installed after New has
	// already started the reader and heartbeat goroutines, either of which
	// can close the tunnel concurrently.
	onClose func()
}

// Config contains tunnel configuration
type Config struct {
	Serial   string
	Username string
	Password string
	Timeout  time.Duration
	P2PPort  int // Fixed local UDP port for P2P (0 = random)

	// Trace and Error report protocol activity. This package owns no logger,
	// so the caller wires them to one; while nil, nothing is formatted.
	Trace func(format string, v ...any)
	Error func(format string, v ...any)
}

// New creates a new tunnel with the given configuration
func New(cfg Config) (*Tunnel, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	result, err := dh.Handshake(dh.HandshakeOptions{
		Serial:         cfg.Serial,
		Timeout:        cfg.Timeout,
		DeviceUsername: cfg.Username,
		DevicePassword: cfg.Password,
		P2PPort:        cfg.P2PPort,
		Trace:          cfg.Trace,
	})
	if err != nil {
		return nil, err
	}

	t := &Tunnel{
		client:   result.Client,
		session:  result.Session,
		rtspPort: result.RTSPPort,
		done:     make(chan struct{}),
		realms:   make(map[uint32]*Conn),
		connCh:   make(map[uint32]chan bool),
		trace:    nopLog,
		errorf:   nopLog,
	}
	if cfg.Trace != nil {
		t.trace = cfg.Trace
	}
	if cfg.Error != nil {
		t.errorf = cfg.Error
	}

	// Start reader goroutine
	go t.reader()

	// Start heartbeat
	t.startHeartbeat()

	// Start loss reporter
	go t.reportLoss()

	return t, nil
}

// lossReportInterval is how often the tunnel reports both endpoints' view of
// the byte counters, so persistent divergence (i.e. packet loss) is visible.
const lossReportInterval = 30 * time.Second

// Stats returns the PTCP session counters for this tunnel.
func (t *Tunnel) Stats() ptcp.Stats { return t.session.Stats() }

// RTSPPort returns the device's advertised RTSP port.
func (t *Tunnel) RTSPPort() uint32 { return t.rtspPort }

// reportLoss periodically logs our counters next to the device's view of
// them. In a healthy tunnel the out/in gaps oscillate around a small
// in-flight value; a gap that climbs monotonically across reports is loss,
// and the direction says which way.
//
// An idle tunnel is reported too. Every health check the tunnel makes reads
// these counters, and the decision they drive -- whether a tunnel with no
// streams on it is still worth keeping -- is invisible without them.
func (t *Tunnel) reportLoss() {
	ticker := time.NewTicker(lossReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			st := t.session.Stats()
			t.missedHeartbeatsMu.Lock()
			missed := t.missedHeartbeats
			t.missedHeartbeatsMu.Unlock()
			t.trace("ptcp counters sent=%d peer_recv=%d out_unacked=%d out_msgs=%d recv=%d peer_sent=%d in_skew=%d missed_hb=%d realms=%d",
				st.Sent, st.PeerRecv, st.OutBytes(), st.OutMsgs(),
				st.Recv, st.PeerSent, st.InBytes(), missed, t.ActiveRealms())
		}
	}
}

// sendPacket serializes session-state update and UDP write under sendMu so
// packets always arrive at the device in the order their LMID/PID were assigned.
func (t *Tunnel) sendPacket(body *ptcp.Body) error {
	return t.sendPacketFor(body, nil)
}

func (t *Tunnel) sendPacketFor(body *ptcp.Body, writer *Conn) error {
	if err := t.acquireSendPermit(writer); err != nil {
		return err
	}
	defer func() { t.sendPermit <- struct{}{} }()

	var deadline time.Time
	if writer != nil {
		t.writeDeadlineMu.Lock()
		writer.mu.Lock()
		closed := writer.closed
		deadline = writer.writeDeadline
		writer.mu.Unlock()
		if closed {
			t.writeDeadlineMu.Unlock()
			return ErrTunnelClosed
		}
		if !deadline.IsZero() && time.Until(deadline) <= 0 {
			t.writeDeadlineMu.Unlock()
			return os.ErrDeadlineExceeded
		}

		t.activeWriter = writer
		if err := t.client.SetWriteDeadline(deadline); err != nil {
			t.activeWriter = nil
			t.writeDeadlineMu.Unlock()
			return err
		}
		t.writeDeadlineMu.Unlock()
		defer func() {
			t.writeDeadlineMu.Lock()
			t.activeWriter = nil
			_ = t.client.SetWriteDeadline(time.Time{})
			t.writeDeadlineMu.Unlock()
		}()
	}

	if body.Type == ptcp.BodyTypePayload {
		t.payloadWrites.Add(1)
	}

	packet := t.session.Send(body)
	return t.client.Send(packet.Serialize())
}

func (t *Tunnel) acquireSendPermit(writer *Conn) error {
	t.sendOnce.Do(func() {
		t.sendPermit = make(chan struct{}, 1)
		t.sendPermit <- struct{}{}
	})

	if writer == nil {
		<-t.sendPermit
		return nil
	}

	for {
		writer.mu.Lock()
		if writer.writeDeadlineChanged == nil {
			writer.writeDeadlineChanged = make(chan struct{})
		}
		closed := writer.closed
		deadline := writer.writeDeadline
		deadlineChanged := writer.writeDeadlineChanged
		writer.mu.Unlock()

		if closed {
			return ErrTunnelClosed
		}

		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}

		select {
		case <-writer.closeCh:
			if timer != nil {
				timer.Stop()
			}
			return ErrTunnelClosed
		case <-t.done:
			if timer != nil {
				timer.Stop()
			}
			return ErrTunnelClosed
		case <-deadlineChanged:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timeout:
			return os.ErrDeadlineExceeded
		case <-t.sendPermit:
			if timer != nil {
				timer.Stop()
			}
			select {
			case <-t.done:
				t.sendPermit <- struct{}{}
				return ErrTunnelClosed
			default:
				return nil
			}
		}
	}
}

func (t *Tunnel) updateWriteDeadline(writer *Conn, deadline time.Time) error {
	t.writeDeadlineMu.Lock()
	defer t.writeDeadlineMu.Unlock()
	writer.mu.Lock()
	closed := writer.closed
	writer.mu.Unlock()
	if closed {
		return ErrTunnelClosed
	}
	if t.activeWriter == writer {
		return t.client.SetWriteDeadline(deadline)
	}
	return nil
}

func (t *Tunnel) interruptWrite(writer *Conn) {
	t.writeDeadlineMu.Lock()
	if t.activeWriter == writer {
		_ = t.client.SetWriteDeadline(time.Now())
	}
	t.writeDeadlineMu.Unlock()
}

// Close closes the tunnel, sending DISC for all active realms first.
func (t *Tunnel) Close() error {
	t.mu.Lock()

	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	close(t.done)
	t.signalRetired()

	if t.heartbeatTicker != nil {
		t.heartbeatTicker.Stop()
	}

	t.ackMu.Lock()
	if t.ackTimer != nil {
		t.ackTimer.Stop()
	}
	t.ackMu.Unlock()

	// Collect active realms and swap the map to nil so concurrent Dial calls
	// hit ErrTunnelClosed instead of writing to the map we're tearing down.
	t.realmsMu.Lock()
	realms := t.realms
	t.realms = nil
	t.realmsMu.Unlock()

	// Wake every realm first. A realm can own sendPermit in a blocked write;
	// waiting to send another realm's DISC before signaling it would deadlock
	// shutdown.
	for _, conn := range realms {
		conn.signalClosed()
	}
	for id := range realms {
		_ = t.sendPacket(ptcp.NewStatusBody(id, ptcp.StatusDisconnect))
	}

	err := t.client.Close()
	onClose := t.onClose
	t.mu.Unlock()

	if onClose != nil {
		onClose()
	}
	return err
}

// IsClosed returns whether the tunnel is closed
func (t *Tunnel) IsClosed() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.closed
}

// Retire stops the tunnel accepting new realms without disturbing the ones it
// is already serving. Use it when the device refuses to grant realms but the
// data path is still healthy: closing outright would tear down every sibling
// stream, whereas retiring lets them run to their natural end while the next
// stream opens a fresh tunnel.
func (t *Tunnel) Retire() {
	t.mu.Lock()
	t.retired = true
	t.mu.Unlock()
	t.signalRetired()
}

// signalRetired releases everyone waiting for something this tunnel will
// never grant. Safe to call repeatedly and from both Retire and Close.
func (t *Tunnel) signalRetired() {
	ch := t.retiredChan()
	t.retireOnce.Do(func() { close(ch) })
}

// Retired returns a channel closed when the tunnel stops granting new realms,
// so a caller can abandon a queue instead of waiting out its turn for one.
func (t *Tunnel) Retired() <-chan struct{} { return t.retiredChan() }

func (t *Tunnel) retiredChan() chan struct{} {
	t.retiredMu.Lock()
	defer t.retiredMu.Unlock()
	if t.retiredCh == nil {
		t.retiredCh = make(chan struct{})
	}
	return t.retiredCh
}

// IsRetired reports whether the tunnel has stopped accepting new realms.
func (t *Tunnel) IsRetired() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.retired || t.closed
}

// SetOnClose installs the tunnel-closed callback. Safe to call after New,
// which has already started the reader and heartbeat goroutines.
func (t *Tunnel) SetOnClose(fn func()) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		fn()
		return
	}
	t.onClose = fn
	t.mu.Unlock()
}

// startHeartbeat starts the heartbeat ticker
func (t *Tunnel) startHeartbeat() {
	t.heartbeatTicker = time.NewTicker(5 * time.Second)

	go func() {
		for {
			select {
			case <-t.heartbeatTicker.C:
				t.sendHeartbeat()
			case <-t.done:
				return
			}
		}
	}()
}

// outboundStallTimeout is how long the device may go without consuming any of
// our bytes before the tunnel is considered dead. Heartbeats are sent every
// 5s and each advances the device's Recv by 12, so a healthy tunnel never
// stalls for more than one round; four rounds is unambiguous.
const outboundStallTimeout = 20 * time.Second

// outboundStalled reports whether the device has stopped consuming our data.
// This is the failure that precedes a tunnel refusing every BIND: it keeps
// answering with packets of its own, so inbound liveness stays true, while
// its Recv counter freezes and nothing we send is taken.
func (t *Tunnel) outboundStalled() bool {
	st := t.session.Stats()
	written := t.payloadWrites.Load()

	// Nothing outstanding means nothing to be stalled on.
	if st.OutBytes() <= 0 {
		t.markDrained(st.PeerRecv, written)
		return false
	}

	if st.PeerRecv != t.lastDrain {
		t.markDrained(st.PeerRecv, written)
		return false
	}

	// First observation of a non-draining tunnel starts the clock.
	if t.lastDrainTime.IsZero() {
		t.markDrained(t.lastDrain, written)
		return false
	}

	// A tunnel nobody has written to proves nothing. The device stops
	// advancing its Recv counter over an idle tunnel even while it is
	// perfectly willing to serve the next BIND -- observed closing a tunnel
	// with two live realms thirty seconds after its last RTSP exchange. Only
	// realm data the device declines to take is evidence of a stall; total
	// silence is the missed-heartbeat timeout's business, and it allows six
	// times as long before concluding anything.
	if written == t.drainPayload {
		t.lastDrainTime = time.Now()
		return false
	}

	return time.Since(t.lastDrainTime) > outboundStallTimeout
}

// markDrained restarts the stall clock. Must be called from the heartbeat
// goroutine, which is the only caller of outboundStalled.
func (t *Tunnel) markDrained(peerRecv uint32, written uint64) {
	t.lastDrain = peerRecv
	t.lastDrainTime = time.Now()
	t.drainPayload = written
}

// sendHeartbeat sends a heartbeat packet and tracks missed responses.
func (t *Tunnel) sendHeartbeat() {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return
	}
	t.mu.RUnlock()

	t.missedHeartbeatsMu.Lock()
	t.missedHeartbeats++
	missed := t.missedHeartbeats
	t.missedHeartbeatsMu.Unlock()

	if missed > maxMissedHeartbeats {
		t.errorf("too many missed heartbeats (%d), closing tunnel", missed)
		t.Close()
		return
	}

	if err := t.sendPacket(ptcp.NewHeartbeatBody()); err != nil {
		t.errorf("heartbeat send failed: %s", err)
	}

	// Checked after sending so the freshly queued heartbeat counts toward the
	// outstanding bytes the device ought to consume.
	if t.outboundStalled() {
		t.errorf("device stopped consuming our data (unacked=%d for >%s), closing tunnel",
			t.session.Stats().OutBytes(), outboundStallTimeout)
		t.Close()
	}
}

// ackHeartbeat resets the missed heartbeat counter (called when any packet is received).
func (t *Tunnel) ackHeartbeat() {
	now := time.Now()
	t.missedHeartbeatsMu.Lock()
	t.missedHeartbeats = 0
	t.missedHeartbeatsMu.Unlock()
	t.lastAckTimeMu.Lock()
	t.lastAckTime = now
	t.lastAckTimeMu.Unlock()
}

// IsResponsive returns true if the tunnel received a packet from the device
// within the given duration. This indicates the device is not overloaded
// and can handle new BIND/DESCRIBE requests.
func (t *Tunnel) IsResponsive(within time.Duration) bool {
	t.lastAckTimeMu.Lock()
	last := t.lastAckTime
	t.lastAckTimeMu.Unlock()
	if last.IsZero() {
		return false
	}
	return time.Since(last) < within
}

// reader reads packets from the device
func (t *Tunnel) reader() {
	for {
		select {
		case <-t.done:
			return
		default:
		}

		data, err := t.client.ReadRaw(1 * time.Second)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-t.done:
				return
			default:
			}

			t.consecutiveReadErrs++
			if t.consecutiveReadErrs >= maxConsecutiveReadErrors {
				t.errorf("too many read errors (%d), closing tunnel", t.consecutiveReadErrs)
				t.Close()
				return
			}
			continue
		}

		t.consecutiveReadErrs = 0
		packet, err := ptcp.ParsePacket(data)
		if err != nil {
			t.trace("reader: unparseable packet len=%d: %s", len(data), err)
			continue
		}

		t.ackHeartbeat()
		t.session.Recv(packet)

		switch packet.Body.Type {
		case ptcp.BodyTypeEmpty:
			// Don't ACK empty packets; they are ACKs themselves.
			continue

		case ptcp.BodyTypeSync:
			_ = t.sendPacket(ptcp.NewSyncBody())
			continue

		case ptcp.BodyTypeStatus:
			realm := packet.Body.Realm
			status := packet.Body.Status

			t.trace("PTCP status realm=%d status=%s", realm, status)

			if status == ptcp.StatusConnect {
				t.connChMu.Lock()
				if ch, ok := t.connCh[realm]; ok {
					ch <- true
					delete(t.connCh, realm)
				} else {
					t.errorf("reader: StatusConnect for unknown realm=%d", realm)
				}
				t.connChMu.Unlock()
			} else if status == ptcp.StatusDisconnect {
				// Device initiated disconnect: signal the Conn and remove realm.
				t.realmsMu.Lock()
				conn, ok := t.realms[realm]
				if ok {
					delete(t.realms, realm)
				}
				t.realmsMu.Unlock()
				if ok {
					conn.signalClosed()
				}
			}

			t.scheduleACK()

		case ptcp.BodyTypePayload:
			realm := packet.Body.Realm
			t.realmsMu.RLock()
			conn, ok := t.realms[realm]
			t.realmsMu.RUnlock()

			if ok {
				// Never block the reader: it serves every realm on this
				// tunnel, so one slow consumer must not stall the others.
				// When the buffer is full we tear the realm down rather than
				// drop bytes, since a hole in the middle of an RTSP stream is
				// worse than a clean EOF.
				select {
				case conn.dataCh <- packet.Body.Data:
				default:
					t.errorf("payload channel full, closing realm=%d", realm)
					t.realmsMu.Lock()
					delete(t.realms, realm)
					t.realmsMu.Unlock()
					conn.signalClosed()
					_ = t.sendPacket(ptcp.NewStatusBody(realm, ptcp.StatusDisconnect))
				}
			} else {
				t.errorf("reader: payload for unknown realm=%d len=%d", realm, len(packet.Body.Data))
			}

			t.scheduleACK()

		case ptcp.BodyTypeHeartbeat:
			t.scheduleACK()

		default:
			t.trace("reader: unhandled body type=%d", int(packet.Body.Type))
		}
	}
}

// ackCoalesceWindow is how long to wait before sending a batched ACK.
// The DMSS app averages ~2.7 payloads per ACK; 20ms coalesces effectively
// while staying responsive.
const ackCoalesceWindow = 20 * time.Millisecond

// scheduleACK marks that an ACK is needed and starts a coalescing timer.
// Multiple received packets within the window produce a single ACK,
// reducing traffic to the device.
func (t *Tunnel) scheduleACK() {
	t.ackMu.Lock()
	defer t.ackMu.Unlock()

	if t.ackPending {
		return
	}
	t.ackPending = true
	t.ackTimer = time.AfterFunc(ackCoalesceWindow, t.flushACK)
}

// flushACK sends the coalesced ACK. The whole body runs under ackMu so two
// flushes can never overlap: clearing ackPending before the send would let
// the reader arm a second timer that fires while this one is still in
// sendPacket, racing on consecutiveSendErrs.
func (t *Tunnel) flushACK() {
	t.ackMu.Lock()
	err := t.sendPacket(ptcp.NewEmptyBody())
	if err == nil {
		t.consecutiveSendErrs = 0
	} else {
		t.consecutiveSendErrs++
	}
	errs := t.consecutiveSendErrs
	t.ackPending = false
	t.ackMu.Unlock()

	if err == nil {
		return
	}
	if errs >= maxConsecutiveSendErrors {
		t.errorf("too many ACK send errors (%d), closing tunnel", errs)
		t.Close()
		return
	}
	t.trace("ACK send failed: %s", err)
}

// randomRealmID generates a random uint32 realm ID that doesn't collide with
// any existing realm. The DMSS app uses large, non-sequential realm IDs.
func (t *Tunnel) randomRealmID() uint32 {
	t.realmsMu.RLock()
	defer t.realmsMu.RUnlock()
	for {
		id := rand.Uint32()
		if _, exists := t.realms[id]; !exists {
			return id
		}
	}
}

// ActiveRealms returns the number of currently active realms on this tunnel.
func (t *Tunnel) ActiveRealms() int {
	t.realmsMu.RLock()
	n := len(t.realms)
	t.realmsMu.RUnlock()
	return n
}

// Dial creates a new realm/connection to the specified port on the device.
// Serialized via dialMu so the device processes one BIND at a time.
func (t *Tunnel) Dial(port uint32) (*Conn, error) {
	t.mu.RLock()
	closed, retired := t.closed, t.retired
	t.mu.RUnlock()
	if closed {
		return nil, ErrTunnelClosed
	}
	if retired {
		return nil, ErrTunnelRetired
	}

	// Serialize Dial calls: the device can't reliably handle concurrent BINDs
	t.dialMu.Lock()
	defer t.dialMu.Unlock()

	// Re-check after the wait: the tunnel may have been retired or closed
	// while we were queued behind another dial.
	t.mu.RLock()
	closed, retired = t.closed, t.retired
	t.mu.RUnlock()
	if closed {
		return nil, ErrTunnelClosed
	}
	if retired {
		return nil, ErrTunnelRetired
	}

	// One BIND, and two seconds for it.
	//
	// A BIND the device means to answer comes back in tens of milliseconds:
	// 11ms median and 40ms worst over 16 measured realm opens. This used to
	// retry up to three times with a fresh realm ID, on the theory that UDP
	// loses packets. Across three production logs, twenty such retries went
	// out and not one was ever answered: once a tunnel stops granting
	// realms, it grants no more, while a sibling tunnel to the same device
	// binds one in under a second. Retrying here only spends the waiting
	// RTSP client's budget -- five seconds in go2rtc, for the whole of
	// acquire, lock, settle and BIND -- and holds the negotiate lock while
	// every other stream on the tunnel queues behind it.
	//
	// Failing at two seconds lets the caller do the thing that does work,
	// which is to take the realm to another tunnel.
	const bindTimeout = 2 * time.Second

	realmID := t.randomRealmID()
	conn := &Conn{
		tunnel:               t,
		realmID:              realmID,
		remotePort:           port,
		dataCh:               make(chan []byte, 4096),
		closeCh:              make(chan struct{}),
		readDeadlineChanged:  make(chan struct{}),
		writeDeadlineChanged: make(chan struct{}),
	}
	connCh := make(chan bool, 1)

	// Install conn under realmsMu, refusing if the tunnel closed between
	// our initial check and now (which would have nilled the map).
	t.realmsMu.Lock()
	if t.realms == nil {
		t.realmsMu.Unlock()
		return nil, ErrTunnelClosed
	}
	t.realms[realmID] = conn
	t.realmsMu.Unlock()

	t.connChMu.Lock()
	t.connCh[realmID] = connCh
	t.connChMu.Unlock()

	cleanup := func() {
		t.realmsMu.Lock()
		delete(t.realms, realmID)
		t.realmsMu.Unlock()
		t.connChMu.Lock()
		delete(t.connCh, realmID)
		t.connChMu.Unlock()
	}

	t.trace("sending BIND realm=%d port=%d", realmID, port)

	if err := t.sendPacket(ptcp.NewBindBody(realmID, port)); err != nil {
		cleanup()
		return nil, err
	}

	select {
	case <-connCh:
		return conn, nil
	case <-t.done:
		cleanup()
		return nil, ErrTunnelClosed
	case <-time.After(bindTimeout):
		cleanup()
	}

	t.errorf("bind request unanswered after %s port=%d closed=%v",
		bindTimeout, port, t.IsClosed())
	return nil, ErrDialTimeout
}

// Conn represents a connection within a tunnel
type Conn struct {
	tunnel     *Tunnel
	realmID    uint32
	remotePort uint32
	dataCh     chan []byte
	closeCh    chan struct{} // closed once by signalClosed to unblock Read/Write
	closed     bool
	mu         sync.Mutex

	closeOnce sync.Once

	readBuf              []byte
	readDeadline         time.Time
	writeDeadline        time.Time
	readDeadlineChanged  chan struct{}
	writeDeadlineChanged chan struct{}
}

// signalClosed closes closeCh exactly once. Called by Conn.Close and by the
// tunnel reader when the device or backpressure forces a realm teardown.
func (c *Conn) signalClosed() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.closeOnce.Do(func() {
		close(c.closeCh)
	})
	if c.tunnel != nil {
		c.tunnel.interruptWrite(c)
	}
}

// Read reads data from the connection, respecting SetReadDeadline.
func (c *Conn) Read(p []byte) (n int, err error) {
	for {
		// Drain whatever is already buffered before reporting EOF, so a realm
		// that closes mid-response still yields the bytes already received.
		c.mu.Lock()
		if len(c.readBuf) > 0 {
			n = copy(p, c.readBuf)
			c.readBuf = c.readBuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		if c.readDeadlineChanged == nil {
			c.readDeadlineChanged = make(chan struct{})
		}
		closed := c.closed
		deadline := c.readDeadline
		deadlineChanged := c.readDeadlineChanged
		c.mu.Unlock()

		// Prefer queued bytes over EOF after a remote DISC.
		if closed {
			select {
			case data := <-c.dataCh:
				return c.readData(p, data)
			default:
				return 0, io.EOF
			}
		}

		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}

		select {
		case data := <-c.dataCh:
			if timer != nil {
				timer.Stop()
			}
			return c.readData(p, data)
		case <-c.closeCh:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-deadlineChanged:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *Conn) readData(p, data []byte) (int, error) {
	n := copy(p, data)
	if n < len(data) {
		c.mu.Lock()
		c.readBuf = append(c.readBuf, data[n:]...)
		c.mu.Unlock()
	}
	return n, nil
}

// maxPayloadSize is the maximum PTCP payload per UDP packet.
// PTCP header (24) + body header (12) + 1280 = 1316 bytes UDP payload,
// matching the DMSS app and staying well within MTU limits.
const maxPayloadSize = 1280

// Write writes data to the connection, fragmenting into MTU-safe PTCP packets.
func (c *Conn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ErrTunnelClosed
	}
	c.mu.Unlock()

	if c.tunnel.IsClosed() {
		return 0, ErrTunnelClosed
	}

	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPayloadSize {
			chunk = p[:maxPayloadSize]
		}
		p = p[len(chunk):]

		if err := c.tunnel.sendPacketFor(ptcp.NewPayloadBody(c.realmID, chunk), c); err != nil {
			return n, err
		}
		n += len(chunk)
	}

	return n, nil
}

// Close closes the connection, sending DISC with retries for UDP reliability.
func (c *Conn) Close() error {
	c.mu.Lock()
	alreadyClosed := c.closed
	c.closed = true
	c.mu.Unlock()

	c.signalClosed()

	if alreadyClosed {
		return nil
	}

	if !c.tunnel.IsClosed() {
		const discRetries = 3
		const discInterval = 50 * time.Millisecond
		for i := 0; i < discRetries; i++ {
			if err := c.tunnel.sendPacket(ptcp.NewStatusBody(c.realmID, ptcp.StatusDisconnect)); err != nil {
				break
			}
			if i < discRetries-1 {
				time.Sleep(discInterval)
			}
		}
	}

	c.tunnel.realmsMu.Lock()
	delete(c.tunnel.realms, c.realmID)
	c.tunnel.realmsMu.Unlock()

	return nil
}

// LocalAddr returns the local address (placeholder)
func (c *Conn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// RemoteAddr returns the remote address (placeholder)
func (c *Conn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: int(c.remotePort)}
}

// SetDeadline sets the read and write deadlines.
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.notifyReadDeadlineLocked()
	c.notifyWriteDeadlineLocked()
	c.mu.Unlock()
	return c.tunnel.updateWriteDeadline(c, t)
}

// SetReadDeadline sets the read deadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.notifyReadDeadlineLocked()
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline sets the deadline used by subsequent PTCP writes.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.notifyWriteDeadlineLocked()
	c.mu.Unlock()
	return c.tunnel.updateWriteDeadline(c, t)
}

func (c *Conn) notifyReadDeadlineLocked() {
	if c.readDeadlineChanged != nil {
		close(c.readDeadlineChanged)
	}
	c.readDeadlineChanged = make(chan struct{})
}

func (c *Conn) notifyWriteDeadlineLocked() {
	if c.writeDeadlineChanged != nil {
		close(c.writeDeadlineChanged)
	}
	c.writeDeadlineChanged = make(chan struct{})
}
