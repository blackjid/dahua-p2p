// Package dahua provides a Go implementation of the Dahua P2P protocol
// for connecting to Dahua/KBVision cameras through their P2P service.
package dahua

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/blackjid/dahua-p2p/tunnel"
)

// ErrDialTimeout is returned by Client.Dial when the device stops answering
// BINDs on a tunnel that is otherwise alive. Callers should treat the tunnel
// as dead and close it so queued siblings fail fast instead of each waiting
// out their own BIND timeout.
var ErrDialTimeout = tunnel.ErrDialTimeout

// ErrTunnelRetired is returned when a tunnel has stopped accepting new realms
// but is still serving its existing ones. Callers should acquire again to get
// a fresh tunnel rather than treating it as a failure.
var ErrTunnelRetired = tunnel.ErrTunnelRetired

// ErrSessionManagerClosed is returned by Acquire after CloseAll has started.
var ErrSessionManagerClosed = errors.New("dahua session manager closed")

// ErrFixedPortCapacity is returned when a tunnel bound to a fixed UDP port is
// full. A second tunnel cannot bind the same local port concurrently.
var ErrFixedPortCapacity = errors.New("fixed P2P port tunnel is at capacity")

// Settle times between consecutive RTSP negotiations on one tunnel. The
// device needs a breather after a DESCRIBE before it will answer the next
// BIND reliably. minNegotiateSettle is used when the device is still
// answering heartbeats, which indicates it is not yet saturated.
const (
	NegotiateSettle    = 500 * time.Millisecond
	minNegotiateSettle = 250 * time.Millisecond
	deadTunnelSilence  = 12 * time.Second
	maxBindFailures    = 2
)

// DefaultIdleTimeout is how long a tunnel persists after all streams
// disconnect. Re-handshaking costs ~3s, so keeping the tunnel warm across a
// dashboard refresh is worth far more than the idle UDP socket costs.
const DefaultIdleTimeout = 5 * time.Minute

// DefaultMaxRealmsPerTunnel is the default number of realms multiplexed on a
// single P2P tunnel. The ceiling is firmware-dependent, so it is configurable
// via `dahua.max_realms` or a per-stream `max_realms` parameter. 8 covers a
// typical dashboard mosaic on one tunnel without paying the ~3s handshake per
// stream, and has run 7 concurrent realms against a KBVision NVR for months.
const DefaultMaxRealmsPerTunnel = 8

// Client represents a P2P connection to a Dahua device.
//
// RTSP negotiation must be serialized per-client because the device cannot
// handle concurrent OPTIONS/DESCRIBE/SETUP through the PTCP tunnel. We use
// a 1-buffer channel as a context-cancellable semaphore so a caller can give
// up rather than wedge forever behind a stuck negotiation.
type Client struct {
	tunnel        *tunnel.Tunnel
	negotiateSem  chan struct{} // buffered 1; holds a token while locked
	lastNegotiate time.Time     // guarded by the negotiate lock
	errorf        func(format string, v ...any)
}

// Config contains configuration options for the P2P client
type Config struct {
	Serial    string
	Username  string
	Password  string
	Timeout   time.Duration
	P2PPort   int // Fixed local UDP port for P2P (0 = random)
	MaxRealms int // Max concurrent realms per tunnel (0 = DefaultMaxRealmsPerTunnel)

	// Trace and Error report protocol activity. This package owns no logger,
	// so the caller wires them to one; while nil, nothing is formatted.
	Trace func(format string, v ...any)
	Error func(format string, v ...any)
}

// ConnectWithConfig performs the P2P handshake and returns a live client.
func ConnectWithConfig(cfg Config) (*Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	t, err := tunnel.New(tunnel.Config{
		Serial:   cfg.Serial,
		Username: cfg.Username,
		Password: cfg.Password,
		Timeout:  cfg.Timeout,
		P2PPort:  cfg.P2PPort,
		Trace:    cfg.Trace,
		Error:    cfg.Error,
	})
	if err != nil {
		return nil, err
	}

	return &Client{
		tunnel:       t,
		negotiateSem: make(chan struct{}, 1),
		errorf:       cfg.Error,
	}, nil
}

// LockNegotiate blocks until the negotiate lock is acquired, or ctx is done.
func (c *Client) LockNegotiate(ctx context.Context) error {
	select {
	case c.negotiateSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// UnlockNegotiate releases the negotiate lock. Call it only after a
// successful LockNegotiate; calling it without ownership steals another
// caller's token.
func (c *Client) UnlockNegotiate() {
	<-c.negotiateSem
}

// WaitSettle sleeps until the device is ready for a new RTSP negotiation.
// Must be called while holding the negotiate lock.
func (c *Client) WaitSettle() {
	if c.lastNegotiate.IsZero() {
		return
	}

	settle := NegotiateSettle
	if c.tunnel.IsResponsive(2 * time.Second) {
		settle = minNegotiateSettle
	}

	if wait := settle - time.Since(c.lastNegotiate); wait > 0 {
		time.Sleep(wait)
	}
}

// DoneNegotiate records the end of an RTSP negotiation.
// Must be called while holding the negotiate lock.
func (c *Client) DoneNegotiate() {
	c.lastNegotiate = time.Now()
}

// SetOnClose registers a callback invoked once when the underlying tunnel
// closes (heartbeat timeout, too many errors, explicit Close).
func (c *Client) SetOnClose(fn func()) {
	c.tunnel.SetOnClose(fn)
}

// Close closes the P2P connection
func (c *Client) Close() error {
	return c.tunnel.Close()
}

// IsClosed returns whether the tunnel is closed
func (c *Client) IsClosed() bool {
	return c.tunnel.IsClosed()
}

// IsResponsive reports whether the device has sent us anything within d.
// Any inbound packet counts, so a tunnel whose heartbeats are still being
// answered is responsive even while it refuses new BINDs.
func (c *Client) IsResponsive(d time.Duration) bool {
	return c.tunnel.IsResponsive(d)
}

// Retire stops this client accepting new realms without disturbing the
// streams it is already carrying.
func (c *Client) Retire() { c.tunnel.Retire() }

// IsRetired reports whether the client has stopped accepting new realms.
func (c *Client) IsRetired() bool { return c.tunnel.IsRetired() }

// BindFailures returns how many consecutive realm dials have timed out on the
// underlying tunnel. Reset to zero by any successful dial.
func (c *Client) BindFailures() int {
	return c.tunnel.BindFailures()
}

// ActiveRealms returns the number of active realms on the underlying tunnel.
func (c *Client) ActiveRealms() int {
	return c.tunnel.ActiveRealms()
}

// RTSPPort returns the RTSP port advertised by the device.
func (c *Client) RTSPPort() uint32 {
	return c.tunnel.RTSPPort()
}

// Dial opens a new realm to the given port on the device. It closes a silent
// tunnel or retires one that repeatedly refuses new realms, allowing the next
// SessionManager.Acquire call to establish a fresh tunnel without disrupting
// existing realms that are still healthy.
func (c *Client) Dial(port uint32) (net.Conn, error) {
	conn, err := c.tunnel.Dial(port)
	if !errors.Is(err, ErrDialTimeout) {
		return conn, err
	}

	switch {
	case !c.tunnel.IsResponsive(deadTunnelSilence):
		c.reportError("device silent, closing tunnel")
		_ = c.Close()
	case c.tunnel.BindFailures() >= maxBindFailures:
		c.reportError("tunnel not granting realms, retiring (bind_failures=%d realms=%d)",
			c.tunnel.BindFailures(), c.tunnel.ActiveRealms())
		c.tunnel.Retire()
	}
	return nil, err
}

func (c *Client) reportError(format string, v ...any) {
	if c.errorf != nil {
		c.errorf(format, v...)
	}
}

// SessionManager manages shared P2P tunnels per effective configuration with
// refcounting. Multiple tunnels can be opened to work around the device's
// per-tunnel realm limit. Tunnels persist for IdleTimeout after the last stream
// disconnects, avoiding expensive P2P re-handshakes on reconnect.
type SessionManager struct {
	mu          sync.Mutex
	sessions    map[sessionKey][]*managedSession
	inflight    map[sessionKey]*inflightConn
	IdleTimeout time.Duration
	closed      bool
}

// sessionKey contains every setting that changes which underlying tunnel may
// be reused. MaxRealms is included because it is a per-source capacity policy.
type sessionKey struct {
	serial    string
	username  string
	password  string
	p2pPort   int
	maxRealms int
}

type managedSession struct {
	client    *Client
	refCount  int
	idleTimer *time.Timer
	maxRealms int // capacity frozen at acquire-time to match the caller's cfg
}

// inflightConn tracks an in-progress handshake so multiple goroutines
// don't race to create the same tunnel.
type inflightConn struct {
	done chan struct{}
	err  error
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:    make(map[sessionKey][]*managedSession),
		inflight:    make(map[sessionKey]*inflightConn),
		IdleTimeout: DefaultIdleTimeout,
	}
}

func sessionKeyFor(cfg Config) sessionKey {
	maxRealms := cfg.MaxRealms
	if maxRealms <= 0 {
		maxRealms = DefaultMaxRealmsPerTunnel
	}
	return sessionKey{
		serial: cfg.Serial, username: cfg.Username, password: cfg.Password,
		p2pPort: cfg.P2PPort, maxRealms: maxRealms,
	}
}

// findAvailableSession returns an existing live session with capacity, or nil.
// Must be called with m.mu held.
func (m *SessionManager) findAvailableSession(key sessionKey) *managedSession {
	sessions := m.sessions[key]
	live := sessions[:0]
	for _, s := range sessions {
		if s.client.IsClosed() {
			if s.idleTimer != nil {
				s.idleTimer.Stop()
			}
			continue
		}
		// Retired sessions stay in the list so their existing streams keep
		// their refcount and idle timer, but they are never handed out again.
		live = append(live, s)
	}
	if len(live) == 0 {
		delete(m.sessions, key)
	} else {
		m.sessions[key] = live
	}

	for _, s := range live {
		if s.client.IsRetired() {
			continue
		}
		// refCount is the number of producers that reserved this tunnel. A
		// reservation is made before Dial, so concurrent startup cannot race
		// past the realm cap.
		if s.refCount < s.maxRealms {
			return s
		}
	}
	return nil
}

// Acquire returns a cached or new client for the given config.
// If all existing tunnels are at capacity, a new tunnel is created unless the
// config pins one local UDP port, which cannot be bound by two live tunnels.
// The caller must call Release when done.
func (m *SessionManager) Acquire(cfg Config) (*Client, error) {
	key := sessionKeyFor(cfg)

	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, ErrSessionManagerClosed
		}
		if s := m.findAvailableSession(key); s != nil {
			if s.idleTimer != nil {
				s.idleTimer.Stop()
				s.idleTimer = nil
			}
			s.refCount++
			m.mu.Unlock()
			return s.client, nil
		}
		if key.p2pPort != 0 && len(m.sessions[key]) != 0 {
			m.mu.Unlock()
			return nil, fmt.Errorf("%w: %d", ErrFixedPortCapacity, key.p2pPort)
		}

		// Another goroutine is already handshaking for this configuration.
		// Wait, then retry capacity selection under the lock.
		if inf, ok := m.inflight[key]; ok {
			m.mu.Unlock()
			<-inf.done
			if inf.err != nil {
				return nil, inf.err
			}
			continue
		}

		inf := &inflightConn{done: make(chan struct{})}
		m.inflight[key] = inf
		m.mu.Unlock()

		client, err := ConnectWithConfig(cfg)

		var ms *managedSession
		m.mu.Lock()
		delete(m.inflight, key)
		if err == nil && m.closed {
			err = ErrSessionManagerClosed
		}
		inf.err = err
		if err == nil {
			ms = &managedSession{
				client:    client,
				refCount:  1,
				maxRealms: key.maxRealms,
			}
			m.sessions[key] = append(m.sessions[key], ms)
		}
		m.mu.Unlock()
		if err == nil {
			client.SetOnClose(func() { m.forget(key, ms) })
		} else if client != nil {
			if closeErr := client.Close(); closeErr != nil {
				if cfg.Error != nil {
					cfg.Error("close unused tunnel: %s", closeErr)
				}
			}
		}

		close(inf.done)

		if err != nil {
			return nil, err
		}
		return client, nil
	}
}

// removeSession returns list without s. Must be called with m.mu held.
func removeSession(list []*managedSession, s *managedSession) []*managedSession {
	for i, cur := range list {
		if cur == s {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// forget drops a dead session from the map. Called from the tunnel's OnClose,
// so it must not close anything itself.
func (m *SessionManager) forget(key sessionKey, ms *managedSession) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ms.idleTimer != nil {
		ms.idleTimer.Stop()
	}
	m.sessions[key] = removeSession(m.sessions[key], ms)
	if len(m.sessions[key]) == 0 {
		delete(m.sessions, key)
	}
}

// Release decrements the refcount for the given client. At zero the tunnel is
// kept warm for IdleTimeout before being closed. Releasing a client that has
// already been forgotten (its tunnel died) is a no-op.
func (m *SessionManager) Release(serial string, client *Client) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, sessions := range m.sessions {
		if key.serial != serial {
			continue
		}
		for _, s := range sessions {
			if s.client != client {
				continue
			}

			s.refCount--
			if s.refCount > 0 {
				return
			}
			s.refCount = 0

			if s.idleTimer != nil {
				s.idleTimer.Stop()
				s.idleTimer = nil
			}

			// A retired tunnel will never serve another stream, so there is
			// nothing to keep warm once its last one leaves.
			if s.client.IsRetired() {
				m.sessions[key] = removeSession(m.sessions[key], s)
				if len(m.sessions[key]) == 0 {
					delete(m.sessions, key)
				}
				go s.client.Close()
				return
			}
			s.idleTimer = time.AfterFunc(m.IdleTimeout, func() {
				// Drop the session under the lock, then close outside it:
				// Close fires OnClose, which takes m.mu again.
				m.mu.Lock()
				cur := m.sessions[key]
				for i, s2 := range cur {
					if s2 != s || s2.refCount > 0 {
						continue
					}
					m.sessions[key] = append(cur[:i], cur[i+1:]...)
					if len(m.sessions[key]) == 0 {
						delete(m.sessions, key)
					}
					m.mu.Unlock()
					s2.client.Close()
					return
				}
				m.mu.Unlock()
			})
			return
		}
	}
}

// CloseAll permanently closes the manager and all active sessions.
func (m *SessionManager) CloseAll() {
	m.mu.Lock()
	m.closed = true
	var all []*managedSession
	for key, sessions := range m.sessions {
		for _, s := range sessions {
			if s.idleTimer != nil {
				s.idleTimer.Stop()
			}
			all = append(all, s)
		}
		delete(m.sessions, key)
	}
	m.mu.Unlock()

	for _, s := range all {
		s.client.Close()
	}
}
