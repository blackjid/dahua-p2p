package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/blackjid/dahua-p2p"
)

const (
	initialRequestTimeout = 10 * time.Second
	negotiateTimeout      = 90 * time.Second

	// admitTimeout bounds how long a client waits behind other streams for
	// the negotiate lock. RTSP clients abandon a command in about five
	// seconds and go2rtc hardcodes exactly that, so a longer queue only
	// collects connections whose client has already given up while they
	// still hold a slot. Failing fast lets the client retry against a
	// bridge that can actually answer it.
	admitTimeout = 3 * time.Second

	// maxSettleWait is how much of the client's remaining patience may be
	// spent waiting for the device to be ready for another realm. Waiting
	// happens under the negotiate lock, so anything longer starves every
	// other stream as well; past it we turn this one away at once and let it
	// retry, which costs it a reconnect instead of costing all of them.
	maxSettleWait = time.Second

	// logInterval is the minimum gap between repeats of a throttled line.
	logInterval = 5 * time.Second

	reconnectMinDelay = time.Second
	reconnectMaxDelay = 30 * time.Second

	// lostContactDelay is how long to leave the device alone after a tunnel
	// died without reaching it. Our DISCs went nowhere, so the device still
	// holds that session and every realm on it, and a tunnel built straight
	// away competes with the corpse of its predecessor until the device runs
	// out of realms and refuses every BIND. Measured: about thirty seconds of
	// quiet is enough for the device to expire a stranded session.
	lostContactDelay      = 30 * time.Second
	defaultMaxConnections = 32
)

type config struct {
	listen    string
	serial    string
	username  string
	password  string
	p2pPort   int
	maxRealms int
	maxConns  int
	timeout   time.Duration

	bindRetries  int
	bindTimeout  time.Duration
	countersEach time.Duration

	debug bool
}

type bridge struct {
	config      config
	client      *dahua.Client
	cancel      context.CancelFunc
	slots       chan struct{}
	connections map[net.Conn]struct{}
	served      atomic.Bool
	refusals    tally
	mu          sync.Mutex
	wg          sync.WaitGroup
}

// tally counts refusals by reason and reports them as one line per
// reportInterval. A client that retries a refused stream several times a
// second would otherwise bury every line worth reading; dropping the repeats
// outright would instead hide which reason was actually dominant.
type tally struct {
	mu     sync.Mutex
	last   time.Time
	counts map[string]int
}

// add records one refusal and returns the counts to report, or nil while the
// reporting interval has not elapsed. The returned map is the caller's.
func (t *tally) add(reason string, interval time.Duration) map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.counts == nil {
		t.counts = map[string]int{}
	}
	t.counts[reason]++
	if !t.last.IsZero() && time.Since(t.last) < interval {
		return nil
	}
	t.last = time.Now()
	counts := t.counts
	t.counts = nil
	return counts
}

// report logs the reasons RTSP connections were turned away since the last
// report, busiest first.
func (t *tally) report(reason string) {
	counts := t.add(reason, logInterval)
	if counts == nil {
		return
	}
	reasons := make([]string, 0, len(counts))
	for r := range counts {
		reasons = append(reasons, r)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if counts[reasons[i]] != counts[reasons[j]] {
			return counts[reasons[i]] > counts[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})

	total := 0
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		total += counts[r]
		parts = append(parts, fmt.Sprintf("%s=%d", r, counts[r]))
	}
	log.Printf("turned away %d RTSP connections: %s", total, strings.Join(parts, " "))
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return supervise(ctx, backoff{
		min:         reconnectMinDelay,
		max:         reconnectMaxDelay,
		lostContact: lostContactDelay,
	}, func(ctx context.Context) error {
		return runBridge(ctx, cfg)
	})
}

func runBridge(ctx context.Context, cfg config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	b := &bridge{
		config:      cfg,
		cancel:      cancel,
		slots:       make(chan struct{}, cfg.maxConns),
		connections: make(map[net.Conn]struct{}),
	}

	if err := b.connect(); err != nil {
		return fmt.Errorf("connect P2P tunnel: %w", err)
	}
	b.client.SetOnClose(cancel)

	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		_ = b.client.Close()
		return err
	}
	defer closeListener(listener)

	log.Printf("Dahua P2P bridge listening on %s for serial %s", listener.Addr(), cfg.serial)
	if err := b.serve(ctx, listener); err != nil {
		return err
	}
	// A tunnel the device stopped answering is the case that must not be
	// rebuilt immediately, however well it was working beforehand.
	if b.client.LostContact() {
		return errLostContact
	}
	// A tunnel that never granted a realm is a failed attempt, not a healthy
	// session that ended. Saying so lets the supervisor back off instead of
	// rebuilding a tunnel the device is refusing once a second.
	if !b.served.Load() {
		return errors.New("tunnel closed without serving any RTSP stream")
	}
	return nil
}

// backoff is how long to wait between bridge cycles. lostContact is the floor
// applied when a tunnel died without reaching the device, which needs longer
// than an ordinary failure because the device is still holding the session.
type backoff struct {
	min         time.Duration
	max         time.Duration
	lostContact time.Duration
}

func supervise(ctx context.Context, b backoff, runCycle func(context.Context) error) error {
	delay := b.min
	for {
		err := runCycle(ctx)
		if ctx.Err() != nil {
			return nil
		}
		delay = b.next(delay, err)
		log.Printf("reconnecting in %s", delay)

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
	}
}

// next reports how long to wait after a cycle ended with err, and logs why.
// A cycle that reached the device and ended cleanly may retry at once; one
// that failed backs off; one that lost contact waits out the session the
// device is still holding, however healthy the tunnel was beforehand.
func (b backoff) next(delay time.Duration, err error) time.Duration {
	switch {
	case errors.Is(err, errLostContact):
		log.Printf("Dahua P2P tunnel lost contact with the device")
		if delay < b.lostContact {
			return b.lostContact
		}
		return nextBackoff(delay, b.max)
	case err != nil:
		log.Printf("Dahua P2P bridge stopped: %v", err)
		return nextBackoff(delay, b.max)
	default:
		log.Printf("Dahua P2P tunnel closed")
		return b.min
	}
}

func nextBackoff(delay, maxDelay time.Duration) time.Duration {
	if delay >= maxDelay/2 {
		return maxDelay
	}
	return delay * 2
}

func loadConfig() (config, error) {
	p2pPort, err := envInt("DAHUA_P2P_PORT", 0)
	if err != nil {
		return config{}, err
	}
	maxRealms, err := envInt("DAHUA_MAX_REALMS", dahua.DefaultMaxRealmsPerTunnel)
	if err != nil {
		return config{}, err
	}
	maxConns, err := envInt("DAHUA_MAX_CONNECTIONS", defaultMaxConnections)
	if err != nil {
		return config{}, err
	}
	bindRetries, err := envInt("DAHUA_BIND_RETRIES", 0)
	if err != nil {
		return config{}, err
	}
	bindTimeout, err := envDuration("DAHUA_BIND_TIMEOUT", 0)
	if err != nil {
		return config{}, err
	}
	countersEach, err := envDuration("DAHUA_COUNTERS_INTERVAL", 0)
	if err != nil {
		return config{}, err
	}

	cfg := config{}
	flag.StringVar(&cfg.listen, "listen", env("LISTEN_ADDR", ":8554"), "TCP address to expose as RTSP")
	flag.StringVar(&cfg.serial, "serial", "", "Dahua device serial; defaults to DAHUA_SERIAL")
	flag.StringVar(&cfg.username, "username", "", "Dahua username; defaults to DAHUA_USERNAME")
	flag.IntVar(&cfg.p2pPort, "p2p-port", p2pPort, "fixed local UDP port; zero chooses one automatically")
	flag.IntVar(&cfg.maxRealms, "max-realms", maxRealms, "maximum concurrent RTSP connections per P2P tunnel")
	flag.IntVar(&cfg.maxConns, "max-connections", maxConns, "maximum concurrent RTSP client connections")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "P2P handshake timeout")
	flag.DurationVar(&cfg.countersEach, "counters-interval", countersEach, "how often to trace PTCP counters; needs -debug")
	flag.IntVar(&cfg.bindRetries, "bind-retries", bindRetries, "attempts to open one P2P realm before giving up")
	flag.DurationVar(&cfg.bindTimeout, "bind-timeout", bindTimeout, "how long to wait for each realm attempt")
	flag.BoolVar(&cfg.debug, "debug", false, "log protocol traces")
	flag.Parse()
	if cfg.serial == "" {
		cfg.serial = os.Getenv("DAHUA_SERIAL")
	}
	if cfg.username == "" {
		cfg.username = os.Getenv("DAHUA_USERNAME")
	}
	cfg.password, err = secretEnv("DAHUA_PASSWORD")
	if err != nil {
		return config{}, err
	}

	switch {
	case cfg.serial == "":
		return config{}, errors.New("DAHUA_SERIAL or -serial is required")
	case cfg.p2pPort < 0 || cfg.p2pPort > 65535:
		return config{}, fmt.Errorf("p2p port must be between 0 and 65535: %d", cfg.p2pPort)
	case cfg.maxRealms < 1:
		return config{}, fmt.Errorf("max realms must be positive: %d", cfg.maxRealms)
	case cfg.maxConns < 1:
		return config{}, fmt.Errorf("max connections must be positive: %d", cfg.maxConns)
	case cfg.timeout <= 0:
		return config{}, fmt.Errorf("timeout must be positive: %s", cfg.timeout)
	case cfg.bindRetries < 0:
		return config{}, fmt.Errorf("bind retries cannot be negative: %d", cfg.bindRetries)
	case cfg.bindTimeout < 0:
		return config{}, fmt.Errorf("bind timeout cannot be negative: %s", cfg.bindTimeout)
	case cfg.countersEach < 0:
		return config{}, fmt.Errorf("counters interval cannot be negative: %s", cfg.countersEach)
	}
	return cfg, nil
}

func secretEnv(name string) (string, error) {
	value := os.Getenv(name)
	filename := os.Getenv(name + "_FILE")
	if value != "" && filename != "" {
		return "", fmt.Errorf("set only one of %s and %s_FILE", name, name)
	}
	if filename == "" {
		return value, nil
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", name, value, err)
	}
	return d, nil
}

func envInt(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", name, value, err)
	}
	return n, nil
}

func (b *bridge) serve(ctx context.Context, listener net.Listener) error {
	defer b.shutdown()
	go func() {
		<-ctx.Done()
		closeListener(listener)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept RTSP connection: %w", err)
		}
		select {
		case b.slots <- struct{}{}:
			b.track(conn)
			b.wg.Add(1)
			go func() {
				defer func() {
					b.untrack(conn)
					<-b.slots
					b.wg.Done()
				}()
				b.handle(ctx, conn)
			}()
		default:
			b.refusals.report("connection limit")
			closeConn(conn)
		}
	}
}

// connect establishes the bridge's single persistent tunnel before the RTSP
// listener opens. A closed or retired tunnel ends this bridge cycle so the
// supervisor can establish a clean replacement.
func (b *bridge) connect() error {
	client, err := dahua.ConnectWithConfig(b.clientConfig())
	if err != nil {
		return err
	}
	b.client = client
	log.Printf("Dahua P2P tunnel ready for serial %s", b.config.serial)
	return nil
}

func (b *bridge) clientConfig() dahua.Config {
	cfg := dahua.Config{
		Serial:    b.config.serial,
		Username:  b.config.username,
		Password:  b.config.password,
		Timeout:   b.config.timeout,
		P2PPort:   b.config.p2pPort,
		MaxRealms: b.config.maxRealms,

		// The budget is held under the tunnel's dial lock, so it is also how
		// long every other queued stream waits on a device that has stopped
		// answering. Keep it inside an RTSP client's patience.
		BindRetries: b.config.bindRetries,
		BindTimeout: b.config.bindTimeout,

		LossReportInterval: b.config.countersEach,

		Error: func(format string, args ...any) { log.Printf("dahua: "+format, args...) },
	}
	if b.config.debug {
		cfg.Trace = func(format string, args ...any) { log.Printf("dahua: "+format, args...) }
	}
	return cfg
}

func (b *bridge) track(conn net.Conn) {
	b.mu.Lock()
	b.connections[conn] = struct{}{}
	b.mu.Unlock()
}

func (b *bridge) untrack(conn net.Conn) {
	b.mu.Lock()
	delete(b.connections, conn)
	b.mu.Unlock()
}

func (b *bridge) shutdown() {
	if b.client != nil {
		_ = b.client.Close()
	}
	b.mu.Lock()
	connections := make([]net.Conn, 0, len(b.connections))
	for conn := range b.connections {
		connections = append(connections, conn)
	}
	b.mu.Unlock()
	for _, conn := range connections {
		closeConn(conn)
	}
	b.wg.Wait()
}

func (b *bridge) handle(ctx context.Context, upstream net.Conn) {
	defer closeConn(upstream)

	if err := upstream.SetReadDeadline(time.Now().Add(initialRequestTimeout)); err != nil {
		log.Printf("set initial request deadline for %s: %v", upstream.RemoteAddr(), err)
		return
	}
	upstreamReader := bufio.NewReaderSize(upstream, maxRTSPHeaderBytes)
	var firstRequest bytes.Buffer
	requestLine, err := copyRTSPMessage(&firstRequest, upstreamReader)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			log.Printf("read initial RTSP request from %s: %v", upstream.RemoteAddr(), err)
		}
		return
	}
	if !validRTSPRequest(requestLine) {
		log.Printf("reject invalid RTSP request from %s", upstream.RemoteAddr())
		return
	}
	if err := upstream.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("clear initial request deadline for %s: %v", upstream.RemoteAddr(), err)
		return
	}

	device, finishNegotiation, err := b.openRealm(ctx)
	if err != nil {
		b.refusals.report(refusalReason(err))
		if b.client.IsClosed() || b.client.IsRetired() {
			b.cancel()
		}
		return
	}
	defer finishNegotiation()
	defer closeConn(device)

	deadline := time.Now().Add(negotiateTimeout)
	if err := upstream.SetDeadline(deadline); err != nil {
		log.Printf("set upstream negotiation deadline: %v", err)
		return
	}
	if err := device.SetDeadline(deadline); err != nil {
		log.Printf("set device negotiation deadline: %v", err)
		return
	}
	finishProxyNegotiation := func() {
		finishNegotiation()
		if err := upstream.SetDeadline(time.Time{}); err != nil {
			log.Printf("clear upstream negotiation deadline: %v", err)
		}
		if err := device.SetDeadline(time.Time{}); err != nil {
			log.Printf("clear device negotiation deadline: %v", err)
		}
	}

	if err := proxyRTSP(upstream, upstreamReader, device, firstRequest.Bytes(), requestLine, finishProxyNegotiation); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("RTSP bridge from %s closed: %v", upstream.RemoteAddr(), err)
	}
}

// Reasons a stream is turned away, kept as sentinels so the log groups them
// rather than printing one line per retry.
// errLostContact marks a cycle that ended because the device stopped reaching
// us, which is also why it never received our teardown.
var errLostContact = errors.New("device unreachable")

var (
	errAdmitTimeout   = errors.New("waiting for negotiate lock")
	errRealmCapacity  = errors.New("realm capacity reached")
	errDeviceSettling = errors.New("device not ready for another realm")
)

// refusalReason names the failure for the refusal log. RTSP gives the client
// only a closed connection, so this line is the sole record of why a stream
// did not start.
func refusalReason(err error) string {
	switch {
	case errors.Is(err, errAdmitTimeout):
		return "negotiate lock busy"
	case errors.Is(err, errRealmCapacity):
		return "realm capacity"
	case errors.Is(err, errDeviceSettling):
		return "device settling"
	case errors.Is(err, dahua.ErrDialTimeout):
		return "device refusing realms"
	case errors.Is(err, dahua.ErrTunnelRetired):
		return "tunnel retired"
	case errors.Is(err, dahua.ErrTunnelClosed):
		return "tunnel closed"
	default:
		return "error: " + err.Error()
	}
}

func (b *bridge) openRealm(ctx context.Context) (net.Conn, func(), error) {
	admitCtx, cancel := context.WithTimeout(ctx, admitTimeout)
	err := b.client.LockNegotiate(admitCtx)
	cancel()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errAdmitTimeout, err)
	}
	// Checked before settling: a BIND the device would refuse is not worth
	// the settle delay, and the caller can be turned away while its client
	// is still listening.
	if n := b.client.ActiveRealms(); n >= b.config.maxRealms {
		b.client.UnlockNegotiate()
		return nil, nil, fmt.Errorf("%w: %d/%d", errRealmCapacity, n, b.config.maxRealms)
	}

	// The device goes quiet for seconds after granting a realm. Waiting that
	// out holds the negotiate lock, so wait only what this client can afford
	// and stand down beyond it rather than taking every other stream down
	// with us.
	if wait := b.client.SettleRemaining(); wait > maxSettleWait {
		b.client.UnlockNegotiate()
		return nil, nil, fmt.Errorf("%w: ready in %s", errDeviceSettling, wait.Round(time.Millisecond))
	}
	b.client.WaitSettle()

	var finishOnce sync.Once
	finish := func() {
		finishOnce.Do(func() {
			b.client.DoneNegotiate()
			b.client.UnlockNegotiate()
		})
	}

	device, err := b.client.Dial(b.client.RTSPPort())
	if err != nil {
		finish()
		return nil, nil, fmt.Errorf("dial P2P realm: %w", err)
	}
	b.served.Store(true)
	return device, finish, nil
}

func closeListener(listener net.Listener) {
	if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("close listener: %v", err)
	}
}
