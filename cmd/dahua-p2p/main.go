package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blackjid/dahua-p2p"
)

const (
	initialRequestTimeout = 10 * time.Second
	negotiateTimeout      = 90 * time.Second
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
	debug     bool
}

type bridge struct {
	config      config
	sessions    *dahua.SessionManager
	slots       chan struct{}
	connections map[net.Conn]struct{}
	mu          sync.Mutex
	wg          sync.WaitGroup
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

	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return err
	}
	defer closeListener(listener)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	b := &bridge{
		config:      cfg,
		sessions:    dahua.NewSessionManager(),
		slots:       make(chan struct{}, cfg.maxConns),
		connections: make(map[net.Conn]struct{}),
	}

	log.Printf("Dahua P2P bridge listening on %s for serial %s", listener.Addr(), cfg.serial)
	return b.serve(ctx, listener)
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

	cfg := config{}
	flag.StringVar(&cfg.listen, "listen", env("LISTEN_ADDR", ":8554"), "TCP address to expose as RTSP")
	flag.StringVar(&cfg.serial, "serial", "", "Dahua device serial; defaults to DAHUA_SERIAL")
	flag.StringVar(&cfg.username, "username", "", "Dahua username; defaults to DAHUA_USERNAME")
	flag.IntVar(&cfg.p2pPort, "p2p-port", p2pPort, "fixed local UDP port; zero chooses one automatically")
	flag.IntVar(&cfg.maxRealms, "max-realms", maxRealms, "maximum concurrent RTSP connections per P2P tunnel")
	flag.IntVar(&cfg.maxConns, "max-connections", maxConns, "maximum concurrent RTSP client connections")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "P2P handshake timeout")
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
	case cfg.p2pPort != 0 && cfg.maxConns > cfg.maxRealms:
		return config{}, errors.New("max connections cannot exceed max realms with a fixed P2P port")
	case cfg.timeout <= 0:
		return config{}, fmt.Errorf("timeout must be positive: %s", cfg.timeout)
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
			log.Printf("reject RTSP connection from %s: connection limit reached", conn.RemoteAddr())
			closeConn(conn)
		}
	}
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
	b.sessions.CloseAll()
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
		log.Printf("read initial RTSP request from %s: %v", upstream.RemoteAddr(), err)
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

	cfg := dahua.Config{
		Serial:    b.config.serial,
		Username:  b.config.username,
		Password:  b.config.password,
		Timeout:   b.config.timeout,
		P2PPort:   b.config.p2pPort,
		MaxRealms: b.config.maxRealms,
		Error:     func(format string, args ...any) { log.Printf("dahua: "+format, args...) },
	}
	if b.config.debug {
		cfg.Trace = func(format string, args ...any) { log.Printf("dahua: "+format, args...) }
	}

	device, finishNegotiation, release, err := b.openRealm(ctx, cfg)
	if err != nil {
		log.Printf("open P2P realm from %s: %v", upstream.RemoteAddr(), err)
		return
	}
	defer release()
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

func (b *bridge) openRealm(ctx context.Context, cfg dahua.Config) (net.Conn, func(), func(), error) {
	var lastErr error
	// The client is still waiting on its first RTSP response while all of
	// this runs, and it applies its own deadline to that response — five
	// seconds in go2rtc. Acquire, lock, settle and BIND all come out of that
	// budget before a single byte reaches the device, so each phase is timed
	// separately: a total past the deadline loses the stream no matter how
	// quickly the device then answers.
	realmStart := time.Now()
	for attempt := 0; attempt < 2; attempt++ {
		client, err := b.sessions.Acquire(cfg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("P2P handshake: %w", err)
		}
		acquired := time.Now()

		negotiateCtx, cancel := context.WithTimeout(ctx, negotiateTimeout)
		err = client.LockNegotiate(negotiateCtx)
		cancel()
		if err != nil {
			b.sessions.Release(b.config.serial, client)
			return nil, nil, nil, fmt.Errorf("negotiate lock: %w", err)
		}
		locked := time.Now()
		client.WaitSettle()
		settled := time.Now()

		var finishOnce sync.Once
		finish := func() {
			finishOnce.Do(func() {
				client.DoneNegotiate()
				client.UnlockNegotiate()
			})
		}
		device, err := client.Dial(client.RTSPPort())
		logRealmOpen(attempt, realmStart, acquired, locked, settled, time.Now(), err)
		if err == nil {
			release := func() { b.sessions.Release(b.config.serial, client) }
			return device, finish, release, nil
		}

		finish()
		b.sessions.Release(b.config.serial, client)
		lastErr = err
		if cfg.P2PPort != 0 || !client.IsRetired() {
			break
		}
	}
	return nil, nil, nil, fmt.Errorf("dial P2P realm: %w", lastErr)
}

// realmOpenBudget is the deadline an unmodified go2rtc applies to the RTSP
// response this whole sequence delays (pkg/rtsp.Timeout). Past it the client
// has already given up, so the realm is opened for nobody.
const realmOpenBudget = 5 * time.Second

func logRealmOpen(attempt int, start, acquired, locked, settled, done time.Time, err error) {
	total := done.Sub(start)
	verdict := ""
	if total >= realmOpenBudget {
		verdict = fmt.Sprintf(" (past the %s an RTSP client allows)", realmOpenBudget)
	}
	ms := func(a, b time.Time) string { return b.Sub(a).Round(time.Millisecond).String() }
	if err != nil {
		log.Printf("realm timing attempt=%d FAILED total=%s%s acquire=%s lock=%s settle=%s bind=%s: %v",
			attempt+1, total.Round(time.Millisecond), verdict,
			ms(start, acquired), ms(acquired, locked), ms(locked, settled), ms(settled, done), err)
		return
	}
	log.Printf("realm timing attempt=%d total=%s%s acquire=%s lock=%s settle=%s bind=%s",
		attempt+1, total.Round(time.Millisecond), verdict,
		ms(start, acquired), ms(acquired, locked), ms(locked, settled), ms(settled, done))
}

func closeListener(listener net.Listener) {
	if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("close listener: %v", err)
	}
}
