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
	reconnectMinDelay     = time.Second
	reconnectMaxDelay     = 30 * time.Second
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
	client      *dahua.Client
	cancel      context.CancelFunc
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return supervise(ctx, reconnectMinDelay, reconnectMaxDelay, func(ctx context.Context) error {
		return runBridge(ctx, cfg)
	})
}

func runBridge(ctx context.Context, cfg config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	b := &bridge{
		config:      cfg,
		cancel:      cancel,
		slots:       make(chan struct{}, connectionLimit(cfg)),
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
	return b.serve(ctx, listener)
}

func supervise(ctx context.Context, minDelay, maxDelay time.Duration, runCycle func(context.Context) error) error {
	delay := minDelay
	for {
		err := runCycle(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			log.Printf("Dahua P2P bridge stopped: %v", err)
		} else {
			log.Printf("Dahua P2P tunnel closed")
			delay = minDelay
		}
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
		if err != nil {
			delay = nextBackoff(delay, maxDelay)
		}
	}
}

func nextBackoff(delay, maxDelay time.Duration) time.Duration {
	if delay >= maxDelay/2 {
		return maxDelay
	}
	return delay * 2
}

func connectionLimit(cfg config) int {
	if cfg.maxConns < cfg.maxRealms {
		return cfg.maxConns
	}
	return cfg.maxRealms
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
		Error:     func(format string, args ...any) { log.Printf("dahua: "+format, args...) },
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
		log.Printf("open P2P realm from %s: %v", upstream.RemoteAddr(), err)
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

func (b *bridge) openRealm(ctx context.Context) (net.Conn, func(), error) {
	negotiateCtx, cancel := context.WithTimeout(ctx, negotiateTimeout)
	err := b.client.LockNegotiate(negotiateCtx)
	cancel()
	if err != nil {
		return nil, nil, fmt.Errorf("negotiate lock: %w", err)
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
	return device, finish, nil
}

func closeListener(listener net.Listener) {
	if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("close listener: %v", err)
	}
}
