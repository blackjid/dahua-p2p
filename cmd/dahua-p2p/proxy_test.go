package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCopyRTSPMessage(t *testing.T) {
	tests := []struct {
		name    string
		message string
		wantErr bool
	}{
		{
			name:    "request without body",
			message: "OPTIONS rtsp://bridge/ RTSP/1.0\r\nCSeq: 1\r\n\r\n",
		},
		{
			name:    "response with body",
			message: "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 4\r\n\r\ntest",
		},
		{
			name:    "invalid content length",
			message: "RTSP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "duplicate content length",
			message: "RTSP/1.0 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "body too large",
			message: "RTSP/1.0 200 OK\r\nContent-Length: 1048577\r\n\r\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dst bytes.Buffer
			_, err := copyRTSPMessage(&dst, bufio.NewReader(strings.NewReader(tt.message)))
			if (err != nil) != tt.wantErr {
				t.Fatalf("copyRTSPMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && dst.String() != tt.message {
				t.Fatalf("copied message = %q, want %q", dst.String(), tt.message)
			}
		})
	}
}

func TestProxyRTSPTransitionsToInterleavedData(t *testing.T) {
	upstreamClient, upstreamBridge := net.Pipe()
	deviceBridge, deviceServer := net.Pipe()
	defer upstreamClient.Close()
	defer upstreamBridge.Close()
	defer deviceBridge.Close()
	defer deviceServer.Close()

	deadline := time.Now().Add(2 * time.Second)
	for _, conn := range []net.Conn{upstreamClient, upstreamBridge, deviceBridge, deviceServer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}

	firstRequest := "OPTIONS rtsp://bridge/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
	finished := make(chan struct{}, 1)
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxyRTSP(
			upstreamBridge,
			bufio.NewReader(upstreamBridge),
			deviceBridge,
			[]byte(firstRequest),
			"OPTIONS rtsp://bridge/ RTSP/1.0",
			func() { finished <- struct{}{} },
		)
	}()

	deviceReader := bufio.NewReader(deviceServer)
	var got bytes.Buffer
	if _, err := copyRTSPMessage(&got, deviceReader); err != nil {
		t.Fatal(err)
	}
	if got.String() != firstRequest {
		t.Fatalf("first request = %q, want %q", got.String(), firstRequest)
	}
	writeErr := asyncWrite(deviceServer, "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")

	upstreamReader := bufio.NewReader(upstreamClient)
	got.Reset()
	if _, err := copyRTSPMessage(&got, upstreamReader); err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	play := "PLAY rtsp://bridge/ RTSP/1.0\r\nCSeq: 2\r\n\r\n"
	writeErr = asyncWrite(upstreamClient, play)
	got.Reset()
	if _, err := copyRTSPMessage(&got, deviceReader); err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if got.String() != play {
		t.Fatalf("PLAY request = %q, want %q", got.String(), play)
	}
	writeErr = asyncWrite(deviceServer, "RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n$raw")
	got.Reset()
	if _, err := copyRTSPMessage(&got, upstreamReader); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 4)
	if _, err := io.ReadFull(upstreamReader, raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) != "$raw" {
		t.Fatalf("interleaved bytes = %q, want %q", raw, "$raw")
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}

	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("negotiation callback was not called")
	}
	closeConn(upstreamClient)
	closeConn(deviceServer)
	select {
	case <-proxyErr:
	case <-time.After(time.Second):
		t.Fatal("proxyRTSP did not stop after its connections closed")
	}
}

func asyncWrite(dst io.Writer, value string) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(dst, value)
		done <- err
	}()
	return done
}

func TestNegotiationFinished(t *testing.T) {
	tests := []struct {
		request  string
		response string
		want     bool
	}{
		{"PLAY rtsp://bridge/ RTSP/1.0", "RTSP/1.0 200 OK", true},
		{"RECORD rtsp://bridge/ RTSP/1.0", "RTSP/1.0 201 Created", true},
		{"PLAY rtsp://bridge/ RTSP/1.0", "RTSP/1.0 401 Unauthorized", false},
		{"SETUP rtsp://bridge/track1 RTSP/1.0", "RTSP/1.0 200 OK", false},
	}
	for _, tt := range tests {
		if got := negotiationFinished(tt.request, tt.response); got != tt.want {
			t.Errorf("negotiationFinished(%q, %q) = %v, want %v", tt.request, tt.response, got, tt.want)
		}
	}
}

func TestValidRTSPRequest(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"OPTIONS rtsp://bridge/ RTSP/1.0", true},
		{"DESCRIBE /stream RTSP/1.0", true},
		{"RTSP/1.0 200 OK", false},
		{"GET / HTTP/1.1", false},
		{"OPTIONS RTSP/1.0", false},
	}
	for _, tt := range tests {
		if got := validRTSPRequest(tt.line); got != tt.want {
			t.Errorf("validRTSPRequest(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestClientConfigReservesPrewarmSlot(t *testing.T) {
	b := &bridge{config: config{
		serial:    "device",
		username:  "user",
		password:  "pass",
		p2pPort:   5000,
		maxRealms: 8,
		timeout:   10 * time.Second,
	}}

	cfg := b.clientConfig()
	if cfg.MaxRealms != 9 {
		t.Fatalf("MaxRealms = %d, want 9", cfg.MaxRealms)
	}
	if cfg.Serial != b.config.serial || cfg.Username != b.config.username || cfg.Password != b.config.password {
		t.Fatal("clientConfig did not preserve device credentials")
	}
}
