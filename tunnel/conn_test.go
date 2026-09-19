package tunnel

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func newTestConn() *Conn {
	return &Conn{
		dataCh:               make(chan []byte, 4),
		closeCh:              make(chan struct{}),
		readDeadlineChanged:  make(chan struct{}),
		writeDeadlineChanged: make(chan struct{}),
	}
}

// TestReadDrainsBufferAfterClose: a realm that closes mid-response must still
// hand back the bytes it already received, or RTSP loses the tail of a
// DESCRIBE it actually got.
func TestReadDrainsBufferAfterClose(t *testing.T) {
	c := newTestConn()
	c.dataCh <- []byte("RTSP/1.0 200 OK")

	buf := make([]byte, 4)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "RTSP" {
		t.Fatalf("first read: n=%d err=%v got=%q", n, err, buf[:n])
	}

	// Realm dies while the rest is still buffered.
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.signalClosed()

	buf = make([]byte, 64)
	n, err = c.Read(buf)
	if err != nil {
		t.Fatalf("read after close: unexpected err %v", err)
	}
	if string(buf[:n]) != "/1.0 200 OK" {
		t.Fatalf("read after close: got %q", buf[:n])
	}

	if _, err = c.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("drained read: want EOF, got %v", err)
	}
}

func TestReadDeadlineExceeded(t *testing.T) {
	c := newTestConn()
	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want ErrDeadlineExceeded, got %v", err)
	}
}

func TestSetReadDeadlineWakesPendingRead(t *testing.T) {
	c := newTestConn()
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 8))
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("want ErrDeadlineExceeded, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending Read did not observe the new deadline")
	}
}

// TestReadUnblocksOnClose: the tunnel reader signals a realm teardown while a
// consumer is parked in Read; it must return rather than hang to the deadline.
func TestReadUnblocksOnClose(t *testing.T) {
	c := newTestConn()
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 8))
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	c.signalClosed()

	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("want EOF, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not return after signalClosed")
	}
}

// TestReadPartialCopy: a short buffer must not drop the remainder.
func TestReadPartialCopy(t *testing.T) {
	c := newTestConn()
	c.dataCh <- []byte("abcdefgh")

	small := make([]byte, 3)
	var got []byte
	for i := 0; i < 3; i++ {
		n, err := c.Read(small)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		got = append(got, small[:n]...)
	}
	if string(got) != "abcdefgh" {
		t.Fatalf("got %q, want %q", got, "abcdefgh")
	}
}

func TestSignalClosedIsIdempotent(t *testing.T) {
	c := newTestConn()
	c.signalClosed()
	c.signalClosed() // must not panic on double close
}

func TestSignalClosedRejectsWrites(t *testing.T) {
	c := newTestConn()
	c.signalClosed()
	if _, err := c.Write([]byte("data")); !errors.Is(err, ErrTunnelClosed) {
		t.Fatalf("Write after remote close = %v, want ErrTunnelClosed", err)
	}
}

func TestWriteDeadlineExceeded(t *testing.T) {
	c := newTestConn()
	c.tunnel = &Tunnel{}
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("data")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write after deadline = %v, want ErrDeadlineExceeded", err)
	}
}

func TestQueuedWriteObservesUpdatedDeadline(t *testing.T) {
	tunnel := &Tunnel{done: make(chan struct{})}
	if err := tunnel.acquireSendPermit(nil); err != nil {
		t.Fatal(err)
	}
	defer func() { tunnel.sendPermit <- struct{}{} }()

	c := newTestConn()
	c.tunnel = tunnel
	done := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("data"))
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("want ErrDeadlineExceeded, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued Write did not observe the new deadline")
	}
}

func TestQueuedWriteUnblocksOnClose(t *testing.T) {
	tunnel := &Tunnel{done: make(chan struct{})}
	if err := tunnel.acquireSendPermit(nil); err != nil {
		t.Fatal(err)
	}
	defer func() { tunnel.sendPermit <- struct{}{} }()

	c := newTestConn()
	c.tunnel = tunnel
	done := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("data"))
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	c.signalClosed()

	select {
	case err := <-done:
		if !errors.Is(err, ErrTunnelClosed) {
			t.Fatalf("want ErrTunnelClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued Write did not return after Close")
	}
}

func TestSetWriteDeadlineAfterClose(t *testing.T) {
	c := newTestConn()
	c.tunnel = &Tunnel{}
	c.signalClosed()
	if err := c.SetWriteDeadline(time.Now().Add(time.Hour)); !errors.Is(err, ErrTunnelClosed) {
		t.Fatalf("SetWriteDeadline after close = %v, want ErrTunnelClosed", err)
	}
}

func TestRemoteAddrUsesDialPort(t *testing.T) {
	c := newTestConn()
	c.remotePort = 8554
	if got := c.RemoteAddr().(*net.TCPAddr).Port; got != 8554 {
		t.Fatalf("RemoteAddr port = %d, want 8554", got)
	}
}
