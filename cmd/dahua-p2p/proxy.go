package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	maxRTSPHeaderBytes = 64 << 10
	maxRTSPBodyBytes   = 1 << 20
)

func proxyRTSP(
	upstream net.Conn,
	upstreamReader *bufio.Reader,
	device net.Conn,
	firstRequest []byte,
	requestLine string,
	finishNegotiation func(),
) error {
	deviceReader := bufio.NewReaderSize(device, maxRTSPHeaderBytes)
	sent := time.Now()
	if err := writeAll(device, firstRequest); err != nil {
		return err
	}

	for {
		responseLine, err := copyRTSPMessage(upstream, deviceReader)
		// Every command the client sends is round-tripped to the device here,
		// and an RTSP client applies its own deadline to each one. go2rtc
		// hardcodes five seconds, so a command the device answers more slowly
		// than that is abandoned no matter how healthy the tunnel is. Timing
		// each one is the only way to see that from this side.
		logRTSPCommand(requestLine, responseLine, time.Since(sent), err)
		if err != nil {
			return err
		}
		if negotiationFinished(requestLine, responseLine) {
			finishNegotiation()
			return copyBoth(upstream, upstreamReader, device, deviceReader)
		}
		requestLine, err = copyRTSPMessage(device, upstreamReader)
		if err != nil {
			return err
		}
		sent = time.Now()
	}
}

// rtspSlowCommand is the deadline an unmodified go2rtc applies to each RTSP
// command (pkg/rtsp.Timeout). Commands at or past it are the ones a client
// gives up on, so they are called out rather than merely timed.
const rtspSlowCommand = 5 * time.Second

func logRTSPCommand(requestLine, responseLine string, took time.Duration, err error) {
	method := "?"
	if f := strings.Fields(requestLine); len(f) > 0 {
		method = strings.ToUpper(f[0])
	}
	switch {
	case err != nil:
		log.Printf("rtsp timing %s failed after %s: %v", method, took.Round(time.Millisecond), err)
	case took >= rtspSlowCommand:
		log.Printf("rtsp timing %s took %s (past the %s an RTSP client allows) -> %s",
			method, took.Round(time.Millisecond), rtspSlowCommand, responseLine)
	default:
		log.Printf("rtsp timing %s took %s -> %s", method, took.Round(time.Millisecond), responseLine)
	}
}

func copyRTSPMessage(dst io.Writer, src *bufio.Reader) (string, error) {
	startLine, err := readRTSPLine(src)
	if err != nil {
		return "", err
	}
	headerBytes := len(startLine)
	if err := writeAll(dst, []byte(startLine)); err != nil {
		return "", err
	}
	contentLength := int64(0)
	contentLengthSeen := false

	for {
		line, err := readRTSPLine(src)
		if err != nil {
			return "", err
		}
		headerBytes += len(line)
		if headerBytes > maxRTSPHeaderBytes {
			return "", errors.New("RTSP header exceeds 64 KiB")
		}
		if err := writeAll(dst, []byte(line)); err != nil {
			return "", err
		}
		if line == "\r\n" || line == "\n" {
			break
		}

		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			if contentLengthSeen {
				return "", errors.New("duplicate RTSP Content-Length")
			}
			contentLengthSeen = true
			contentLength, err = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil || contentLength < 0 {
				return "", fmt.Errorf("invalid RTSP Content-Length %q", strings.TrimSpace(value))
			}
		}
	}

	if contentLength > 0 {
		if contentLength > maxRTSPBodyBytes {
			return "", errors.New("RTSP body exceeds 1 MiB")
		}
		if _, err := io.CopyN(dst, src, contentLength); err != nil {
			return "", fmt.Errorf("copy RTSP body: %w", err)
		}
	}
	return strings.TrimSpace(startLine), nil
}

func validRTSPRequest(requestLine string) bool {
	fields := strings.Fields(requestLine)
	return len(fields) == 3 && fields[0] != "" && fields[1] != "" && fields[2] == "RTSP/1.0"
}

func readRTSPLine(src *bufio.Reader) (string, error) {
	line, err := src.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errors.New("RTSP header line exceeds 64 KiB")
	}
	if err != nil {
		return "", err
	}
	return string(line), nil
}

func writeAll(dst io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if err != nil {
			return fmt.Errorf("write RTSP data: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func negotiationFinished(requestLine, responseLine string) bool {
	request := strings.Fields(requestLine)
	response := strings.Fields(responseLine)
	if len(request) == 0 || len(response) < 2 {
		return false
	}
	method := strings.ToUpper(request[0])
	return (method == "PLAY" || method == "RECORD") && strings.HasPrefix(response[1], "2")
}

func copyBoth(upstream net.Conn, upstreamReader io.Reader, device net.Conn, deviceReader io.Reader) error {
	errors := make(chan error, 2)
	go func() {
		_, err := io.Copy(device, upstreamReader)
		errors <- err
	}()
	go func() {
		_, err := io.Copy(upstream, deviceReader)
		errors <- err
	}()

	err := <-errors
	closeConn(upstream)
	closeConn(device)
	return err
}

func closeConn(conn net.Conn) {
	// Closing is used to unblock the opposite io.Copy. There is no useful
	// recovery if the peer has already closed the connection.
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("close RTSP connection: %v", err)
	}
}
