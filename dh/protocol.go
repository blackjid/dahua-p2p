// Package dh implements the Dahua P2P protocol for camera connectivity.
package dh

import (
	cryptorand "crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Constants for the Dahua P2P service
const (
	MainServer = "www.easy4ipcloud.com"
	MainPort   = 8800

	// Authentication credentials (public API credentials)
	Username = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	UserKey  = "996103384cdf19179e19243e959bbf8b"

	// DefaultTimeout bounds each request/response exchange with the cloud.
	DefaultTimeout = 10 * time.Second
)

// Errors
var (
	ErrDeviceNotFound       = errors.New("device not found")
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrTimeout              = errors.New("connection timeout")
	ErrInvalidResponse      = errors.New("invalid response from server")
)

// Response represents a parsed DH HTTP response
type Response struct {
	Version string
	Code    int
	Status  string
	Headers map[string]string
	Body    map[string]string // Flattened XML body
}

// XMLBody is used for parsing the XML body
type XMLBody struct {
	XMLName xml.Name
	Content string `xml:",innerxml"`
}

// parseXMLBody parses XML body into a flattened map with paths as keys
func parseXMLBody(xmlStr string) map[string]string {
	result := make(map[string]string)

	decoder := xml.NewDecoder(strings.NewReader(xmlStr))
	var stack []string

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && len(stack) > 0 {
				key := strings.Join(stack, "/")
				result[key] = text
			}
		}
	}

	return result
}

// ParseResponse parses a DH HTTP response.
// Accepts both CRLF and LF line endings, since servers occasionally omit CR.
func ParseResponse(data string) (*Response, error) {
	// Normalize to CRLF so header/body separator handling is uniform.
	normalized := strings.ReplaceAll(strings.ReplaceAll(data, "\r\n", "\n"), "\n", "\r\n")
	parts := strings.SplitN(normalized, "\r\n\r\n", 2)
	if len(parts) < 2 {
		return nil, ErrInvalidResponse
	}

	head := parts[0]
	body := parts[1]

	lines := strings.Split(head, "\r\n")
	if len(lines) < 1 {
		return nil, ErrInvalidResponse
	}

	// Parse status line
	statusParts := strings.SplitN(lines[0], " ", 3)
	if len(statusParts) < 3 {
		return nil, ErrInvalidResponse
	}

	code, err := strconv.Atoi(statusParts[1])
	if err != nil {
		return nil, ErrInvalidResponse
	}

	// Parse headers
	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if idx := strings.Index(line, ": "); idx > 0 {
			headers[line[:idx]] = line[idx+2:]
		}
	}

	// Parse XML body if present
	var bodyMap map[string]string
	if strings.TrimSpace(body) != "" {
		bodyMap = parseXMLBody(body)
	}

	return &Response{
		Version: statusParts[0],
		Code:    code,
		Status:  statusParts[2],
		Headers: headers,
		Body:    bodyMap,
	}, nil
}

// UDPClient wraps a UDP connection with DH protocol methods
type UDPClient struct {
	conn    *net.UDPConn
	laddr   *net.UDPAddr
	raddr   *net.UDPAddr
	timeout time.Duration
	cseq    uint32
}

// NewUDPClient creates a new UDP client on a random port.
func NewUDPClient(timeout time.Duration) (*UDPClient, error) {
	return NewUDPClientPort(timeout, 0)
}

// NewUDPClientPort creates a new UDP client on a specific local port.
// Pass 0 for a random ephemeral port.
func NewUDPClientPort(timeout time.Duration, localPort int) (*UDPClient, error) {
	laddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", localPort))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}

	return &UDPClient{
		conn:    conn,
		laddr:   conn.LocalAddr().(*net.UDPAddr),
		timeout: timeout,
	}, nil
}

// LocalPort returns the local UDP port
func (c *UDPClient) LocalPort() int {
	return c.laddr.Port
}

// Connect sets the remote address
func (c *UDPClient) Connect(host string, port int) error {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	c.raddr = raddr
	return nil
}

// Close closes the UDP connection
func (c *UDPClient) Close() error {
	return c.conn.Close()
}

// Send sends raw data to the remote address
func (c *UDPClient) Send(data []byte) error {
	if c.raddr == nil {
		return errors.New("not connected")
	}
	_, err := c.conn.WriteToUDP(data, c.raddr)
	return err
}

// SendTo sends raw data to a specific address without changing the default raddr.
func (c *UDPClient) SendTo(data []byte, addr *net.UDPAddr) error {
	_, err := c.conn.WriteToUDP(data, addr)
	return err
}

// SetWriteDeadline sets the deadline for writes on the UDP socket.
func (c *UDPClient) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// RecvFrom receives data with timeout and returns the source address.
func (c *UDPClient) RecvFrom(timeout time.Duration) ([]byte, *net.UDPAddr, error) {
	if timeout > 0 {
		if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, nil, err
		}
		defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	}
	buf := make([]byte, 65535)
	n, addr, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}
	return buf[:n], addr, nil
}

// Recv receives data with timeout
func (c *UDPClient) Recv(timeout time.Duration) ([]byte, error) {
	if timeout > 0 {
		if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	}

	buf := make([]byte, 65535)
	for {
		n, addr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		if sameUDPAddr(addr, c.raddr) {
			return buf[:n], nil
		}
	}
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

// generateAuth generates WSSE authentication header.
// The nonce must be unpredictable to prevent replay of the signed digest,
// so it's drawn from crypto/rand rather than math/rand.
func generateAuth() string {
	nonceBytes := RandomBytes(4)
	nonce := binary.BigEndian.Uint32(nonceBytes)
	currDate := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	// Generate password digest: SHA1(nonce + date + "DHP2P:" + username + ":" + userkey)
	pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, currDate, Username, UserKey)
	hasher := sha1.New()
	hasher.Write([]byte(pwd))
	digest := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	return fmt.Sprintf("WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%d\", Created=\"%s\"",
		Username, digest, nonce, currDate)
}

// Request sends a DH HTTP request
func (c *UDPClient) Request(path string, body string) error {
	c.cseq++

	method := "DHGET"
	if body != "" {
		method = "DHPOST"
	}

	auth := generateAuth()

	req := fmt.Sprintf("%s %s HTTP/1.1\r\nCSeq: %d\r\nAuthorization: %s\r\n\r\n%s",
		method, path, c.cseq, auth, body)

	return c.Send([]byte(req))
}

// Read reads and parses a DH HTTP response
func (c *UDPClient) Read() (*Response, error) {
	data, err := c.Recv(c.timeout)
	if err != nil {
		return nil, err
	}
	return ParseResponse(string(data))
}

// ReadRaw reads raw data
func (c *UDPClient) ReadRaw(timeout time.Duration) ([]byte, error) {
	return c.Recv(timeout)
}

// splitHostPort validates a host:port address received from the P2P service.
func splitHostPort(address string) (string, int, error) {
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, ErrInvalidResponse
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, ErrInvalidResponse
	}
	return host, port, nil
}

// ipToBytes converts an IPv4 host:port to bytes with inversion.
func ipToBytes(address string) ([]byte, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, ErrInvalidResponse
	}

	result := make([]byte, 6)
	result[0] = byte(port >> 8)
	result[1] = byte(port)
	result[2] = ip[0]
	result[3] = ip[1]
	result[4] = ip[2]
	result[5] = ip[3]

	// Invert all bytes
	for i := range result {
		result[i] = ^result[i]
	}

	return result, nil
}

// RandomBytes generates cryptographically random bytes for protocol nonces
// and IDs that feed into HMAC authentication. crypto/rand.Read on current
// platforms does not fail in practice; we panic on error because a broken
// RNG indicates a fundamentally unhealthy system.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := cryptorand.Read(b); err != nil {
		panic(fmt.Errorf("crypto/rand failed: %w", err))
	}
	return b
}

// formatIdentify formats the identify bytes as fixed-width hex ("00 ff 1a 05")
// so the device sees consistent field widths regardless of byte value.
func formatIdentify(id []byte) string {
	parts := make([]string, len(id))
	for i, b := range id {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, " ")
}
