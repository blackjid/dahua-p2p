package dh

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/blackjid/dahua-p2p/ptcp"
)

// HandshakeResult contains the result of a successful P2P handshake
type HandshakeResult struct {
	Client   *UDPClient
	Session  *ptcp.Session
	RTSPPort uint32
}

// HandshakeOptions contains options for the P2P handshake
type HandshakeOptions struct {
	Serial  string
	Timeout time.Duration

	// Device authentication credentials (required for devices with per-device randsalt)
	DeviceUsername string
	DevicePassword string

	// P2PPort is the local UDP port for the device connection.
	// Use a fixed port with k8s hostPort to bypass pod-level NAT.
	// 0 means random ephemeral port (default).
	P2PPort int

	// Trace reports handshake progress. This package owns no logger, so the
	// caller wires it to one; while nil, nothing is formatted. Failures are
	// reported through the returned error, not here.
	Trace func(format string, v ...any)
}

// trace is the nil-safe accessor for the caller's Trace hook.
func (o HandshakeOptions) trace(format string, v ...any) {
	if o.Trace != nil {
		o.Trace(format, v...)
	}
}

// Handshake performs the full P2P handshake and returns a socket with an
// established PTCP session to the device.
//
// Steps 1-11 talk to Dahua's cloud (main server, P2P server, relay agent) to
// learn the device's public address and to obtain the auth sign. Step 12 then
// punches a hole directly to the device. Relaying media through Dahua's agent
// is deliberately not supported: it was measured as slower and less reliable
// than direct P2P, and a silent fallback to it hides a NAT change that the
// operator needs to know about.
//
// All UDP sockets opened here are closed on any error path via the deferred
// cleanup below. On success deviceClient is nilled out so the defer leaves the
// caller's socket alone.
func Handshake(opts HandshakeOptions) (result *HandshakeResult, err error) {
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}

	var mainClient, p2pClient, deviceClient *UDPClient
	defer func() {
		if err == nil {
			return
		}
		if mainClient != nil {
			mainClient.Close()
		}
		if p2pClient != nil {
			p2pClient.Close()
		}
		if deviceClient != nil {
			deviceClient.Close()
		}
	}()

	// Step 1: Connect to main server and get P2P server info
	mainClient, err = NewUDPClient(opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to create main client: %w", err)
	}

	if err = mainClient.Connect(MainServer, MainPort); err != nil {
		return nil, fmt.Errorf("failed to connect to main server: %w", err)
	}

	opts.trace("connected to main server %s:%d", MainServer, MainPort)

	// Probe P2P server
	if err = mainClient.Request("/probe/p2psrv", ""); err != nil {
		return nil, fmt.Errorf("failed to probe p2psrv: %w", err)
	}
	if _, err = mainClient.Read(); err != nil {
		return nil, fmt.Errorf("failed to read probe response: %w", err)
	}

	// Get P2P server for device
	if err = mainClient.Request(fmt.Sprintf("/online/p2psrv/%s", opts.Serial), ""); err != nil {
		return nil, fmt.Errorf("failed to get p2psrv: %w", err)
	}
	p2pResp, err := mainClient.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read p2psrv response: %w", err)
	}

	p2psrv, ok := p2pResp.Body["body/US"]
	if !ok {
		err = ErrDeviceNotFound
		return nil, err
	}

	opts.trace("P2P server %s", p2psrv)

	// Step 2: Connect to P2P server and probe device
	p2pHost, p2pPort, err := splitHostPort(p2psrv)
	if err != nil {
		return nil, fmt.Errorf("invalid P2P server address %q: %w", p2psrv, err)
	}

	p2pClient, err = NewUDPClient(opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to create p2p client: %w", err)
	}

	if err = p2pClient.Connect(p2pHost, p2pPort); err != nil {
		return nil, fmt.Errorf("failed to connect to p2p server: %w", err)
	}

	// Probe device
	if err = p2pClient.Request(fmt.Sprintf("/probe/device/%s", opts.Serial), ""); err != nil {
		return nil, fmt.Errorf("failed to probe device: %w", err)
	}
	if _, err = p2pClient.Read(); err != nil {
		return nil, fmt.Errorf("failed to read device probe response: %w", err)
	}

	// Query device info to get randsalt
	if err = p2pClient.Request(fmt.Sprintf("/info/device/%s", opts.Serial), ""); err != nil {
		return nil, fmt.Errorf("failed to request device info: %w", err)
	}
	infoResp, err := p2pClient.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read device info response: %w", err)
	}

	rtspPort := uint32(554)
	var randsalt string
	if infoField, ok := infoResp.Body["body/Info"]; ok && infoField != "" {
		deviceInfo, decErr := DecryptDeviceInfo(infoField)
		if decErr != nil {
			opts.trace("could not decrypt device info: %s", decErr)
		} else {
			randsalt = deviceInfo.RandSalt
			if deviceInfo.RTSPPort > 0 && deviceInfo.RTSPPort <= 65535 {
				rtspPort = uint32(deviceInfo.RTSPPort)
			}
			opts.trace("device info randsalt_present=%t rtspport=%d", randsalt != "", deviceInfo.RTSPPort)
		}
	}

	// Step 3: Get relay server info
	if err = mainClient.Request("/online/relay", ""); err != nil {
		return nil, fmt.Errorf("failed to get relay: %w", err)
	}
	relayResp, err := mainClient.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read relay response: %w", err)
	}

	relayAddr, ok := relayResp.Body["body/Address"]
	if !ok {
		err = ErrInvalidResponse
		return nil, err
	}

	opts.trace("relay server %s", relayAddr)

	// Step 4: Create device connection client and request P2P channel
	opts.trace("step 4: requesting P2P channel from device")
	deviceClient, err = NewUDPClientPort(opts.Timeout, opts.P2PPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create device client: %w", err)
	}

	if err = deviceClient.Connect(MainServer, MainPort); err != nil {
		return nil, fmt.Errorf("failed to connect device client: %w", err)
	}

	// Generate identify
	cid := RandomBytes(8)
	localAddr := fmt.Sprintf("127.0.0.1:%d", deviceClient.LocalPort())

	var deviceKey []byte
	var deviceNonce int

	needsAuth := opts.DeviceUsername != "" && opts.DevicePassword != "" && randsalt != ""

	if needsAuth {
		deviceKey = GetDeviceKey(opts.DeviceUsername, opts.DevicePassword, randsalt)
		deviceNonce = GetDeviceNonce()

		encAddr, encErr := EncryptAddr(deviceKey, deviceNonce, localAddr)
		if encErr != nil {
			err = fmt.Errorf("failed to encrypt address: %w", encErr)
			return nil, err
		}

		authXML := GetDeviceAuth(opts.DeviceUsername, deviceKey, deviceNonce, randsalt, encAddr)
		body := fmt.Sprintf("<body>%s<Identify>%s</Identify><IpEncrptV2>true</IpEncrptV2><LocalAddr>%s</LocalAddr><version>5.0.0</version></body>",
			authXML, formatIdentify(cid), encAddr)

		if err = deviceClient.Request(fmt.Sprintf("/device/%s/p2p-channel", opts.Serial), body); err != nil {
			return nil, fmt.Errorf("failed to request p2p channel: %w", err)
		}
	} else {
		body := fmt.Sprintf("<body><Identify>%s</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>%s</LocalAddr><version>5.0.0</version></body>",
			formatIdentify(cid), localAddr)

		if err = deviceClient.Request(fmt.Sprintf("/device/%s/p2p-channel", opts.Serial), body); err != nil {
			return nil, fmt.Errorf("failed to request p2p channel: %w", err)
		}
	}

	// Step 5: Connect to relay and get agent info
	opts.trace("step 5: connecting to relay %s for agent info", relayAddr)
	relayHost, relayPort, err := splitHostPort(relayAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid relay address %q: %w", relayAddr, err)
	}

	if err = p2pClient.Connect(relayHost, relayPort); err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}

	if err = p2pClient.Request("/relay/agent", ""); err != nil {
		return nil, fmt.Errorf("failed to request relay agent: %w", err)
	}
	agentResp, err := p2pClient.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read agent response: %w", err)
	}

	token, ok := agentResp.Body["body/Token"]
	if !ok {
		err = ErrInvalidResponse
		return nil, err
	}
	agentAddr, ok := agentResp.Body["body/Agent"]
	if !ok {
		err = ErrInvalidResponse
		return nil, err
	}

	opts.trace("agent info agent=%s", agentAddr)

	// Step 6: Connect to agent and start relay
	opts.trace("step 6: connecting to agent %s", agentAddr)
	agentHost, agentPort, err := splitHostPort(agentAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid agent address %q: %w", agentAddr, err)
	}

	if err = p2pClient.Connect(agentHost, agentPort); err != nil {
		return nil, fmt.Errorf("failed to connect to agent: %w", err)
	}

	opts.trace("step 6: starting relay")
	if err = p2pClient.Request(fmt.Sprintf("/relay/start/%s", token), "<body><Client>:0</Client></body>"); err != nil {
		return nil, fmt.Errorf("failed to start relay: %w", err)
	}
	if _, err = p2pClient.Read(); err != nil {
		return nil, fmt.Errorf("failed to read relay start response: %w", err)
	}

	// Step 7: Read P2P channel response from device
	opts.trace("step 7: reading P2P channel response from device")
	channelResp, err := deviceClient.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read p2p channel response: %w", err)
	}

	// Handle 100 Continue
	if channelResp.Code == 100 {
		channelResp, err = deviceClient.Read()
		if err != nil {
			return nil, fmt.Errorf("failed to read final p2p channel response: %w", err)
		}
	}

	if channelResp.Code >= 400 {
		if channelResp.Code == 403 {
			err = ErrAuthenticationFailed
			return nil, err
		}
		err = fmt.Errorf("p2p channel error: %s", channelResp.Status)
		return nil, err
	}

	deviceLAddr, ok := channelResp.Body["body/LocalAddr"]
	if !ok {
		err = ErrInvalidResponse
		return nil, err
	}

	// Decrypt local address if using authenticated mode
	if needsAuth {
		respNonceStr := channelResp.Body["body/Nonce"]
		if respNonceStr != "" {
			respNonce, _ := strconv.Atoi(respNonceStr)
			decAddr, decErr := DecryptAddr(deviceKey, respNonce, deviceLAddr)
			if decErr == nil {
				deviceLAddr = decAddr
			}
		}
	}

	devicePubAddr, ok := channelResp.Body["body/PubAddr"]
	if !ok {
		err = ErrInvalidResponse
		return nil, err
	}

	opts.trace("device address pub=%s local=%s", devicePubAddr, deviceLAddr)

	deviceHost, devicePort, err := splitHostPort(devicePubAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid device address %q: %w", devicePubAddr, err)
	}

	// Connect deviceClient to device public address
	opts.trace("step 8: connecting to device public address %s", devicePubAddr)
	if err = deviceClient.Connect(deviceHost, devicePort); err != nil {
		return nil, fmt.Errorf("failed to connect to device: %w", err)
	}

	// Step 8: Request relay channel
	opts.trace("step 9: requesting relay channel")
	if err = p2pClient.Connect(MainServer, MainPort); err != nil {
		return nil, fmt.Errorf("failed to reconnect to main server: %w", err)
	}

	var relayChannelBody string
	if needsAuth {
		respNonceStr := channelResp.Body["body/Nonce"]
		respNonce, _ := strconv.Atoi(respNonceStr)
		relayAuth := GetDeviceAuth(opts.DeviceUsername, deviceKey, respNonce, randsalt, "")
		relayChannelBody = fmt.Sprintf("<body>%s<agentAddr>%s</agentAddr></body>", relayAuth, agentAddr)
	} else {
		relayChannelBody = fmt.Sprintf("<body><agentAddr>%s</agentAddr></body>", agentAddr)
	}
	if err = p2pClient.Request(fmt.Sprintf("/device/%s/relay-channel", opts.Serial), relayChannelBody); err != nil {
		return nil, fmt.Errorf("failed to request relay channel: %w", err)
	}

	// Step 9: Connect to agent for PTCP session
	opts.trace("step 10: connecting to agent %s for PTCP", agentAddr)
	if err = p2pClient.Connect(agentHost, agentPort); err != nil {
		return nil, fmt.Errorf("failed to connect to agent for PTCP: %w", err)
	}

	// Read agent response (Server Nat Info)
	opts.trace("step 10: reading agent NAT info")
	_, err = p2pClient.ReadRaw(opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to read agent PTCP info: %w", err)
	}

	// Start PTCP session with agent
	agentSession := ptcp.NewSession()

	// Send PTCP SYNC to agent
	opts.trace("step 10: PTCP sync with agent")
	syncPacket := agentSession.Send(ptcp.NewSyncBody())
	if err = p2pClient.Send(syncPacket.Serialize()); err != nil {
		return nil, fmt.Errorf("failed to send PTCP sync to agent: %w", err)
	}

	// Read SYNC response
	syncResp, err := p2pClient.ReadRaw(opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to read PTCP sync response from agent: %w", err)
	}

	syncRespPacket, err := ptcp.ParsePacket(syncResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PTCP sync response: %w", err)
	}
	agentSession.Recv(syncRespPacket)

	opts.trace("PTCP session established with agent")

	// Step 11: Request sign from agent (command 0x17)
	opts.trace("step 11: requesting sign from agent")
	signRequestCmd := []byte{0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	signReqPacket := agentSession.Send(ptcp.NewCommandBody(signRequestCmd))
	if err = p2pClient.Send(signReqPacket.Serialize()); err != nil {
		return nil, fmt.Errorf("failed to send sign request: %w", err)
	}

	var sign []byte
	for i := 0; i < 5; i++ {
		signResp, readErr := p2pClient.ReadRaw(opts.Timeout)
		if readErr != nil {
			opts.trace("sign read timeout attempt=%d, resending request: %s", i+1, readErr)
			signReqPacket = agentSession.Send(ptcp.NewCommandBody(signRequestCmd))
			if sendErr := p2pClient.Send(signReqPacket.Serialize()); sendErr != nil {
				opts.trace("failed to resend sign request: %s", sendErr)
			}
			continue
		}
		signRespPacket, parseErr := ptcp.ParsePacket(signResp)
		if parseErr != nil {
			continue
		}
		agentSession.Recv(signRespPacket)

		if signRespPacket.Body.Type == ptcp.BodyTypeCommand && len(signRespPacket.Body.Command) > 12 {
			sign = signRespPacket.Body.Command[12:]
			break
		}
	}

	if sign == nil {
		err = fmt.Errorf("could not get sign from agent")
		return nil, err
	}

	opts.trace("got sign")

	// Step 12: punch a hole directly to the device.
	// mainClient and p2pClient have served their purpose (address discovery
	// and sign); close them now and nil the handles so the deferred cleanup
	// doesn't double-close.
	mainClient.Close()
	mainClient = nil
	p2pClient.Close()
	p2pClient = nil

	const directRetries = 3
	var session *ptcp.Session
	for attempt := 1; attempt <= directRetries; attempt++ {
		opts.trace("step 12: attempting direct connection attempt=%d", attempt)
		session, err = performDirectHandshake(deviceClient, cid, devicePubAddr, deviceLAddr, sign, opts)
		if err == nil {
			break
		}
		opts.trace("direct connection attempt %d/%d failed: %s", attempt, directRetries, err)
	}
	if err != nil {
		return nil, fmt.Errorf("direct P2P failed after %d attempts: %w", directRetries, err)
	}

	// Success: hand ownership of deviceClient to the caller.
	keptDeviceClient := deviceClient
	deviceClient = nil
	opts.trace("direct P2P connection established serial=%s", opts.Serial)
	return &HandshakeResult{Client: keptDeviceClient, Session: session, RTSPPort: rtspPort}, nil
}

// performDirectHandshake performs the STUN-like handshake and PTCP authentication with the device
func performDirectHandshake(client *UDPClient, cid []byte, devicePubAddr, deviceLAddr string, sign []byte, opts HandshakeOptions) (*ptcp.Session, error) {
	// Invert CID
	invertedCID := make([]byte, len(cid))
	for i, b := range cid {
		invertedCID[i] = ^b
	}

	// Generate cookie and transaction ID
	cookie := RandomBytes(4)
	transID := RandomBytes(12)

	// Build STUN request targeting the public address
	data := []byte{0xff, 0xfe, 0xff, 0xe7}
	data = append(data, cookie...)
	data = append(data, transID...)
	data = append(data, 0x7f, 0xd5, 0xff, 0xf7)
	data = append(data, invertedCID...)
	data = append(data, 0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe)
	encodedAddr, err := ipToBytes(devicePubAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid device public address %q: %w", devicePubAddr, err)
	}
	data = append(data, encodedAddr...)

	opts.trace("sending STUN request to device pub=%s local=%s", devicePubAddr, deviceLAddr)

	if err := client.Send(data); err != nil {
		return nil, fmt.Errorf("failed to send STUN request: %w", err)
	}

	// Also send to the device's local/LAN address for same-network cameras.
	// Only these two addresses are allowed to answer the hole-punch request.
	var localAddr *net.UDPAddr
	if deviceLAddr != devicePubAddr && deviceLAddr != "" {
		localAddr, err = net.ResolveUDPAddr("udp", deviceLAddr)
		if err == nil {
			_ = client.SendTo(data, localAddr)
		}
	}

	// Read the first response from the expected public or local device address.
	deadline := time.Now().Add(8 * time.Second)
	var resp []byte
	var respAddr *net.UDPAddr
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("timeout waiting for device response (try relay mode): %w", ErrTimeout)
		}
		resp, respAddr, err = client.RecvFrom(remaining)
		if err != nil {
			return nil, fmt.Errorf("timeout waiting for device response (try relay mode): %w", ErrTimeout)
		}
		if sameUDPAddr(respAddr, client.raddr) || sameUDPAddr(respAddr, localAddr) {
			break
		}
	}

	// Reconnect to the address that actually responded
	if respAddr != nil {
		client.Connect(respAddr.IP.String(), respAddr.Port)
		opts.trace("STUN response from %s", respAddr)
	}

	if len(resp) < 20 {
		return nil, ErrInvalidResponse
	}

	// Extract remote transaction ID
	rtransID := resp[8:20]

	// Send STUN confirmation (magic 0xfefefff3, no trailing address)
	data2 := []byte{0xfe, 0xfe, 0xff, 0xf3}
	data2 = append(data2, cookie...)
	data2 = append(data2, rtransID...)
	data2 = append(data2, 0x7f, 0xd6, 0xff, 0xf7)
	data2 = append(data2, invertedCID...)

	if err := client.Send(data2); err != nil {
		return nil, fmt.Errorf("failed to send STUN confirmation: %w", err)
	}

	// Drain remaining STUN handshake packets (arrive within ~250ms)
	for i := 0; i < 5; i++ {
		_, err := client.ReadRaw(500 * time.Millisecond)
		if err != nil {
			break
		}
	}

	// Now perform PTCP handshake
	session := ptcp.NewSession()

	// Send SYNC
	syncPacket := session.Send(ptcp.NewSyncBody())
	if err := client.Send(syncPacket.Serialize()); err != nil {
		return nil, fmt.Errorf("failed to send PTCP sync: %w", err)
	}

	// Read SYNC response
	syncResp, err := client.ReadRaw(opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to read PTCP sync response: %w", err)
	}

	packet, err := ptcp.ParsePacket(syncResp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PTCP sync response: %w", err)
	}
	session.Recv(packet)

	if packet.Body.Type != ptcp.BodyTypeSync {
		return nil, errors.New("expected SYNC response")
	}

	// Send authentication with sign (command 0x19)
	authCmd := []byte{0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	authCmd = append(authCmd, sign...)
	authPacket := session.Send(ptcp.NewCommandBody(authCmd))
	if err := client.Send(authPacket.Serialize()); err != nil {
		return nil, fmt.Errorf("failed to send auth: %w", err)
	}

	// Read auth response, skipping empty (ACK) packets. The device answers a
	// 0x19 with 0x1A; if it never does, the session is unauthenticated and
	// every later BIND would silently time out, so fail here instead.
	var authOK bool
	for i := 0; i < 5 && !authOK; i++ {
		authResp, readErr := client.ReadRaw(opts.Timeout)
		if readErr != nil {
			continue
		}
		authRespPacket, parseErr := ptcp.ParsePacket(authResp)
		if parseErr != nil {
			continue
		}
		session.Recv(authRespPacket)

		authOK = authRespPacket.Body.Type == ptcp.BodyTypeCommand &&
			len(authRespPacket.Body.Command) > 0 &&
			authRespPacket.Body.Command[0] == 0x1A
	}
	if !authOK {
		return nil, fmt.Errorf("device did not acknowledge auth: %w", ErrAuthenticationFailed)
	}

	// Send final acknowledgment (command 0x1B)
	ackCmd := []byte{0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	ackPacket := session.Send(ptcp.NewCommandBody(ackCmd))
	if err := client.Send(ackPacket.Serialize()); err != nil {
		return nil, fmt.Errorf("failed to send ack: %w", err)
	}

	// Read final ack response and update session state so recv/rmid
	// counters stay in sync with the device (critical for subsequent packets)
	if ackResp, err := client.ReadRaw(opts.Timeout); err == nil {
		if ackRespPacket, err := ptcp.ParsePacket(ackResp); err == nil {
			session.Recv(ackRespPacket)
		}
	}

	// Drain any additional pending packets the device sent during the handshake
	for i := 0; i < 3; i++ {
		extra, err := client.ReadRaw(500 * time.Millisecond)
		if err != nil {
			break
		}
		if pkt, err := ptcp.ParsePacket(extra); err == nil {
			session.Recv(pkt)
		}
	}

	opts.trace("PTCP session established with device")

	return session, nil
}
