# Dahua P2P

Reverse-engineered implementation of the P2P transport Dahua/KBVision devices
use to reach the easy4ip cloud, carrying an ordinary RTSP session over a
NAT-punched UDP socket.

```
dh/      cloud protocol: UDP client, DH-HTTP, WSSE auth, device crypto, handshake
ptcp/    PTCP packet framing and session counters
tunnel/  TCP-over-PTCP realms, exposed as net.Conn
```

This module owns no logger. Callers may wire `Config.Trace` and `Config.Error`
to their logger; while nil, nothing is formatted.

## Install

```sh
go get github.com/blackjid/dahua-p2p
```

The root package performs the handshake, shares tunnels, and exposes each
device realm as a standard `net.Conn`. The `dh`, `ptcp`, and `tunnel`
subpackages expose the lower protocol layers for diagnostics and research.

## RTSP bridge

The included `cmd/dahua-p2p` executable exposes a device's RTSP port locally
for any standard RTSP client. It carries RTSP and interleaved RTP over the P2P
tunnel. The consuming client must use TCP transport; UDP media cannot cross
this TCP bridge.

```sh
docker network create cameras
docker run --rm --name dahua-p2p --network cameras -p 8554:8554 \
  -e DAHUA_SERIAL=YOUR_SERIAL \
  -e DAHUA_USERNAME=admin \
  -e DAHUA_PASSWORD=secret \
  ghcr.io/blackjid/dahua-p2p:latest
```

For example, an unmodified upstream go2rtc can consume the bridge as an
ordinary RTSP source:

```yaml
streams:
  camera:
    - rtsp://admin:secret@dahua-p2p:8554/cam/realmonitor?channel=1&subtype=0#transport=tcp
```

Run one bridge per Dahua device or NVR. Different channels and subtypes can
share that bridge and its P2P tunnel. The bridge establishes and owns one P2P
tunnel before it opens the RTSP listener, so the first RTSP client does not pay
the cloud handshake cost. If the handshake fails or the tunnel later dies, the
bridge reconnects with a capped backoff. The process exits only on shutdown, so
it behaves the same under Docker, Docker Compose, systemd, and Kubernetes.

| Environment | Flag | Default | Purpose |
|---|---|---:|---|
| `DAHUA_SERIAL` | `-serial` | required | Device serial registered with easy4ip |
| `DAHUA_USERNAME` | `-username` | empty | Device username |
| `DAHUA_PASSWORD` | — | empty | Device password |
| `DAHUA_PASSWORD_FILE` | — | empty | File containing the device password |
| `LISTEN_ADDR` | `-listen` | `:8554` | RTSP TCP listen address |
| `DAHUA_P2P_PORT` | `-p2p-port` | `0` | Fixed local UDP port; `0` chooses one |
| `DAHUA_MAX_REALMS` | `-max-realms` | `8` | Connections per shared P2P tunnel |
| `DAHUA_MAX_CONNECTIONS` | `-max-connections` | `32` | Total concurrent RTSP clients |

Use `-debug` to print protocol traces.
The bridge owns one tunnel, so its effective connection limit is the lower of
`DAHUA_MAX_CONNECTIONS` and `DAHUA_MAX_REALMS`.

## Handshake

Four parties: this client, Dahua's main server, a relay agent, and the device.

| Step | Request | To | Purpose |
|---|---|---|---|
| 1 | `DHGET /probe/p2psrv` | `easy4ipcloud.com:8800` | discover infrastructure |
| 2 | `DHGET /online/p2psrv/{serial}` | main server | P2P server for this device |
| 3 | `DHGET /probe/device/{serial}` | P2P server | confirm device online |
| 4 | `DHGET /info/device/{serial}` | P2P server | encrypted info (randsalt, RTSP port) |
| 5 | `DHPOST /device/{serial}/p2p-channel` | main server | request channel, AES-encrypted local address |
| 6 | `DHGET /relay/agent` | relay server | agent address and token |
| 7 | `DHGET /relay/start/{token}` | agent | start agent session |
| 8 | read step 5 response | main server | device public and local addresses |
| 9 | `DHPOST /device/{serial}/relay-channel` | main server | authorize the agent |
| 10 | PTCP SYNC | agent | establish agent session |
| 11 | command `0x17` | agent | obtain the **sign** |
| 12 | STUN-like exchange, SYNC, `0x19`/`0x1A`/`0x1B` | device | hole punch and authenticate |

Steps 6-11 exist only to obtain the sign; media never flows through the agent.
Step 12 is attempted 3 times, against the device's public and LAN addresses
simultaneously so a camera on the same network connects directly.

Relaying media through the agent is deliberately unsupported: it measured
slower and less reliable than direct P2P, and a silent fallback would hide a
NAT change the operator needs to see.

Devices with a per-device `randsalt` (all recent firmware) require
`key = MD5("user:Login to {randsalt}:pass")` uppercase, addresses encrypted
AES-OFB under `PBKDF2-SHA256(key, nonce, 20000)`, and each request signed with
`HMAC-SHA256(key, nonce ‖ date ‖ payload)`. Without valid credentials the
device answers the p2p-channel request with 403.

## PTCP

PTCP ("phony TCP") multiplexes connections over one UDP socket as *realms*.

```
┌──────────────────── Header (24 bytes) ─────────────────────┐
│ "PTCP" │ Sent(4) │ Recv(4) │ PID(4) │ LMID(4) │ RMID(4)    │
├──────────────────── Body (variable) ───────────────────────┤
│ Type(1) │ Length(3) │ Realm(4) │ Padding(4) │ Data(N)      │
└────────────────────────────────────────────────────────────┘
```

`0x00` SYNC, `0x10` payload, `0x11` BIND, `0x12` status (`CONN`/`DISC`),
`0x13` heartbeat, `0x17`-`0x1B` handshake commands. The status body's length
field stays zero even though `CONN`/`DISC` follows it; the trailer is found by
position.

Neither ID field in the header is an identifier. Both were originally modelled
as counters, which is wrong in a way that degrades slowly, so a capture of the
DMSS app decides them:

- **LMID is a millisecond clock**, quantized to 10ms. Over 15.7s it advances at
  exactly 1.000 units per millisecond in both directions, and 1573 of 2610
  consecutive packets repeat the previous value. Packets sent inside one tick
  share an LMID, so nothing may treat it as unique or as a sequence number.
  `Stats.OutLagMillis` reads the device's echo of it as a round-trip time.
- **PID is a receive-side byte count**, `0xFFFF` minus the bytes taken in since
  our previous transmission. It is not a dedup token: three BINDs for three
  different realms went out 10ms apart carrying `pid=63345` and the device
  granted all three, and the device used only 83 distinct values across 4776
  packets. Its value never strays more than ~4000 below `0xFFFF`. A decrementing
  packet counter leaves that band after a few thousand packets and wraps every
  65536, which is what froze the device's view of our receive window.

`sendPacket` still serializes the session-state read and the UDP write, so the
`Sent`/`Recv` a packet advertises are true of the moment it leaves.

Payloads fragment at 1280 bytes, matching the official app and keeping the
datagram (24 + 12 + 1280) inside common MTUs.

ACKs are header-only packets with no body. The app answers inbound data after
0.88ms at the median (5ms at p90), batching 2.55 packets per ACK; the
coalescing window here is 1ms, which lands on the same ratio because inbound
packets arrive 0.44ms apart at the median.

Realm setup is not paced. The same capture opens seventeen realms with three
or four BINDs in flight at once, each answered in 10-30ms, and tears all
seventeen down in 60ms. `Dial` is safe to call concurrently.

## Measuring loss

Inbound headers carry the device's view of the conversation, so loss is
observable without a capture. `Tunnel.Stats` exposes it and the tunnel traces
it every 30s while realms are active:

```
ptcp counters sent=23314 peer_recv=23302 out_unacked=12 out_lag_ms=179
              recv=124174150 peer_sent=124172858 in_skew=-1292 realms=7
```

`out_unacked` returns to 0 in a healthy tunnel; sustained growth means the
device has stopped consuming what we send. That is the failure that precedes
a tunnel refusing every BIND, and it is invisible to inbound liveness checks
because the device keeps sending packets of its own throughout. The heartbeat
loop watches the same signal and rebuilds the tunnel after
`outboundStallTimeout`. `in_skew` is normally slightly *negative* — the device's snapshot
predates packets we already consumed — and sustained growth is inbound loss.
`out_lag_ms` is our clock minus the last reading of it the device echoed back,
so it reads as a round trip; it keeps climbing while the tunnel is idle,
because the clock runs whether or not we send.

Measured over 124 MB across 7 realms the device acknowledged every byte sent,
which is why no retransmission layer is implemented. Revisit if `out_unacked`
is seen climbing on some other network.
