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
share that bridge and its P2P tunnel. The bridge establishes the P2P tunnel
before it opens the RTSP listener, so the first RTSP client does not pay the
cloud handshake cost. If the initial handshake fails, the process exits so the
container runtime can restart it.

It then keeps two tunnel reservations in hand and refills each one as a stream
takes it. A reservation on a tunnel that still has room costs nothing; the one
that finds every tunnel full pays the cloud handshake, and holding them in
advance moves that cost into the background. An RTSP client applies its own
deadline to its first response -- five seconds in go2rtc -- and everything the
bridge does to open a realm comes out of that budget before a byte reaches the
device.

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
When `DAHUA_P2P_PORT` is fixed, `DAHUA_MAX_CONNECTIONS` cannot exceed
`DAHUA_MAX_REALMS` because two tunnels cannot bind the same UDP port.

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
`0x13` heartbeat, `0x17`-`0x1B` handshake commands.

Two framing rules are load-bearing:

- **Every non-SYNC packet needs a unique PID.** The device dedupes on PID and
  silently discards repeats; when ACKs and heartbeats shared one, the device's
  view of our receive window froze and video stalled after 2-3s. PID is
  `0x0000FFFF - (count & 0xFFFF)`; the mask keeps the high half zero, which is
  how the device always sees it.
- **Send order must match LMID order.** `sendPacket` holds `sendMu` across both
  the counter update and the UDP write, because a packet arriving out of LMID
  order is dropped.

Payloads fragment at 1280 bytes, matching the official app and keeping the
datagram (24 + 12 + 1280) inside common MTUs.

## Measuring loss

Inbound headers carry the device's view of the conversation, so loss is
observable without a capture. `Tunnel.Stats` exposes it and the tunnel traces
it every 30s, idle tunnels included:

```
ptcp counters sent=23314 peer_recv=23302 out_unacked=12 out_msgs=179
              recv=124174150 peer_sent=124172858 in_skew=-1292 missed_hb=0 realms=7
```

`out_unacked` returns to 0 in a healthy tunnel; sustained growth while realms
are writing means the device has stopped consuming what we send. That is the
failure that precedes a tunnel refusing every BIND, and it is invisible to
inbound liveness checks because the device keeps sending packets of its own
throughout. The heartbeat loop watches the same signal and rebuilds the tunnel
after `outboundStallTimeout`.

The device only reports its `Recv` in packets it sends, so over a tunnel
nobody is writing to there is no fresh number to read and `peer_recv` simply
stops moving. That is not a stall, and treating it as one tore down tunnels
that were serving live realms, so the check also requires that a realm has
written something since the counter last moved. A tunnel that has gone
entirely silent is caught by `missed_hb` instead, which allows six times as
long. `in_skew` is normally slightly *negative* — the device's snapshot
predates packets we already consumed — and sustained growth is inbound loss.
`out_msgs` settles at a steady non-zero lag because the device advances `RMID`
more slowly than we emit coalesced ACKs.

Measured over 124 MB across 7 realms the device acknowledged every byte sent,
which is why no retransmission layer is implemented. Revisit if `out_unacked`
is seen climbing on some other network.
