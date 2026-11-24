# NW3 Node Support

The sing-box backend implements the [NW3 Core wire specification](https://github.com/NodePassProject/Nowhere-Protocol/blob/main/PROTOCOL.md).
It reuses the pinned nowhere-go wire codecs, UDP fragmentation/reassembly,
and Morph key derivation. Egress registration/chaining is not implemented.

Supported combinations:

| Carrier | TCP forwarding | UDP forwarding | Morph |
| --- | --- | --- | --- |
| TLS 1.3 | Dedicated TLS connection | Length-prefixed datagrams | Optional |
| QUIC v1 | Bidirectional streams | QUIC DATAGRAM with fragmentation | Optional |

ALPN is always `nw3`; 0-RTT is disabled. Morph defaults to enabled. Both
TCP and UDP listeners default to the node port. `network: tcp` enables TLS
only; `network: udp` enables QUIC only; `network: both` enables both.

## Local Configuration

```yaml
kernel:
  type: singbox
cert:
  cert_mode: self
standalone:
  enabled: true
  node:
    protocol: nw3
    server_port: 2077
    network: both
    network_settings:
      morph: true
    tls: 1
  users:
    - id: 1
      uuid: aaaaaaaa-1111-2222-3333-444444444444
```

Replace the example UUID with a randomly generated UUID. A user's NW3 Shared
Key is the UUID with hyphens removed and letters converted to lowercase:
the example becomes `aaaaaaaa111122223333444444444444`. The 32 ASCII text
bytes enter the protocol KDF directly, without hexadecimal decoding. Client
provisioning must use this exact key and the same Morph setting. Clients must
verify the certificate through a trusted CA or an independently verified pin;
the example self-signed certificate requires client trust/pinning setup.

## Panel Integration

The node accepts `protocol: nw3`, `network` and `network_settings.morph` from
the panel, and preserves UUID-to-user-ID attribution for existing traffic
reports. The Xboard panel and subscription generator must separately support
these fields and the NW3 Shared Key mapping. Upgrading this node does not add
NW3 menus or subscriptions to the panel.

User updates atomically replace credentials. Removing a user or changing
their key closes that identity's TLS/QUIC sessions without interrupting other
users. Existing cumulative statistics are retained by the node tracker.

## Accounting and Limits

The sing-box tracker counts routed TCP payload and complete UDP payload after
reassembly. Auth frames, TLS/QUIC overhead, Morph preludes, UDP framing, and
fragment headers are excluded. UDP queue reservations include empty datagrams
and are released on consumption/flow closure. The compatibility patch limits
queued payload to 4 MiB per QUIC session, independently of reassembly limits.

The inbound admits at most 1024 connections, 256 simultaneous authentication
attempts, and 4096 business flows. QUIC connection receive windows remain at
64 KiB before authentication and may grow to 4 MiB afterward. Handshake and
flow-setup reads are bounded by five and ten seconds respectively.

Morph follows Core section 12: TCP receivers consume the 64-byte prelude
without requiring the newer Nowhere application's authenticated-prelude
extension. TLS/QUIC exporter authentication still authorizes every connection.
Modern client preludes are accepted, but this server does not claim to enforce
the extension's additional replay-window policy.

NW3 waits for target setup before READY, so routing uses its declared target
domain/IP rather than waiting for application payload sniffing. Domain rules
cannot discover an additional SNI/Host name hidden behind an IP-only target.

## Build and Verification

Run `make deps` before direct Go commands; `make test` includes protocol
startup/hot-update tests, TLS/QUIC with Morph enabled/disabled, multi-user
accounting, UDP fragmentation, user revocation, and resource-bound tests.
All release builds require `with_quic`; the standard Makefile includes it.

Xray 26.11.9 no longer supports the Shadowsocks `none`/`plain` cipher. Select
a supported cipher or use a compatible sing-box inbound when migrating such
an existing node.
