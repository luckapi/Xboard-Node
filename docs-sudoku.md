# Sudoku Node Support

The sing-box backend embeds [SUDOKU-ASCII/sudoku](https://github.com/SUDOKU-ASCII/sudoku)
v0.5.2-1 (commit `b1d1f0e767653d2c70e2ff814a01264c7dedf1f4`).
This is NOT Xray's incompatible, same-named protocol. The pinned module,
checksum and small embedding patch are managed by `make deps`, just like NW3.
Upstream source and its license notices remain in the generated module.

## Supported Modes

- Native encrypted TCP, native TCP stream multiplexing, and UDP-over-TCP (UoT).
- ChaCha20-Poly1305 (default) or AES-128-GCM; unencrypted `none` is rejected.
- Official ASCII/directional layouts, custom table rotation, padding and pure
  or packed downlink. Clients must use matching options.
- Independent user credentials, live whitelist replacement and revocation.
- Existing sing-box routing, domain sniffing, audit, rate/device limit and
  traffic tracking paths. Each UDP destination gets its own routed flow.

HTTPMask/CDN stream/poll/WebSocket transports, reverse publishing and native UDP
transport are not implemented in this integration. Configure clients to use
native TCP with HTTPMask disabled. This server does not open a public UDP port;
clients may still forward UDP traffic through UoT. Sudoku's native AEAD provides
encryption; an Xboard TLS certificate is not required for this inbound.

## Local Configuration

```yaml
kernel:
  type: singbox
standalone:
  enabled: true
  node:
    protocol: sudoku
    server_port: 2080
    network: tcp
    network_settings:
      aead: chacha20-poly1305
      ascii: prefer_entropy
      padding_min: 0
      padding_max: 0
      enable_pure_downlink: false
  users:
    - id: 1
      uuid: aaaaaaaa-1111-2222-3333-444444444444
```

Replace the example UUID with a random, secret UUID. Neither this UUID nor its
derived private key belongs in public logs or public subscription URLs.
`custom_tables` is an optional array in `network_settings`, using official X/P/V
layout patterns. Omitted `ascii` defaults to `prefer_entropy`.

## User Keys and Provisioning

Do not give every subscriber a split of one shared master key. This integration
selects an independently keyed native handshake for each user and additionally
checks its user hash. Merely supplying another user's hash under one's own key
does not authorize or bill that other user.

Generate native client provisioning data using the matching xbctl build:

```sh
printf '%s\n' 'YOUR-SECRET-USER-UUID' | xbctl sudoku-key
```

The JSON output contains `private_key`, `public_key` and `user_hash`.
Configure the official client with `private_key` in its `key` field, native TCP,
HTTPMask disabled, and the matching AEAD/appearance options. `public_key` is the
per-user native server seed; it is NOT a universal node credential. Keep it
private too: this protocol uses it in its shared appearance/record layers.

The stable mapping, for panel/subscription implementers, is:

1. Parse the UUID to its 16 bytes (case and hyphens do not change the value).
2. SHA-512 the ASCII bytes `xboard-sudoku-user-v1`, one NUL byte, then UUID bytes.
3. Reduce all 64 digest bytes using Edwards25519 `SetUniformBytes` (little-endian
   scalar reduction modulo the group order), not an Ed25519 signing-seed API.
4. Encode the canonical 32-byte scalar as lowercase hex: client `private_key`.
5. Encode scalar times the Edwards25519 base point as lowercase hex: `public_key`.
6. `user_hash` is lowercase hex of the first 8 bytes of SHA-256(private scalar bytes).

Existing user IDs remain the billing IDs; UUID remains the tracker identity.
An empty whitelist denies everyone. Failed user updates leave existing
credentials unchanged; deleting/rotating a credential closes that user's active
sessions but does not disconnect unchanged users. Unchanged tables are reused.

## Panel Integration

The panel must support `protocol: sudoku`, `network: tcp`, the appearance options
above, and the exact credential mapping when generating subscriptions. This
repository does not add the panel's editor or client subscription format.
An ordinary client without Sudoku support cannot use this node. Legacy clients
using older handshakes have not been certified by these tests.

## Accounting and Resources

Traffic is counted once by the existing tracker after decryption and stream/UoT
decapsulation. Native handshakes, crypto/appearance overhead, multiplex headers,
UoT addresses and frame lengths are not billed. Rejected identities and requests
rejected by route rules are not counted as routed payload. TCP/UDP payloads use
the same accounting semantics as other node protocols, not Sudoku's separate
wire-byte monthly-quota system.

Limits: 1024 physical connections, 32 concurrent handshakes, 4096 routed flows
per inbound, 32 native mux streams per session, 256 KiB unread mux data per
stream, and 64 active UDP destinations per UoT session. UDP has no queued payload
backlog in the adapter. Handshake/setup/UDP idle reads are bounded at 5/10/120
seconds; UDP response writes are bounded at 10 seconds.

Independent appearance tables have a real memory cost. A local benchmark with
1000 users, default entropy layout, and packed downlink retained approximately
100 MiB in the user table alone and took about 5.4 seconds to initialize on the
development machine. This excludes kernel, connections, buffers and OS memory;
directional layouts can require two tables per user. These are measurements,
not server sizing guarantees. Do not assume a 128/256 MB server can safely host
thousands of Sudoku users. Test the actual user count and traffic before rollout.

## Verification

`make test` runs project race tests and the patched official codec/tunnel tests.
Integration tests use the official native dialer/codec, both AEADs, entropy and
directional layouts, both downlink modes, mux, UoT, exact multi-user byte totals,
revocation and spoofed identity rejection, and sniffed domain blocking.
These tests are not a claim of interoperability with every GUI client release.

```sh
go test ./internal/kernel/singbox/sudoku -run '^$' \
  -bench BenchmarkSudokuUserTable -benchtime=1x
```
