# xboard-node

Node backend for [Xboard](https://github.com/cedar2025/Xboard). Supports `sing-box` / `xray-core` dual kernels.

> **Disclaimer**: This project is for educational and learning purposes only.

## Features

- Protocols: V2Ray family, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, Mieru, Sudoku, NW3
- Sync: WebSocket push + REST polling dual channel
- User controls: speed limit, device limit, alive-IP tracking, hot update
- Deploy modes: node mode, machine mode, standalone mode
- Multi-instance: single process binding multiple panels / nodes

## Install

### Docker

```bash
docker run -d --restart=always --network=host \
  -e apiHost=https://panel.com -e apiKey=TOKEN -e nodeID=1 \
  ghcr.io/cedar2025/xboard-node:latest
```

### Docker Compose

```bash
git clone -b compose --depth 1 https://github.com/cedar2025/xboard-node.git
cd xboard-node
vim config/config.yml   # set panel.url / token / node_id
docker compose up -d
```

### Installer (Linux systemd / Alpine OpenRC)

```bash
# Node mode
curl -fsSL https://raw.githubusercontent.com/luckapi/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode node --panel https://panel.example.com --token TOKEN --node-id 1

# Machine mode
curl -fsSL https://raw.githubusercontent.com/luckapi/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode machine --panel https://panel.example.com --token TOKEN --machine-id 1
```

The installer uses systemd on Debian/Ubuntu/RHEL-family hosts and OpenRC on Alpine.

## Build From Source

Use Go 1.27.4 or newer and install `patch` (`apk add patch` on Alpine).

```bash
make deps
make test
make build-all
```

`make deps` downloads the official versions pinned in
`scripts/kernel-versions.json`, verifies them through Go module checksums, and
applies `scripts/kernel-patches/*.patch` into the ignored `third_party/`
directory. Run it before using `go test`, `go build`, or `go mod tidy` directly.
The build targets prepare these dependencies automatically.

The current baselines are sing-box 1.14.4 and Xray 26.11.9 (commit
`676eaf66f8f05d4d558ee7a74b4736623d3feeb9`), with Mieru 3.39.0 and AnyTLS
0.0.13. The compatibility patches retain Mieru inbound support, user hot
updates, routing reloads, and Xray per-user bandwidth limits. The downloaded
kernels retain their upstream licenses.

NW3 supports TLS 1.3, QUIC, Morph, multiple users, and per-user traffic
accounting. See [NW3 configuration and compatibility](docs-nw3.md).

Sudoku uses the official SUDOKU-ASCII 0.5.2-1 handshake, TCP, native stream
multiplexing and UDP-over-TCP, with independent per-user credentials, live user
updates and payload accounting. See [Sudoku configuration and limits](docs-sudoku.md).

Traffic batches are only used if an authenticated panel advertises
`traffic_batch_dedup` during its handshake. Otherwise the node retains the
legacy report format and retry behavior. A node-only upgrade does not enable
deduplication on an existing panel.

## xbctl

Run `xbctl` after installation for help. Common commands:

```bash
xbctl list                          # list all instances
xbctl status                        # running status
xbctl bind add-node --panel URL --token TOKEN --node-id 1
xbctl bind add-machine --panel URL --token TOKEN --machine-id 1
xbctl bind remove-node --panel URL --node-id 1
xbctl service restart
```

## Configuration

Legacy single-panel config is fully compatible. Appending bindings auto-migrates to `instances` format. See `config.yml.example`.

## Extensions

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## License

MPL-2.0.
