# Custom Routes

## Quick Example

```json
{
  "custom_route_rules": [
    {
      "name": "direct-example",
      "match": {"domain_suffixes": ["example.com"]},
      "action": {"type": "direct"}
    },
    {
      "name": "block-ads",
      "match": {"domains": ["ads.example.com"]},
      "action": {"type": "block"}
    },
    {
      "name": "route-warp",
      "match": {"ip_cidrs": ["1.1.1.0/24"], "ports": ["80", "443"]},
      "action": {"type": "route", "target": "warp-out"}
    }
  ]
}
```

## Node-side Blocklist

The installer enables node-side audit by downloading
[`rules/blockList`](rules/blockList) from the repository to
`/etc/xboard-node/blockList` and configuring that local path. The node does not
fetch it from the network in this mode. Rules are not bundled into the binary.
The installer preserves existing nonempty local rules and, with a current
`xbctl`, honors previously configured custom sources or an explicit disable.

To opt in to the [remote blockList](https://sh.lefly.co/xiaoji/xbnode/kaifa/blockList),
add `--blocklist-url https://sh.lefly.co/xiaoji/xbnode/kaifa/blockList` to the
`install.sh` install command (requires an `xbctl` build with this flag; not
`upgrade`), or configure it directly:

```yaml
kernel:
  blocklist:
    url: "https://sh.lefly.co/xiaoji/xbnode/kaifa/blockList"
```

Set `path` alone to use only a local file, or set both `path` and `url` to
combine their rules.

```yaml
kernel:
  blocklist:
    path: "/etc/xboard-node/blockList"
```

Set `kernel.blocklist.enabled: false` to disable the audit rules. The list
is fetched when kernel configuration is built; editing the URL contents does
not by itself trigger a reload. If a remote source is unavailable, the node
logs the failure. Using a local file avoids this runtime dependency.

Each non-empty, non-comment line is converted to a `block` route. Lines with dots become domain suffix rules, CIDRs become IP rules, and single words become domain keyword rules.

## Match Conditions

| Condition | Description | Example |
|-----------|-------------|---------|
| `domain_keywords` | Keyword domain match | `["falundafa"]` |
| `domains` | Exact domain match | `["api.example.com"]` |
| `domain_suffixes` | Suffix match | `["example.com"]` |
| `ip_cidrs` | IP CIDR ranges | `["10.0.0.0/8"]` |
| `ports` | Port (single or range) | `["443", "8000-9000"]` |
| `networks` | Protocol | `["tcp"]` or `["udp"]` |
| `source_cidrs` | Source IP CIDR | `["192.168.1.0/24"]` |
| `source_ports` | Source port | `["1024-65535"]` |

## Action Types

| Action | Description |
|--------|-------------|
| `{"type": "direct"}` | Direct connection, bypass proxy |
| `{"type": "block"}` | Block connection |
| `{"type": "route", "target": "tag"}` | Route to specified outbound (by tag) |

## Application Order

1. Structured `custom_route_rules` (highest priority)
2. Node-side `kernel.blocklist`
3. Raw `custom_routes`
4. Built-in private IP block rules
5. Panel routes

## Kernel Compatibility

| Feature | Xray | Sing-box |
|---------|------|----------|
| All match conditions | ✅ | ✅ |
| Node-side blocklist | ✅ | ✅ |
| direct / block / route | ✅ | ✅ |

## Best Practices

- **Prefer** `custom_route_rules`: cross-kernel compatible, panel-managed
- **Use** `custom_routes` only: when native features are needed (e.g., load balancing)
