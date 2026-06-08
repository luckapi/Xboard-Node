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

For line-based lists such as [Rakau/blockList](https://github.com/Rakau/blockList), configure the node to load the raw `blockList` file:

```yaml
kernel:
  blocklist:
    url: "https://raw.githubusercontent.com/Rakau/blockList/main/blockList"
```

You can also download the file yourself and load it locally:

```yaml
kernel:
  blocklist:
    path: "/etc/xboard-node/blockList"
```

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
