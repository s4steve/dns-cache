# dns-cache

A caching-only DNS server written in Rust. It forwards queries to upstream resolvers, caches the answers, and can block domains. It has no zones and never answers authoritatively.

- **Views**: each client is assigned a view by its source IP/CIDR. Every view has its own upstreams, cache and blocklists.
- **Blocklists**: a listed domain, *and every subdomain of it*, gets an immediate `NXDOMAIN`. Nothing is sent upstream.
- **Upstreams**: plain UDP/TCP, DNS-over-TLS (DoT) or DNS-over-HTTPS (DoH).
- **DNSSEC validation**: answers that fail validation get `SERVFAIL`.
- **Hot reload**: on `SIGHUP` the server re-reads its config without dropping the cache.

It is built on [hickory-dns](https://github.com/hickory-dns/hickory-dns).

## Quick start (Docker)

```bash
git clone https://github.com/s4steve/dns-cache.git
cd dns-cache
cp config.example.toml config.toml     # then edit it
docker compose up -d --build
dig @127.0.0.1 example.com
```

The compose file publishes port 53 (UDP and TCP) on the host. It also mounts two things read-only:

| Host path | In container |
|---|---|
| `./config.toml` | `/etc/dns-cache/config.toml` |
| `./lists/` | `/etc/dns-cache/lists/` |

Logs go to stdout:

```bash
docker compose logs -f dns-cache
```

> **Port 53 already in use?** On Linux, `systemd-resolved` usually listens on `127.0.0.53:53`. Either disable its stub listener (`DNSStubListener=no` in `/etc/systemd/resolved.conf`), or change the published port in `docker-compose.yml`.

## Configuration

The config is TOML. [`config.example.toml`](config.example.toml) is a working example with comments. Any unknown key is an error, so typos are caught at startup or reload.

### Top level

| Key | Default | Meaning |
|---|---|---|
| `listen` | required | Addresses to serve on. UDP and TCP are both served on each one, e.g. `["0.0.0.0:53", "[::]:53"]`. Changing this needs a restart. |
| `poll_secs` | `30` | How often local blocklist files are checked for changes. |
| `refresh_secs` | `86400` | How often remote (`http://` / `https://`) blocklists are downloaded again. |

### `[[view]]`

Views are tried in the order they appear in the file, and the first one whose `match_clients` contains the client's IP is used. A client that matches no view gets `REFUSED`. To give everyone else a default, put a catch-all view (`["0.0.0.0/0", "::/0"]`) last.

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Used in logs, and to match views across reloads. |
| `match_clients` | required | List of CIDRs, e.g. `["192.168.1.0/24", "10.0.0.5/32"]`. |
| `upstreams` | required | One or more upstream resolvers (see below). |
| `dnssec` | `true` | Validate DNSSEC. Bogus answers become `SERVFAIL`. |
| `cache_size` | `8192` | Maximum number of cached responses for this view. |
| `blocklists` | `[]` | Local file paths and/or `http(s)://` URLs. All of them are merged. |

### Upstreams

```toml
upstreams = [
  { ip = "1.1.1.1", protocol = "tls",   tls_name = "cloudflare-dns.com" },  # DoT
  { ip = "9.9.9.9", protocol = "https", tls_name = "dns.quad9.net" },       # DoH
  { ip = "192.168.1.1" },                                                   # plain UDP, TCP fallback
]
```

| Key | Default | Meaning |
|---|---|---|
| `ip` | required | Upstream IP address. Hostnames are not accepted. |
| `protocol` | `udp` | `udp` (with TCP fallback), `tls` or `https`. |
| `port` | 53 / 853 / 443 | Defaults to the standard port for the protocol. |
| `tls_name` | | Certificate name. Required for `tls` and `https`. |
| `path` | `/dns-query` | DoH endpoint path. |

When a view has several upstreams, the server prefers whichever has been performing best (based on recent query statistics), and fails over to the others on errors. TLS certificates are checked against the Mozilla root store, which is built into the binary.

### Blocklists

Each file or URL can mix two formats:

```text
# plain: one domain per line
doubleclick.net
ads.example.com

# hosts format (e.g. StevenBlack, many Pi-hole lists)
0.0.0.0 tracker.example.org
```

- A listed domain blocks the domain itself and all of its subdomains. `example.com` blocks `a.b.example.com`, but not `notexample.com`.
- Comments start with `#`. Trailing dots and letter case are ignored.
- In hosts-format lines, names without a dot (such as `localhost`) and IP addresses are skipped.
- Local files are re-read when their modification time changes, checked every `poll_secs`. No restart is needed.
- URLs are downloaded again every `refresh_secs`. If a download fails, the last good copy is kept.
- Blocked queries are logged at `info` level with the view and client IP.

## Reloading

```bash
docker kill -s HUP dns-cache
```

A reload re-reads `config.toml` and rebuilds the views:

- **The cache is kept** for each view whose `name`, `upstreams`, `dnssec` and `cache_size` are unchanged. A view where any of those changed starts with an empty cache.
- Blocklists are loaded again, which includes downloading remote lists.
- If the new config is invalid, the error is logged and the old config keeps serving.
- A change to `listen` is logged as a warning and needs a restart.

## Logging

Logging is controlled with `RUST_LOG`, set in `docker-compose.yml`. The default is `info,hickory_server=warn`, which logs startup, reloads, blocked names and SERVFAILs. To log every query, use `RUST_LOG=info,hickory_server=info`.

## Views and Docker networking

The view is chosen by the client's source IP, so the container has to see each client's real address.

- **Docker Desktop (macOS/Windows):** NAT changes the source address. Queries from the host or LAN arrive from the VM gateway (e.g. `192.168.65.1`), so they all land in the same view.
- **Linux:** to see real client IPs, use `network_mode: host` instead of `ports:` in `docker-compose.yml`.

The compose file includes two test clients on the internal `172.30.0.0/24` network. They match the example `kids` and `default` views:

```bash
docker compose --profile test run --rm client-kids    dig @172.30.0.2 reddit.com   # NXDOMAIN
docker compose --profile test run --rm client-default dig @172.30.0.2 reddit.com   # NOERROR
```

## Running without Docker

```bash
cargo build --release
./target/release/dns-cache path/to/config.toml   # default: /etc/dns-cache/config.toml
```

Binding to port 53 needs root (or `CAP_NET_BIND_SERVICE`). For local testing, use a high port such as `127.0.0.1:5399`. Avoid 5353, which is used by mDNS.

## Tests

```bash
cargo test                   # blocklist parsing and matching
./tests/dnssec-check.sh      # needs docker + dig
```

`dnssec-check.sh` checks that dns-cache does its own DNSSEC validation. It starts an unbound container with validation turned off, so bogus answers reach dns-cache. It then checks that dns-cache returns `SERVFAIL` for them, while correctly signed zones still resolve.

## Not supported (yet)

- Serving DoT or DoH *to clients*. Clients use plain DNS on port 53.
- The AD (authenticated data) bit. Answers are validated, but the AD bit is never set in responses. RRSIGs are passed through to clients that set the DO bit, and stripped for all other clients.
- Metrics endpoint.
- Recursive resolution from the root servers. Lookups are always forwarded to the configured upstreams.
