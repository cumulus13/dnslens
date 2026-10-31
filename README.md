# dnslens

Cross-platform DNS toolkit for developers and DevOps. One dependency (`dnspython`), pure Python, works on Windows, Linux and macOS (Python 3.9+).

```
pip install dnslens            # DoH support: pip install "dnslens[doh]"
```

| Command | Purpose |
|---|---|
| `query NAME [TYPE[,TYPE]]` | dig-like lookup, UDP/TCP/DoT/DoH, auto TCP fallback, `--short`, `--dnssec` |
| `trace NAME [TYPE]` | iterative resolution from the root servers, follows referrals and CNAMEs |
| `propagate NAME [TYPE]` | query 11 public resolvers in parallel, group answers, `--expect` a value |
| `wait NAME [TYPE]` | block until DNS reaches a state (`--expect`, `--subset`, `--absent`) - ideal for CI/CD |
| `bench` | latency stats (min/avg/median/p95/max, loss) per resolver, `--uncached` |
| `audit DOMAIN` | NS redundancy, lame delegation, SOA serial sync, apex CNAME, SPF (10-lookup limit), DMARC, DKIM, CAA, DNSSEC |
| `dnssec DOMAIN` | DS/DNSKEY match, DNSKEY RRSIG validity and expiry |
| `reverse IP` | PTR lookup |
| `serve` | local DNS server: overrides, wildcards, blocklists, caching forwarder (see below) |
| `api` | HTTP JSON API + Prometheus probes (see below) |

Every command supports `--json`, `-r NAME=ADDR` (repeatable), `-t/--timeout`, `--retries`, `--transport`, `-p/--port`, `--no-color`.

## Examples

```bash
dnslens query example.com MX,TXT -r 1.1.1.1
dnslens query example.com --transport tls -r cloudflare=1.1.1.1
dnslens trace www.example.com
dnslens propagate app.example.com A --expect 203.0.113.10
dnslens wait app.example.com CNAME --expect lb.example.net --max-wait 600 && ./deploy-next-step.sh
dnslens bench --uncached -n 20
dnslens audit example.com --dkim-selector google --dkim-selector selector1
dnslens dnssec example.com --json
```

## DNS server (`dnslens serve`)

Dev/staging overrides, CI mocks, split-horizon, ad/tracker blocking on a small network.

```bash
dnslens serve -c zone.json --watch --log-queries            # 127.0.0.1:5353, udp+tcp
dnslens serve --record "app.test A 10.0.0.5" --record "app.test TXT hello"
dnslens serve --host 0.0.0.0 --port 53 --blocklist hosts.txt --allow 192.168.0.0/16   # needs root/Administrator
dnslens query app.test -r 127.0.0.1#5353
```

`zone.json`:

```json
{
  "ttl": 300,
  "authoritative": ["dev.test."],
  "upstream": ["1.1.1.1", "9.9.9.9"],
  "block": ["ads.example.net"],
  "blocklists": ["hosts.txt"],
  "block_mode": "nxdomain",
  "records": {
    "app.dev.test.":   { "A": ["10.0.0.5", "10.0.0.6"], "TXT": "plain text, quoted for you",
                         "AAAA": { "ttl": 30, "data": ["fd00::5"] } },
    "*.svc.dev.test.": { "A": "10.1.1.1" },
    "www.dev.test.":   { "CNAME": "app.dev.test." }
  }
}
```

- Local records win; everything else is forwarded (cached, TTLs count down) unless `--no-forward`.
- `authoritative` zones answer NXDOMAIN for unknown names instead of forwarding. A CNAME to a non-local name is resolved through the upstream.
- Wildcards match at any depth. Blocking a domain also blocks its subdomains; `block_mode: "null"` answers `0.0.0.0` / `::`.
- Security: default bind is loopback. On any other address clients are limited to private ranges unless you pass `--allow`. AXFR/IXFR are refused. Not intended as an internet-facing resolver.
- Responses over the client's UDP size are truncated (TC) and served in full over TCP.
- Ports below 1024 need root/Administrator; on Linux you can use `setcap cap_net_bind_service`.

## HTTP API (`dnslens api`)

```bash
dnslens api --port 8053 --token "$TOKEN" -r internal=10.0.0.2
curl -H "Authorization: Bearer $TOKEN" "localhost:8053/propagate?name=app.example.com&expect=203.0.113.10"
```

| Endpoint | Parameters |
|---|---|
| `/query` | `name`, `type` (comma list), `resolver`, `dnssec`, `norecurse`, `transport`, `timeout`, `retries` |
| `/propagate` | `name`, `type`, `expect` (repeatable), `strict`, `resolver` (default: public set) |
| `/trace`, `/dnssec`, `/audit` | `name` or `domain`, `dkim_selector` (audit) |
| `/bench` | `domain`, `count` (max 50), `uncached`, `resolver` |
| `/reverse` | `ip` |
| `/probe` | `kind=query\|propagate\|audit\|dnssec` + the parameters above, returns Prometheus text |
| `/metrics`, `/healthz`, `/` | API metrics, liveness (always open), endpoint index |

`resolver` takes names (`google`, `cloudflare`, `quad9`, ..., `public`, `system`, or anything registered with `-r`). Arbitrary addresses are refused unless `--allow-custom-resolver` is set, so the API can't be used to send packets to arbitrary hosts. Requests beyond `--max-concurrent` get `503`. Without `--token` keep it on loopback.

Prometheus (blackbox-exporter style):

```yaml
scrape_configs:
  - job_name: dns-propagation
    metrics_path: /probe
    params: { kind: [propagate], name: [app.example.com], expect: ["203.0.113.10"] }
    authorization: { credentials: "<token>" }
    static_configs: [{ targets: ["localhost:8053"] }]
```

## Exit codes

`0` success / healthy, `1` check failed (inconsistent, mismatch, timeout, FAIL finding, no records), `2` usage error, `130` interrupted.

## Notes

- `propagate` reports INCONSISTENT for round-robin/GeoDNS records; use `--expect` there. Unreachable resolvers are ignored unless `--strict`.
- `dnssec` checks the zone against its parent DS and its own signatures; it does not walk the chain to the root.
- `NO_COLOR` is honoured.

## Development

```bash
pip install -e ".[dev]"
pytest && ruff check src tests && mypy src
```

Tests run against an in-process fake DNS server; no network needed.

## License

[MIT](LICENSE)


## 👤 Author
        
[Hadi Cahyadi](mailto:cumulus13@gmail.com)
    

[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/cumulus13)

[![Donate via Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cumulus13)
 
[Support me on Patreon](https://www.patreon.com/cumulus13)