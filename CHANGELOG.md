# Changelog

## 1.1.0
- `dnslens serve`: local DNS server (UDP+TCP) with record overrides, wildcards, CNAME chasing,
  authoritative zones, blocklists (hosts/domain lists), caching forwarder with TTL decay, client ACL,
  UDP truncation, hot reload (`--watch`).
- `dnslens api`: HTTP API (JSON) for every tool, Prometheus `/probe` and `/metrics`, bearer-token auth,
  concurrency limit, named-resolver allow-list.
- Client accepts `IP#PORT` resolvers (e.g. `-r 127.0.0.1#5353`).

## 1.0.0
- Initial release: `query`, `trace`, `propagate`, `wait`, `bench`, `audit`, `dnssec`, `reverse`.
