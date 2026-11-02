# Changelog

## 1.0.3
- Web management UI (`dnslens serve --web`): dashboard with charts, query log, blocklist subscriptions
  (AdGuard / hosts / domain formats), custom rules, DNS rewrites, runtime settings, protection pause,
  diagnostics, account page. Dependency-free single-page app shipped in the wheel.
- Query log and statistics in SQLite with retention and client-IP anonymization.
- Allowlist support; rules remember which list matched; DNS rewrites take priority over blocklists.
- Secure by default: generated admin password, PBKDF2, session cookies, CSRF checks, login lockout, CSP, optional HTTPS.
- Fix: names without a trailing dot in record data (`CNAME target`, `MX 10 mail`) were treated as relative names.
- CI also runs on the `master` branch and smoke-tests the UI.

## 1.0.1
- `dnslens serve`: local DNS server (UDP+TCP) with record overrides, wildcards, CNAME chasing,
  authoritative zones, blocklists (hosts/domain lists), caching forwarder with TTL decay, client ACL,
  UDP truncation, hot reload (`--watch`).
- `dnslens api`: HTTP API (JSON) for every tool, Prometheus `/probe` and `/metrics`, bearer-token auth,
  concurrency limit, named-resolver allow-list.
- Client accepts `IP#PORT` resolvers (e.g. `-r 127.0.0.1#5353`).

## 1.0.0
- Initial release: `query`, `trace`, `propagate`, `wait`, `bench`, `audit`, `dnssec`, `reverse`.
