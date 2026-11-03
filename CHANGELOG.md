# Changelog

## 1.0.4
- **Live dashboard**: per-second traffic chart, live query feed, real-time stat cards, queries/s indicator, pause/resume.
  Server-Sent Events with automatic polling fallback (`/api/live`, `/api/live/poll`).
- **Database storage** (optional, SQLAlchemy 2): `--db URL` / `DNSLENS_DB_URL` keeps config, blocklists and the query log in
  SQLite, PostgreSQL, MySQL or MariaDB; `--log-db` for the log only. Extras: `dnslens[sql]`, `[postgres]`, `[mysql]`.
- Several servers can share one database; configuration changes are picked up within 5 s.
- `dnslens db migrate` copies an existing data directory into a database.
- Settings page shows where data is stored. Query-log SQL is now portable (per-minute buckets); existing SQLite logs are upgraded in place.
- Fix: `/metrics` of `dnslens api` could lag one request behind.

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
