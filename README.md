<div align="center">

# dnslens

**A cross-platform DNS toolkit for developers and DevOps.**
Query, trace, propagation checks, benchmarks, health audits, DNSSEC checks, a local DNS server **with an AdGuard Home style web UI** (statistics, charts, query log, blocklists, DNS rewrites) and an HTTP/Prometheus API. One package, one dependency.

[![CI](https://github.com/cumulus13/dnslens/actions/workflows/ci.yml/badge.svg)](https://github.com/cumulus13/dnslens/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/dnslens)](https://pypi.org/project/dnslens/)
[![Python](https://img.shields.io/pypi/pyversions/dnslens)](https://pypi.org/project/dnslens/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-orange.svg)](LICENSE)
[![EULA](https://img.shields.io/badge/EULA-proprietary-lightgrey.svg)](EULA.md)

</div>

---

<p align="center">
  <a href="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot0.png" target="_blank">
    <img src="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot0.png" width="98%" alt="Screenshot 1">
  </a>
  <a href="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot1.png" target="_blank">
    <img src="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot1.png" width="98%" alt="Screenshot 1">
  </a>
  <a href="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot2.png" target="_blank">
    <img src="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot2.png" width="98%" alt="Screenshot 2">
  </a>
  <a href="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot3.png" target="_blank">
    <img src="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot3.png" width="98%" alt="Screenshot 3">
  </a>
  <a href="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot4.png" target="_blank">
    <img src="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot4.png" width="98%" alt="Screenshot 4">
  </a>
  <a href="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot5.png" target="_blank">
    <img src="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot5.png" width="98%" alt="Screenshot 5">
  </a>
  <a href="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot6.png" target="_blank">
    <img src="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot6.png" width="98%" alt="Screenshot 6">
  </a>
  <a href="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot7.png" target="_blank">
    <img src="https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/screenshot7.png" width="98%" alt="Screenshot 7">
  </a>
</p>


## Contents

- [Why dnslens](#why-dnslens)
- [Install](#install)
- [Quick start](#quick-start)
- [How it fits together](#how-it-fits-together)
- [Command reference](#command-reference)
  - [query](#query) · [trace](#trace) · [propagate](#propagate) · [wait](#wait) · [bench](#bench) · [audit](#audit) · [dnssec](#dnssec) · [reverse](#reverse)
- [DNS server: `dnslens serve`](#dns-server-dnslens-serve)
- [Web UI: `dnslens serve --web`](#web-ui-dnslens-serve---web)
  - [Live dashboard](#live-dashboard) · [Where data is stored](#where-data-is-stored) · [Database storage](#database-storage-sqlalchemy)
- [HTTP API: `dnslens api`](#http-api-dnslens-api)
- [Recipes](#recipes)
- [Use as a Python library](#use-as-a-python-library)
- [Output formats and exit codes](#output-formats-and-exit-codes)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Development and releasing](#development-and-releasing)
- [License](#license)

---

## Why dnslens

| You need to... | Use |
|---|---|
| look up records like `dig`, on Windows too, with JSON output | `dnslens query` |
| see exactly where a resolution breaks | `dnslens trace` |
| know whether a DNS change has reached the world | `dnslens propagate` |
| block a deploy pipeline until DNS is ready | `dnslens wait` |
| pick the fastest resolver | `dnslens bench` |
| check a domain's NS, SOA, mail auth, CAA and DNSSEC | `dnslens audit`, `dnslens dnssec` |
| override names for dev/staging/CI, or block ads on a LAN | `dnslens serve` |
| manage that server from a browser: stats, charts, query log, blocklists | `dnslens serve --web` |
| expose all of this to dashboards and Prometheus | `dnslens api` |

Design goals: **works the same on Windows, Linux and macOS**, scriptable (`--json`, meaningful exit codes), no native tools required (no `dig`, no `nslookup`), and safe defaults for the two server components.

## Install

```bash
pip install dnslens                 # Python 3.9+
pip install "dnslens[doh]"          # adds DNS-over-HTTPS (httpx)
pip install "dnslens[postgres]"     # store web UI data in PostgreSQL (SQLAlchemy + psycopg)
pip install "dnslens[mysql]"        # ... or MySQL / MariaDB (SQLAlchemy + PyMySQL)
pip install "dnslens[sql]"          # SQLAlchemy only (SQLite file via SQLAlchemy, or bring your own driver)
pipx install dnslens                # isolated CLI install
```

Check it works: `dnslens --version` or `python -m dnslens --version`.

## Quick start

```bash
dnslens query example.com MX                       # dig-like lookup via the OS resolver
dnslens query example.com A -r 1.1.1.1 --short     # only the data
dnslens propagate app.example.com --expect 203.0.113.10
dnslens audit example.com
dnslens serve --record "app.test A 10.0.0.5"       # local DNS server on 127.0.0.1:5353
dnslens serve --web                                # same, plus the web UI on http://127.0.0.1:8080
dnslens api --token secret                         # HTTP API on 127.0.0.1:8053
```

## How it fits together

Three front ends share the same tools. Every tool is built on a single query primitive (`core.query`) that talks to resolvers through `dnspython`.

```mermaid
flowchart LR
    subgraph FE["Front ends"]
        CLI["CLI<br/>dnslens ..."]
        HTTP["HTTP API<br/>dnslens api"]
        LIB["Python import<br/>from dnslens import ..."]
    end

    subgraph TOOLS["Tools"]
        QRY["query / reverse"]
        TRC["trace"]
        PRP["propagate / wait / bench"]
        AUD["audit"]
        SEC["dnssec"]
    end

    SRV["DNS server<br/>dnslens serve"]
    WEBUI["Web UI + query log<br/>dnslens serve --web"]
    CORE["core.query<br/>transport, retries, EDNS, TCP fallback"]

    subgraph NET["Network"]
        RES["Recursive resolvers<br/>system / public / custom"]
        AUTH["Authoritative servers"]
        ROOT["Root servers"]
    end

    CLI --> TOOLS
    HTTP --> TOOLS
    LIB --> TOOLS
    CLI --> SRV
    LIB --> SRV
    SRV --- WEBUI
    WEBUI --> TOOLS
    QRY --> CORE
    PRP --> CORE
    AUD --> CORE
    SEC --> CORE
    TRC --> CORE
    SRV -->|"forwards cache misses"| CORE
    CORE --> RES
    CORE --> AUTH
    TRC --> ROOT
```

[![How it fits together](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture1.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture1.jpg)

### How a single query travels

```mermaid
flowchart TD
    A["query(name, type, server, opts)"] --> B{"server given?"}
    B -- "no" --> C["use OS resolvers<br/>try each until one answers"]
    B -- "yes" --> D["use that server<br/>IP, hostname, IP#PORT or DoH URL"]
    C --> E{"transport"}
    D --> E
    E -- "udp" --> F["send over UDP with EDNS 1232"]
    E -- "tcp" --> G["send over TCP"]
    E -- "tls" --> H["DNS-over-TLS, port 853"]
    E -- "https" --> I["DNS-over-HTTPS"]
    F --> J{"truncated?"}
    J -- "yes" --> K["retry the same query over TCP"]
    J -- "no" --> L["parse response"]
    K --> L
    G --> L
    H --> L
    I --> L
    F -. "timeout" .-> M{"retries left?"}
    M -- "yes" --> F
    M -- "no" --> N["Answer with error=timeout"]
    L --> O["Answer: rcode, flags, records, elapsed ms"]
```

[![How a single query travels](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture2.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture2.jpg)

## Command reference

### Options shared by most commands

| Option | Default | Meaning |
|---|---|---|
| `-r, --resolver ADDR` | OS resolvers | Resolver IP, hostname, `IP#PORT` or DoH URL. `NAME=ADDR` gives it a label. Repeatable. |
| `--public` | off | Use the built-in public resolver set (11 resolvers). |
| `-t, --timeout SEC` | `3` | Per-query timeout. |
| `--retries N` | `1` | Retries on timeout. |
| `--transport` | `udp` | `udp` (auto TCP fallback), `tcp`, `tls`, `https`. |
| `-p, --port N` | by transport | Server port. |
| `--json` | off | Machine-readable output. |
| `--no-color` | off | Disable ANSI colour (`NO_COLOR` is also honoured). |

The built-in public set: Google (2), Cloudflare (2), Quad9, OpenDNS, AdGuard, CleanBrowsing, Verisign, DNS.WATCH, Yandex.

### query

dig-like lookup. Several types at once: `A,AAAA,MX`.

```text
$ dnslens query example.test A,MX -r 127.0.0.1#5401
;; example.test A @ 127.0.0.1#5401  NOERROR  [QR AA RD]  2.6 ms  udp
NAME           TTL  TYPE  DATA
-------------  ---  ----  ----------
example.test.  300  A     192.0.2.11
example.test.  300  A     192.0.2.10

;; example.test MX @ 127.0.0.1#5401  NOERROR  [QR AA RD]  1.4 ms  udp
NAME           TTL  TYPE  DATA
-------------  ---  ----  ---------------------
example.test.  300  MX    10 mail.example.test.
```

Extra options: `--short` (data only, ideal for scripts), `--dnssec` (set the DO bit), `--norecurse` (clear RD). Exit code is `1` for NXDOMAIN, errors, or no records.

### trace

Iterative resolution from the root servers, like `dig +trace`. Follows referrals, uses glue, resolves glueless nameservers, follows CNAMEs, detects referral loops.

```mermaid
flowchart TD
    S["start at the root servers"] --> Q["ask the current servers<br/>with RD off"]
    Q --> R{"response"}
    R -- "answer for the type" --> D["done: print records"]
    R -- "CNAME only" --> C["restart from the root<br/>for the CNAME target"]
    C --> Q
    R -- "referral: NS + glue" --> P{"zone is deeper<br/>than before?"}
    P -- "no" --> E["error: referral loop<br/>or lame delegation"]
    P -- "yes" --> G{"glue present?"}
    G -- "yes" --> N["use glue addresses"]
    G -- "no" --> L["resolve NS names<br/>with the system resolver"]
    N --> Q
    L --> Q
    R -- "no NS, no answer" --> X["done: NODATA or NXDOMAIN"]
    R -- "all servers timed out" --> F["error: no server answered"]
```

[![trace](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture3.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture3.jpg)

```bash
dnslens trace www.example.com
dnslens trace www.example.com AAAA --json
```

Each hop shows the zone, the server asked, the round-trip time and the outcome (`referral`, `cname`, `answer`, `nodata`, `nxdomain`, `error`).

### propagate

Queries many resolvers **in parallel** and groups identical answers. Defaults to the public set.

```mermaid
sequenceDiagram
    autonumber
    actor U as You
    participant C as dnslens
    participant P as Thread pool
    participant R1 as Resolver 1
    participant R2 as Resolver 2
    participant RN as Resolver N

    U->>C: propagate app.example.com A --expect 203.0.113.10
    C->>P: one task per resolver
    par in parallel
        P->>R1: A app.example.com?
        R1-->>P: 203.0.113.10
    and
        P->>R2: A app.example.com?
        R2-->>P: 203.0.113.10
    and
        P->>RN: A app.example.com?
        RN--xP: timeout
    end
    P-->>C: results
    C->>C: group answers, ignore unreachable resolvers
    C-->>U: table and verdict, exit code 0 or 1
```

[![propagate](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture4.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture4.jpg)

```text
$ dnslens propagate example.test A -r alpha=127.0.0.1#5401 -r beta=127.0.0.1#5402 --expect 192.0.2.10 --expect 192.0.2.11
RESOLVER  STATE  ANSWER                  TTL  TIME
--------  -----  ----------------------  ---  ----
alpha     OK     192.0.2.10, 192.0.2.11  300  3 ms
beta      OK     192.0.2.10, 192.0.2.11  300  3 ms

2/2 responding resolvers return the expected answer
```

| Option | Meaning |
|---|---|
| `--expect VALUE` | Expected record data (repeatable). The answer set must equal it. |
| `--strict` | Unreachable resolvers count as a failure (default: ignored). |

Success means: all responding resolvers agree (or match `--expect`). Round-robin and GeoDNS records legitimately differ between resolvers, so use `--expect` for those.

### wait

Blocks until DNS reaches a state, then exits `0`. Exits `1` on timeout. Progress goes to stderr, so stdout stays clean.

```mermaid
flowchart TD
    A["start timer"] --> B["query all selected resolvers"]
    B --> C{"every responding resolver<br/>satisfies the condition?"}
    C -- "yes" --> D["exit 0: condition met"]
    C -- "no" --> E{"elapsed + interval<br/>over max-wait?"}
    E -- "yes" --> F["exit 1: timed out"]
    E -- "no" --> G["sleep interval"]
    G --> B
```

[![wait](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture5.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture5.jpg)

```bash
dnslens wait app.example.com A --expect 203.0.113.10 --public --max-wait 600
dnslens wait old.example.com A --absent                       # wait until the record is gone
dnslens wait example.com TXT --expect "v=spf1 -all" --subset  # value must be present, others allowed
```

| Option | Default | Meaning |
|---|---|---|
| `--expect VALUE` | none | Wanted data. Without it, any non-empty answer satisfies. |
| `--subset` | off | Expected values only need to be included in the answer. |
| `--absent` | off | Wait until no records are returned. |
| `--interval SEC` | `5` | Poll interval. |
| `--max-wait SEC` | `300` | Give up after this long. |

### bench

Latency statistics per resolver, sorted by median.

```text
$ dnslens bench -r alpha=127.0.0.1#5401 -r beta=127.0.0.1#5402 -d example.test -n 20
RESOLVER  OK     LOSS  MIN  AVG  MEDIAN  P95  MAX  ERROR
--------  -----  ----  ---  ---  ------  ---  ---  -----
alpha     20/20  0%    0.6  1.3  1.2     1.9  3.5
beta      20/20  0%    0.6  1.2  1.2     2.0  2.2

times in ms, sorted by median
```

`-d/--domain` (repeatable, defaults to five popular domains), `-n/--count` (default 10), `--uncached` prepends a random label to each name so you measure real recursion instead of the resolver's cache (NXDOMAIN counts as answered).

### audit

A health check for one domain. Every finding has a level: `OK`, `INFO`, `WARN` or `FAIL`. The exit code is `1` if any `FAIL` is present.

```mermaid
flowchart TD
    A["audit example.com"] --> B["NS records"]
    B --> B1{"exists?"}
    B1 -- "NXDOMAIN" --> Z["FAIL: domain does not exist"]
    B1 -- "yes" --> C["resolve each NS to A / AAAA"]
    C --> D["ask every NS address directly<br/>SOA with RD off"]
    D --> D1{"reachable?"}
    D1 -- "no" --> D2["FAIL for IPv4, WARN for IPv6"]
    D1 -- "yes" --> D3{"AA flag set?"}
    D3 -- "no" --> D4["FAIL: lame delegation"]
    D3 -- "yes" --> D5["compare SOA serials"]
    D5 --> E["apex CNAME check"]
    E --> F["mail: MX, SPF, DMARC, DKIM selectors"]
    F --> G["CAA"]
    G --> H["DNSSEC: DS, DNSKEY, RRSIG"]
    H --> I["print findings, exit 1 on any FAIL"]
```

[![audit](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture6.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture6.jpg)

What it checks:

| Area | Checks |
|---|---|
| Delegation | at least 2 nameservers, every NS has an address, every NS answers **authoritatively** (lame delegation), IPv6 failures are only warnings |
| SOA | serial identical on all reachable nameservers |
| Apex | CNAME at the zone apex (illegal next to SOA/NS) |
| SPF | present, single record, restrictive ending (`-all` / `~all` / `redirect=`), flags `+all`, RFC 7208 10-lookup limit (follows `include` and `redirect`) |
| DMARC | present, policy is `quarantine` or `reject` (warns on `p=none`), `rua=` reporting address |
| DKIM | each `--dkim-selector` publishes a key |
| CAA | present or not (informational) |
| DNSSEC | see [dnssec](#dnssec) |

Domains without MX only get `INFO` for missing SPF/DMARC; domains that receive mail get `WARN`.

```text
$ dnslens audit example.com --dkim-selector google        # illustrative output
OK    ns     2 nameservers: a.iana-servers.net, b.iana-servers.net
OK    soa    serial 2024081201 consistent on all 4 reachable servers
OK    mx     1 MX record(s)
OK    spf    SPF present with a restrictive policy
OK    spf    1/10 DNS lookups
WARN  dmarc  policy p=none (monitoring only)
FAIL  dkim   selector 'google' not found
INFO  caa    no CAA records (any CA may issue certificates)
OK    dnssec 1 DS record(s) published at parent

1 failure(s), 1 warning(s)
```

### dnssec

Zone-level DNSSEC sanity check (also part of `audit`).

```mermaid
flowchart TD
    A["dnssec example.com"] --> B["query DS at the parent with DO bit"]
    B --> C{"DS exists?"}
    C -- "no" --> D["INFO: zone is not signed"]
    C -- "yes" --> E["query DNSKEY + RRSIG"]
    E --> F{"DNSKEY served?"}
    F -- "no" --> G["FAIL: validating resolvers will SERVFAIL"]
    F -- "yes" --> H{"a DS digest matches<br/>a published DNSKEY?"}
    H -- "no" --> I["FAIL: broken chain of trust"]
    H -- "yes" --> J["OK: DS matches DNSKEY"]
    J --> K["validate the RRSIG over the DNSKEY set"]
    K --> L{"valid?"}
    L -- "no" --> M["FAIL: invalid signature"]
    L -- "yes" --> N{"expires within 3 days?"}
    N -- "yes" --> O["WARN: signatures expire soon"]
    N -- "no" --> P["OK: signatures valid for N days"]
```

[![dnssec](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture7.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture7.jpg)

It verifies the zone against its parent's DS record and its own signatures. It does **not** walk the chain of trust up to the root.

### reverse

`dnslens reverse 8.8.8.8` is a PTR lookup (IPv4 and IPv6). Exit code `2` for an invalid IP.

## DNS server: `dnslens serve`

A small, dependency-light DNS server (UDP **and** TCP) for development, staging, CI mocks, split-horizon setups and LAN ad-blocking. It answers from local records, blocks listed domains, and forwards everything else to upstream resolvers with a cache.

### How it decides

```mermaid
flowchart TD
    IN["datagram or TCP frame"] --> P{"parses as DNS?"}
    P -- "too short" --> DROP["drop"]
    P -- "garbage, 12+ bytes" --> FE["reply FORMERR"]
    P -- "ok" --> ACL{"client allowed<br/>by ACL?"}
    ACL -- "no" --> REF["REFUSED"]
    ACL -- "yes" --> OP{"standard QUERY,<br/>one question, class IN,<br/>not AXFR / IXFR?"}
    OP -- "no" --> REF2["NOTIMP / FORMERR / REFUSED"]
    OP -- "yes" --> BL{"name or parent<br/>on the blocklist?"}
    BL -- "yes" --> BM["NXDOMAIN, or 0.0.0.0 / :: in null mode"]
    BL -- "no" --> LOC{"local record?<br/>exact or wildcard"}
    LOC -- "yes" --> LA["answer with AA flag<br/>follow local CNAMEs"]
    LA --> TAIL{"CNAME target<br/>not local?"}
    TAIL -- "yes" --> FWD
    TAIL -- "no" --> OUT
    LOC -- "no" --> AUTHQ{"under an authoritative<br/>zone?"}
    AUTHQ -- "yes" --> NX["NXDOMAIN (NODATA for empty<br/>non-terminals)"]
    AUTHQ -- "no" --> FQ{"forwarding enabled?"}
    FQ -- "no" --> REF3["REFUSED"]
    FQ -- "yes" --> FWD["cache lookup, then upstream"]
    FWD --> OUT["encode response"]
    NX --> OUT
    BM --> OUT
    OUT --> SZ{"UDP and larger than<br/>client's limit?"}
    SZ -- "yes" --> TC["set TC, client retries over TCP"]
    SZ -- "no" --> SEND["send"]
    TC --> SEND
```

[![How it decides](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture8.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture8.jpg)

### Forwarding and caching

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as dnslens serve
    participant K as Cache
    participant U as Upstream resolver

    C->>S: A real.example.com?
    S->>K: lookup (name, type, DO bit)
    K-->>S: miss
    S->>U: A real.example.com? (RD=1)
    U-->>S: 203.0.113.7, TTL 60
    S->>K: store, expires after 60 s
    S-->>C: 203.0.113.7, TTL 60

    Note over C,S: 20 seconds later
    C->>S: A real.example.com?
    S->>K: lookup
    K-->>S: hit, remaining TTL 40
    S-->>C: 203.0.113.7, TTL 40
```

[![Forwarding and caching](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture9.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture9.jpg)

Negative answers (NXDOMAIN / NODATA) are cached using the SOA minimum (30 s if there is none). SERVFAIL and REFUSED are never cached. If the first upstream fails, the next one is tried; if all fail the client gets SERVFAIL.

### Running it

```bash
dnslens serve -c zone.json --watch --log-queries            # 127.0.0.1:5353
dnslens serve --record "app.test A 10.0.0.5" --record "app.test TXT hello"
dnslens serve --host 0.0.0.0 --port 53 \
              --blocklist hosts.txt --allow 192.168.0.0/16   # LAN resolver (needs root/Administrator)
dnslens query app.test -r 127.0.0.1#5353                      # test it with the client
```

### `zone.json`

```json
{
  "ttl": 300,
  "authoritative": ["dev.test."],
  "upstream": ["1.1.1.1", "9.9.9.9"],
  "block": ["ads.example.net"],
  "blocklists": ["hosts.txt"],
  "block_mode": "nxdomain",
  "records": {
    "app.dev.test.": {
      "A": ["10.0.0.5", "10.0.0.6"],
      "TXT": "plain text, quoted for you",
      "AAAA": { "ttl": 30, "data": ["fd00::5"] }
    },
    "*.svc.dev.test.": { "A": "10.1.1.1" },
    "www.dev.test.": { "CNAME": "app.dev.test." }
  }
}
```

Unknown keys, invalid IPs or a CNAME mixed with other types are rejected at load time with a clear message (and keep the old config when `--watch` is reloading).

### Options

| Option | Default | Meaning |
|---|---|---|
| `--host` / `-p, --port` | `127.0.0.1` / `5353` | Bind address and UDP+TCP port |
| `-c, --config FILE` | none | JSON zone/config file |
| `--record 'NAME TYPE DATA'` | none | Add a record inline (repeatable) |
| `--authoritative ZONE` | none | NXDOMAIN for unknown names under ZONE instead of forwarding |
| `--block DOMAIN` / `--blocklist FILE` | none | Block a domain and its subdomains; hosts-format or one-domain-per-line files |
| `--block-mode` | `nxdomain` | Or `null`: answer `0.0.0.0` / `::` |
| `--upstream ADDR` | OS resolvers (never itself), else 1.1.1.1 and 9.9.9.9 | Upstream, `IP` or `IP#PORT` (repeatable) |
| `--no-forward` | off | Authoritative-only; REFUSE everything else |
| `--cache-size` / `--max-ttl` | `10000` / `86400` | `0` disables the cache; TTL ceiling in seconds |
| `--allow CIDR` | see below | Allowed client networks (repeatable) |
| `--watch` | off | Hot-reload the config and blocklists when the files change |
| `--log-queries` / `-v` | off | Log every query (client, name, type, rcode, source, ms) / debug logging |
| `--workers` | `32` | UDP worker threads |

**Behaviour notes**

- Wildcards match at any depth: `*.svc.dev.test.` also answers `a.b.svc.dev.test`.
- A CNAME whose target is not local is resolved through the upstream and appended to the answer, so simple stub resolvers work.
- Blocking `example.net` also blocks `x.y.example.net`. Hosts-file lines like `0.0.0.0 ads.test` are understood; `localhost` style entries are ignored.
- EDNS is supported (payload capped at 1232). DNSSEC records are forwarded only to clients that set the DO bit.
- AXFR / IXFR are refused. Statistics are logged on shutdown.

### Pointing machines at it

Operating-system resolver settings cannot specify a port, so for system-wide use run on **port 53** (see [Troubleshooting](#troubleshooting)) or put it behind a forwarder that supports custom ports (dnsmasq `server=127.0.0.1#5353`, systemd-resolved drop-ins, Windows NRPT). For per-tool testing, `dnslens query -r 127.0.0.1#5353` and `dig -p 5353 @127.0.0.1` work directly.

## Web UI: `dnslens serve --web`

An AdGuard Home style control panel for the DNS server: live statistics and charts, a searchable query log, blocklist subscriptions, DNS rewrites, runtime settings and the diagnostics from this package, all in the browser. It is a single-page app **shipped inside the Python package** (plain HTML/CSS/JS, no Node, no build step, no CDN), so it works offline, on Windows and on a Raspberry Pi alike.

```bash
dnslens serve --web                                   # DNS on 127.0.0.1:5353, UI on http://127.0.0.1:8080
dnslens serve --web --host 0.0.0.0 --port 53 --web-host 0.0.0.0 --web-cert cert.pem --web-key key.pem
dnslens serve --web --web-password 'a long passphrase' --data-dir /var/lib/dnslens
```

On the first start a random admin password is generated, printed **once** in the log and stored hashed (PBKDF2-SHA256, 240k iterations). Change it on the *Account* page. `--web-password` (or env `DNSLENS_WEB_PASSWORD`) sets it explicitly, which is also how you recover a forgotten one.

### Pages

| Page | What you get |
|---|---|
| **Dashboard** | Query, blocked, cache-hit and rule counters; stacked timeline chart (resolved / blocked / failed) with hover details; top queried domains, top blocked domains, top clients, upstream servers with average latency, query types and response codes; windows of 1 h, 6 h, 24 h, 7 d, 30 d; statistics refresh every 10 s. **Live traffic** panel updates every second (see below). One click blocks or allows a domain straight from the top lists. |
| **Query log** | Every query with time, domain, type, status (Blocked, Cached, Local, Resolved, Failed), answers, client, upstream and latency. Search, status filter, paging, live mode, row details (which rule in which list blocked it), one-click Block / Unblock. |
| **Filters** | Subscribe to blocklists by URL (presets included), enable/disable, update now, automatic refresh. Custom rules editor (`\|\|domain^`, `@@\|\|domain^`). *Check a host* tells you which rule and list would block a name. |
| **DNS rewrites** | Point names (wildcards allowed) at an address or another name, with A/AAAA/CNAME/TXT/MX/PTR/NS/SRV/CAA, TTL, enable/disable, edit in place. |
| **Settings** | Upstream servers (with a connectivity test), timeout, cache size and max TTL, forwarding on/off, block response (NXDOMAIN or `0.0.0.0`), query-log on/off, retention, client-IP anonymization, list update interval, clear cache. |
| **Tools** | The dnslens diagnostics in the browser: lookup, propagation, trace, audit, DNSSEC, benchmark, reverse, optionally through *this* server. |
| **Account** | Change username and password (other sessions are signed out). |

The top bar has the protection switch (enable, or pause for 10 min / 1 h / 24 h / until re-enabled) and a dark/light theme toggle.

### How the pieces connect

```mermaid
flowchart LR
    subgraph CLIENTS["Your network"]
        C1["Laptops, phones, services"]
    end

    subgraph PROC["one dnslens process"]
        DNS["DNS server<br/>UDP + TCP"]
        OBS["Query observer"]
        Q["Writer thread<br/>batched inserts"]
        MGR["Manager<br/>settings, lists, rewrites, rules"]
        WEB["Web server<br/>sessions, JSON API, static UI"]
    end

    DB[("query log<br/>SQLite file or SQL database")]
    CFG[("settings + account<br/>config.json or SQL table")]
    FLT[("blocklists<br/>files or SQL table")]
    UP["Upstream resolvers"]
    BR["Your browser"]

    C1 -->|"DNS queries"| DNS
    DNS -->|"cache miss"| UP
    DNS --> OBS --> Q --> DB
    BR -->|"HTTPS or HTTP"| WEB
    WEB --> MGR
    WEB -->|"statistics, log search"| DB
    MGR -->|"rebuild zone, hot swap"| DNS
    MGR --> CFG
    MGR --> FLT
```

[![How the pieces connect](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture15.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture15.jpg)


Query logging never slows DNS down: the DNS path only drops an event into a bounded in-memory queue; a separate thread writes batches to SQLite (WAL mode). If the queue ever overflows, events are dropped and counted rather than blocking answers.

### What happens to a query

Rules are applied in this order, and the first match wins:

```mermaid
flowchart TD
    Q["query for NAME"] --> RW{"DNS rewrite or<br/>static record for NAME?"}
    RW -- "yes" --> LOCAL["answer locally<br/>status: Local"]
    RW -- "no" --> PR{"protection enabled?"}
    PR -- "paused" --> FWD
    PR -- "on" --> AL{"allow rule matches NAME<br/>or a parent domain?"}
    AL -- "yes" --> FWD
    AL -- "no" --> BL{"block rule matches NAME<br/>or a parent domain?"}
    BL -- "yes" --> BLOCKED["NXDOMAIN or 0.0.0.0<br/>status: Blocked<br/>log keeps rule + list"]
    BL -- "no" --> FWD["cache, then upstream<br/>status: Cached or Resolved"]
```

[![What happens to a query](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture16.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture16.jpg)


- **Allow beats block**, so `@@||example.org^` always wins, even against a list. A *custom* block rule beats a list's allow rule for the same domain.
- A rule for a domain covers its subdomains. `||ads.example.com^` blocks `x.ads.example.com` too.
- Unblocking from the query log adds an `@@||domain^` rule; blocking adds `||domain^` (and removes the opposite rule if present).

### Blocklist formats

| Format | Example | Notes |
|---|---|---|
| AdGuard / ABP | `\|\|ads.example.com^` | `$important` accepted; other modifiers (`$dnsrewrite`, `$client`, regex, cosmetic rules) are skipped and counted |
| Allow rule | `@@\|\|good.example.com^` | overrides every block rule |
| Hosts file | `0.0.0.0 ads.example.com` | `localhost` style entries ignored |
| Plain domains | `ads.example.com` | one per line |

Lists are downloaded over HTTP(S) (max 64 MB each), validated, stored under `filters/` and re-downloaded on the interval you choose. A list that fails to download keeps its previous rules and shows the error. Built-in presets: AdGuard DNS filter, StevenBlack unified hosts, Peter Lowe's ad servers.

### Sign-in, sessions and CSRF

```mermaid
sequenceDiagram
    autonumber
    actor U as Browser
    participant W as Web server
    participant M as Manager

    U->>W: POST /api/login {username, password}
    W->>W: failed 5 times in 5 min from this IP? answer 429
    W->>M: verify (PBKDF2, constant-time compare)
    M-->>W: ok
    W-->>U: 200 + Set-Cookie session (HttpOnly, SameSite=Strict, Secure on HTTPS)
    U->>W: GET /api/stats (cookie)
    W-->>U: 200 JSON
    U->>W: PUT /api/settings (cookie, X-Requested-With: dnslens, Origin = Host)
    W->>W: custom header + same-origin check, then validate input
    W->>M: apply and persist
    M-->>U: 200 JSON
```

[![Sign-in, sessions and CSRF](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture17.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture17.jpg)

### Live dashboard

The dashboard has a **Live traffic** panel next to the statistics: queries per second with a scrolling two-minute chart (resolved / blocked / failed), a feed of the most recent queries with their status, and counters (queries, blocked, cached) that tick up in real time. *Pause* and *Resume* it with the button; the choice is remembered in the browser.

```mermaid
sequenceDiagram
    autonumber
    participant D as DNS server
    participant H as LiveHub (ticker thread)
    participant W as Web server
    participant B as Browser dashboard

    B->>W: GET /api/live (EventSource, session cookie)
    W-->>B: event hello: last 2 minutes + recent queries
    loop every query (cheap)
        D->>H: increment counters, keep a small sample
    end
    loop every second
        H->>H: close the second: totals, blocked, cache, avg ms, up to 15 sample queries
        H-->>W: new tick
        W-->>B: event tick
        B->>B: update chart, feed and the stat cards
    end
    Note over B,W: No push within 5 s (buffering proxy)? the browser switches to GET /api/live/poll?since=N once per second
```

[![Live dashboard](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture18.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture18.jpg)

- **Constant cost.** The DNS path only bumps a few counters; one thread turns them into one small message per second, so a busy resolver (thousands of queries/s) costs the browser the same as an idle one. When more than 15 queries arrive in a second, the feed shows a sample and says so.
- **Server-Sent Events first, polling as a fallback.** SSE is a plain long-lived HTTP response (no WebSocket, no extra dependency). If it does not deliver within 5 s (some proxies buffer streaming responses) the page falls back to polling `/api/live/poll` automatically. The status next to the panel title reads *live* or *live (polling)*.
- **Limits.** At most 20 simultaneous live viewers (each holds one connection); a stream ends cleanly when its session expires or is signed out.
- **Behind nginx** add `proxy_buffering off; proxy_read_timeout 1h;` to the `location` (the server already sends `X-Accel-Buffering: no`).
- The *Query log* page's **Live** switch refreshes the log from the database every 2 s (complete, not sampled).

### Where data is stored

Everything the UI manages goes through one storage layer, with two interchangeable modes:

```mermaid
flowchart TD
    UI["Web UI / API"] --> M["Manager<br/>settings, lists, rewrites, rules, account"]
    DNS["DNS server"] -->|"every query"| QL["Query log writer<br/>batched, off the DNS path"]
    M --> MODE{"started with --db ?"}
    QL --> MODE
    MODE -- "no (default)" --> F["Files, no extra dependency<br/>config.json, filters/N.txt,<br/>queries.db (SQLite)"]
    MODE -- "yes" --> D[("SQL database via SQLAlchemy<br/>SQLite, PostgreSQL, MySQL, MariaDB")]
    D --> T["dnslens_config<br/>dnslens_lists<br/>dnslens_queries"]
```

[![Where data is stored](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture19.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture19.jpg)


| | Files (default) | Database (`--db`) |
|---|---|---|
| Install | `pip install dnslens` | `pip install "dnslens[postgres]"`, `[mysql]` or `[sql]` |
| Settings, account, rewrites, rules, list metadata | `config.json` (written atomically, `0600`) | table `dnslens_config` (one JSON document + revision counter) |
| Downloaded blocklists | `filters/N.txt` | table `dnslens_lists` (zlib-compressed, `LONGBLOB` on MySQL) |
| Query log and statistics | `queries.db`, SQLite via the standard library | table `dnslens_queries` (indexed by time, domain, client) |
| Location | `--data-dir` (Windows `%APPDATA%\dnslens`, otherwise `~/.local/share/dnslens`, owner-only) | the URL you give |
| Several servers sharing the state | no | **yes**: nodes pick up each other's changes within 5 s |
| Backup | copy the directory | your normal database backup |

The **Settings** page shows where the running instance keeps its data (read only), and credentials in the database URL are masked everywhere (log, UI).

**Static vs managed configuration.** `-c zone.json`, `--record`, `--block`, `--blocklist` and `--authoritative` still work and are layered *under* what you manage in the UI (they show up as "static configuration" and are read-only there). Flags such as `--upstream`, `--cache-size`, `--max-ttl`, `--no-forward` and `--block-mode` only **seed** the stored settings the first time; afterwards the UI's settings win.

### Database storage (SQLAlchemy)

```bash
pip install "dnslens[postgres]"
export DNSLENS_DB_URL='postgresql://dnslens:secret@db.internal/dnslens'   # keeps the password out of `ps`
dnslens serve --web                                                      # config, lists AND query log in PostgreSQL

dnslens serve --web --db 'mysql://dnslens:secret@127.0.0.1/dnslens?charset=utf8mb4'
dnslens serve --web --db sqlite:////var/lib/dnslens/dnslens.db           # SQLite through SQLAlchemy
dnslens serve --web --log-db postgresql://...                            # only the query log in a database, the rest stays in files
```

- **URLs** are standard SQLAlchemy URLs. `postgresql://` and `mysql://` pick the driver that is installed (psycopg 3 / psycopg2, PyMySQL / mysqlclient); `mariadb+pymysql://` works too.
- **Tables are created automatically** on first start (`dnslens_config`, `dnslens_lists`, `dnslens_queries`). The database user needs `CREATE`, `INSERT`, `UPDATE`, `DELETE`, `SELECT` and index rights on its schema; nothing else. Use `utf8mb4` on MySQL/MariaDB.
- **Tested** on SQLite, PostgreSQL 16 and MariaDB 10.11 (SQLAlchemy 2.0 and 2.1), including a 2 MB blocklist and two servers sharing one database.
- **Several nodes, one database.** Run two or more `dnslens serve --web --db ...` (for example a primary and a secondary resolver). A rewrite, list, setting or password changed on one node is picked up by the others within 5 s, and all nodes write to the same query log, so the dashboard shows the combined traffic. Protection pause is part of the shared configuration. If two admins save at the same moment the last write wins.
- **Moving an existing installation** from files to a database:

  ```mermaid
  flowchart LR
      A["data directory<br/>config.json, filters, queries.db"] -->|"dnslens db migrate<br/>--from-dir DIR --to URL"| B[("database")]
      B --> C["dnslens serve --web --db URL"]
  ```

  ```bash
  dnslens db migrate --from-dir ~/.local/share/dnslens --to "$DNSLENS_DB_URL"   # --no-log skips the query log, --force overwrites
  ```

  The password hash, rules, rewrites, lists and the log history are copied; the original directory is left untouched.

### Web options

| Option | Default | Meaning |
|---|---|---|
| `--web` | off | Enable the UI |
| `--web-host` / `--web-port` | `127.0.0.1` / `8080` | UI bind address and port |
| `--data-dir DIR` | per-user | Where state lives |
| `--web-user` / `--web-password` | `admin` / generated | Set credentials (password also via `DNSLENS_WEB_PASSWORD`) |
| `--web-cert` / `--web-key` | none | PEM files; serve the UI over HTTPS (TLS 1.2+, HSTS, `Secure` cookie) |
| `--db URL` | env `DNSLENS_DB_URL` | Keep config, blocklists and the query log in a SQL database ([details](#database-storage-sqlalchemy)) |
| `--log-db URL` | env `DNSLENS_LOG_DB_URL` | Keep only the query log in this database |

### Behind a reverse proxy

Terminate TLS in front and keep the original `Host` header (the same-origin check compares `Origin` with `Host`):

```nginx
server {
    listen 443 ssl;
    server_name dns.example.com;
    # ssl_certificate / ssl_certificate_key ...
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Comparison with AdGuard Home

| | dnslens web UI | AdGuard Home |
|---|---|---|
| Dashboard, charts, top lists | yes | yes |
| Query log with search and filters | yes | yes |
| Blocklist subscriptions, custom rules, check host | yes (AdGuard/hosts/domain syntax subset) | yes (full syntax) |
| DNS rewrites, wildcards | yes | yes |
| Pause protection with a timer | yes | yes |
| Live traffic view (per-second chart and feed) | yes | partial (log refresh) |
| Storage in PostgreSQL / MySQL, several nodes on one database | **yes** | no (local files) |
| Upstream test, cache, retention, anonymization | yes | yes |
| Built-in diagnostics (propagation, trace, audit, DNSSEC) | **yes** | no |
| Prometheus probes / REST for automation | **yes** (`dnslens api`) | partial |
| DoH / DoT / DoQ listeners | no | yes |
| DHCP server | no | yes |
| Per-client settings, parental control, safe search | no | yes |
| Install | `pip install dnslens` (Python 3.9+) | single binary |

dnslens is a good fit for developers, home labs and small networks that already use Python tooling; it is not a drop-in replacement for AdGuard Home's full feature set.

## HTTP API: `dnslens api`

A JSON API over every tool, plus Prometheus-format probes. Pure standard library (`http.server`), so it has no extra dependencies.

```mermaid
flowchart TD
    REQ["GET /endpoint?params"] --> H{"path"}
    H -- "/healthz" --> OKH["200 status ok<br/>no auth needed"]
    H -- "other" --> AU{"token configured<br/>and valid?"}
    AU -- "no" --> E401["401"]
    AU -- "yes" --> RT{"known route?"}
    RT -- "no" --> E404["404"]
    RT -- "yes" --> SEM{"free slot under<br/>max-concurrent?"}
    SEM -- "no" --> E503["503 busy"]
    SEM -- "yes" --> VAL["validate and clamp parameters"]
    VAL -- "invalid" --> E400["400 with message"]
    VAL -- "ok" --> RUN["run the tool<br/>named resolvers only"]
    RUN --> FMT{"endpoint type"}
    FMT -- "/probe, /metrics" --> PROM["200 Prometheus text"]
    FMT -- "others" --> JSON["200 JSON"]
```

[![HTTP API](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture10.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture10.jpg)

```bash
dnslens api --port 8053 --token "$TOKEN" -r internal=10.0.0.2
curl -H "Authorization: Bearer $TOKEN" \
     "localhost:8053/propagate?name=app.example.com&expect=203.0.113.10"
```

### Endpoints

| Endpoint | Parameters |
|---|---|
| `/query` | `name`, `type` (comma list, max 5), `resolver`, `dnssec`, `norecurse`, `transport`, `timeout`, `retries` |
| `/propagate` | `name`, `type`, `expect` (repeatable), `strict`, `resolver` (default: public set) |
| `/trace` | `name`, `type` |
| `/audit` | `domain`, `dkim_selector` (repeatable), `resolver` |
| `/dnssec` | `domain`, `resolver` |
| `/bench` | `domain` (repeatable), `count` (max 50), `uncached`, `resolver` |
| `/reverse` | `ip`, `resolver` |
| `/probe` | `kind=query\|propagate\|audit\|dnssec` plus that tool's parameters; returns Prometheus text |
| `/metrics` | API request counters, durations, in-flight gauge, build info |
| `/healthz`, `/` | liveness (always open), endpoint index |

`resolver` accepts names: `google`, `cloudflare`, `quad9`, `opendns`, ..., `public`, `system`, or anything registered with `-r NAME=ADDR`. `timeout` is clamped to 0.2 to 10 seconds, `retries` to 0 to 2.

### Prometheus monitoring

`/probe` works like the blackbox exporter: Prometheus passes the check as URL parameters and reads the result as metrics.

```mermaid
sequenceDiagram
    autonumber
    participant P as Prometheus
    participant A as dnslens api
    participant R as Public resolvers
    participant AM as Alertmanager

    loop every scrape interval
        P->>A: GET /probe?kind=propagate&name=app.example.com&expect=203.0.113.10
        A->>R: parallel queries
        R-->>A: answers
        A-->>P: dnslens_probe_success 1<br/>dnslens_probe_resolvers_matching 10 ...
    end
    P->>AM: alert when dnslens_probe_success == 0 for 10m
```

[![Prometheus monitoring](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture11.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture11.jpg)

```yaml
# prometheus.yml
scrape_configs:
  - job_name: dns-propagation
    metrics_path: /probe
    params:
      kind: [propagate]
      name: [app.example.com]
      expect: ["203.0.113.10"]
    authorization: { credentials: "<token>" }
    static_configs:
      - targets: ["localhost:8053"]
```

Metrics returned by `/probe`:

| `kind` | Metrics |
|---|---|
| all | `dnslens_probe_success`, `dnslens_probe_duration_seconds` |
| `query` | `dnslens_probe_answer_records`, `dnslens_probe_dns_seconds` |
| `propagate` | `dnslens_probe_resolvers_total`, `_responding`, `_matching`, `dnslens_probe_distinct_answers` |
| `audit`, `dnssec` | `dnslens_probe_failures`, `dnslens_probe_warnings` |

Example alert rule:

```yaml
- alert: DnsRecordNotPropagated
  expr: dnslens_probe_success{job="dns-propagation"} == 0
  for: 10m
```

### API options

| Option | Default | Meaning |
|---|---|---|
| `--host` / `-p, --port` | `127.0.0.1` / `8053` | Bind address and port |
| `--token TOKEN` | env `DNSLENS_API_TOKEN` | Require `Authorization: Bearer ...` or `X-API-Key` |
| `-r, --resolver NAME=ADDR` | none | Register named resolvers; they become the defaults |
| `--allow-custom-resolver` | off | Let callers pass arbitrary resolver addresses |
| `-t, --timeout` | `3` | Default per-query timeout |
| `--max-concurrent` | `16` | Concurrent tool requests before `503` |

## Recipes

### Gate a deployment on DNS (any CI)

```mermaid
sequenceDiagram
    autonumber
    participant D as Pipeline
    participant T as Terraform / DNS provider
    participant L as dnslens
    participant S as Smoke tests

    D->>T: apply (new A record)
    T-->>D: applied
    D->>L: dnslens wait app.example.com A --expect NEW_IP --public --max-wait 900
    loop until all resolvers match
        L->>L: query, sleep 5 s
    end
    L-->>D: exit 0
    D->>S: run smoke tests against the hostname
```

[![Recipes](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture12.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture12.jpg)

```yaml
# GitHub Actions
- run: pip install dnslens
- run: dnslens wait app.example.com A --expect ${{ steps.tf.outputs.ip }} --public --max-wait 900
```

### Mock DNS in tests

Start a throwaway server inside the test run, no root and no network:

```python
import pytest
from dnslens.server import DNSHandler, DNSServer, ServerOptions, build_zone

@pytest.fixture
def dns_server():
    zone = build_zone(records=["api.test A 127.0.0.1", "db.test A 10.0.0.9"])
    handler = DNSHandler(zone, ServerOptions(forward=False))
    with DNSServer(handler, "127.0.0.1", 0) as srv:   # port 0 = any free port
        yield srv.port
```

### Shell and `jq`

```bash
dnslens query example.com A --json | jq -r '.[0].records[].data'
dnslens propagate example.com --json | jq '.groups[] | {values, resolvers}'
dnslens audit example.com --json | jq -e '.ok' >/dev/null || echo "audit failed"
[ "$(dnslens query example.com TXT --short | grep -c spf1)" -eq 1 ]
```

### Find the fastest resolver for this network

```bash
dnslens bench --uncached -n 30 --json | jq -r 'sort_by(.median)[0] | "\(.resolver) \(.median) ms"'
```

### Run the server and API as services (Linux, systemd)

```ini
# /etc/systemd/system/dnslens-dns.service
[Unit]
Description=dnslens DNS server
After=network-online.target

[Service]
ExecStart=/usr/local/bin/dnslens serve -c /etc/dnslens/zone.json --watch --host 0.0.0.0 --port 53 --allow 192.168.0.0/16
AmbientCapabilities=CAP_NET_BIND_SERVICE
DynamicUser=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/dnslens-api.service
[Service]
Environment=DNSLENS_API_TOKEN=change-me
ExecStart=/usr/local/bin/dnslens api --host 127.0.0.1 --port 8053
DynamicUser=yes
Restart=on-failure
```

On Windows run them under a service wrapper such as NSSM, or as a scheduled task at startup.

## Use as a Python library

Everything the CLI does is importable. All functions return plain dataclasses with a `to_dict()`.

```python
from dnslens.core import PUBLIC_RESOLVERS, QueryOpts, query
from dnslens.tools import propagate, wait
from dnslens.trace import trace
from dnslens.audit import audit
from dnslens.dnssec import check_dnssec

opts = QueryOpts(timeout=2.0, retries=1)

a = query("example.com", "A", "1.1.1.1", opts)
print(a.rcode, a.values(), a.elapsed_ms)          # NOERROR frozenset({'93.184.216.34'}) 12.3

rep = propagate(PUBLIC_RESOLVERS, "example.com", "A", opts, expected=["93.184.216.34"])
print(rep.ok, rep.responders, rep.failed)

ok, _ = wait(PUBLIC_RESOLVERS, "app.example.com", "A", opts,
             expected=["203.0.113.10"], interval=5, max_wait=600)

for f in audit("example.com", None, opts, dkim_selectors=["google"]):
    print(f.level, f.check, f.message)
```

Main types:

```mermaid
classDiagram
    class Target {
        name
        address
    }
    class QueryOpts {
        timeout
        retries
        transport
        port
        dnssec
    }
    class Answer {
        server
        rcode
        flags
        records
        elapsed_ms
        error
        ok
        values()
    }
    class Record {
        name
        ttl
        type
        data
    }
    class PropagationReport {
        groups
        failed
        consistent
        ok
    }
    class Finding {
        level
        check
        message
    }
    class TraceResult {
        hops
        final
        error
    }
    Answer "1" o-- "*" Record
    PropagationReport "1" o-- "*" Answer
    TraceResult "1" o-- "0..1" Answer
    Target <.. PropagationReport : queried
    QueryOpts <.. Answer : produced with
```

[![Main types](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture13.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture13.jpg)

Embedding the servers:

```python
from dnslens.server import DNSHandler, DNSServer, ServerOptions, build_zone
from dnslens.api import ApiConfig, ApiServer

zone = build_zone(records=["app.test A 10.0.0.5"])
with DNSServer(DNSHandler(zone, ServerOptions(forward=False)), "127.0.0.1", 5353), \
     ApiServer(ApiConfig(token="secret"), "127.0.0.1", 8053):
    ...  # both are running on background threads
```

## Output formats and exit codes

`--json` prints one JSON document per command (a list for multi-resolver commands). Example for `query`:

```json
[
  {
    "server": "1.1.1.1",
    "qname": "example.com",
    "type": "A",
    "rcode": "NOERROR",
    "flags": "QR RD RA",
    "elapsed_ms": 11.4,
    "transport": "udp",
    "error": null,
    "records": [
      { "name": "example.com.", "ttl": 3600, "type": "A", "data": "93.184.216.34" }
    ],
    "resolver": "system"
  }
]
```

| Exit code | Meaning |
|---|---|
| `0` | success, healthy, condition met |
| `1` | check failed: inconsistent or mismatched answers, timeout, `FAIL` finding, no records, NXDOMAIN, bind error |
| `2` | usage or configuration error (bad arguments, invalid zone file, invalid IP) |
| `130` | interrupted (Ctrl-C) |

## Security notes

- **`serve`** binds to loopback by default. Binding anywhere else limits clients to private ranges (RFC 1918, ULA, link-local, CGNAT, loopback) unless you pass `--allow`. Open resolvers are abused for DDoS amplification, so do not expose it to the internet. AXFR/IXFR are refused. There is no rate limiting.
- **Web UI.** Binds to loopback by default; on other addresses it warns when TLS is off. Sign-in uses PBKDF2-SHA256 (240k iterations), constant-time comparison, a lockout after 5 failed attempts in 5 minutes per IP, `HttpOnly` + `SameSite=Strict` session cookies (24 h sliding), and sessions are invalidated when the password changes. State-changing requests need a custom header and a same-origin `Origin`. Responses carry a strict Content-Security-Policy (no inline scripts), `X-Frame-Options: DENY`, `nosniff` and `no-referrer`. All DNS-derived text (domains from clients!) is rendered with `textContent`, never `innerHTML`; this is covered by a test that sends a hostile name. List URLs must be `http(s)`; the admin is trusted to choose them, so do not expose the UI to people you would not trust with outbound HTTP requests from this host.
- **Database credentials.** Prefer the `DNSLENS_DB_URL` environment variable over `--db` (command lines are visible to other users via `ps`). Passwords are masked in logs and in the UI, the stored admin password is a PBKDF2 hash, and the database account only needs rights on its own schema. The query log contains client IPs and the names they look up: set a short retention or enable anonymization if that is sensitive.
- **`api`** binds to loopback by default and warns when you bind elsewhere without `--token`. Token comparison is constant-time. Callers can only use resolvers you registered (plus the public set) unless `--allow-custom-resolver` is set, which prevents using it to send packets to arbitrary hosts. Inputs are validated and clamped, and concurrency is capped. It speaks plain HTTP: put it behind a TLS reverse proxy if it leaves localhost.
- Zone and blocklist files are data only; nothing is executed.
- Reports from `audit` and `propagate` reveal what public DNS says about a domain. They contain nothing secret, but the API makes your host perform those queries on request.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `cannot bind 0.0.0.0:53: permission denied` | Ports below 1024 need root/Administrator. Linux alternatives: `sudo sysctl net.ipv4.ip_unprivileged_port_start=53`, or systemd `AmbientCapabilities=CAP_NET_BIND_SERVICE`, or run on 5353 and redirect. |
| `cannot bind ...: address already in use` on Linux | `systemd-resolved` owns `127.0.0.53:53`. Bind a specific address (`--host 192.168.1.5`) or disable its stub listener. |
| Port 53 in use on Windows | Internet Connection Sharing or Hyper-V may hold it. Find it with `netstat -ano \| findstr :53` and stop the service, or use another port. |
| `propagate` says INCONSISTENT for a CDN hostname | Round-robin / GeoDNS answers differ legitimately. Use `--expect` with the full set, or `--subset` with `wait`. |
| Some public resolvers show `FAIL timeout` | Your network blocks UDP/53 to them. They are ignored unless `--strict`. Try `--transport tcp` or `tls`. |
| `audit` reports an unreachable IPv6 nameserver | Only a `WARN`: the host may lack IPv6 connectivity. |
| `database storage needs SQLAlchemy` | `pip install "dnslens[postgres]"` (or `[mysql]` / `[sql]`). |
| `cannot use database ...` on start | Wrong URL or credentials, the server is unreachable, or the user may not create tables. The message includes the driver's error. |
| Live panel says *live (polling)* | A proxy buffers streaming responses. Works as is; for true push add `proxy_buffering off;` (nginx). |
| Live panel says *reconnecting...* | The browser lost the connection (server restarted, or the session expired: you are sent to the sign-in page). |
| Forgot the web UI password | Restart with `--web-password 'new passphrase'` (it is stored hashed). The data directory keeps everything else. |
| Dashboard is empty | Query logging is switched off in Settings, or no client uses this server yet. Test with `dnslens query example.com -r 127.0.0.1#5353`. |
| A blocklist cannot be downloaded | The host has no outbound HTTP(S), or the URL is wrong. The error is shown on the Filters page; the list keeps its old rules. |
| UI says `cross-origin request refused` behind a proxy | Pass the original `Host` header (`proxy_set_header Host $host;`). |
| `--transport https` fails with `NoDOH` | Install the extra: `pip install "dnslens[doh]"`. |
| Colours look broken in a log file | Colour is only used on a TTY. Set `NO_COLOR=1` or pass `--no-color`. |
| Server answers `REFUSED` | Your client is outside `--allow`, or `--no-forward` is set and the name is not local. |

## Limitations

- `dnssec` checks the zone against its parent DS and its own signatures; it does not validate the chain up to the root, and `serve` does not perform DNSSEC validation itself (it passes validation results from the upstream through).
- `serve` is not a full recursive resolver or authoritative server: no zone transfers, no dynamic updates, no rate limiting, no DoT/DoH listener, no negative-cache SOA synthesis for local NODATA.
- Wildcards match at any depth (a deliberate, dnsmasq-like simplification of RFC 4592).
- `trace` uses a built-in list of root server addresses and IPv4 glue first; an IPv6-only network may need the system resolver for glueless delegations.
- Zone files are JSON, not RFC 1035 master files.
- The web UI is a single-admin panel: no multi-user roles, no per-client rules, no DHCP, no DoH/DoT/DoQ listeners. Blocklist support covers the DNS-relevant subset of AdGuard syntax (see the table above).
- Database mode creates the tables itself and has no migration framework yet (schema version 1); there is no `db export` back to files. Nodes sharing a database sync configuration every 5 s, not instantly.
- The query log lives in SQLite or a SQL database; for very busy resolvers (millions of queries a day) use a short retention.

## Development and releasing

```bash
git clone https://github.com/cumulus13/dnslens && cd dnslens
pip install -e ".[dev]"
pytest && ruff check src tests && mypy src
```

The tests start an in-process fake DNS server on localhost and need no network. CI (on pushes to `main`/`master` and on pull requests) runs lint, type checks and the tests on Ubuntu, Windows and macOS for Python 3.9 to 3.13, plus a web UI smoke test and a job that runs the database tests against PostgreSQL 16 and MariaDB 11 service containers.

```bash
# database backends on real servers (SQLite always runs)
DNSLENS_TEST_PG='postgresql+psycopg://user:pw@localhost/dnslens' \
DNSLENS_TEST_MYSQL='mysql+pymysql://user:pw@localhost/dnslens?charset=utf8mb4' pytest tests/test_sql.py

# optional: UI smoke test, SSE and polling paths (needs Node 20+)
cd tests/ui && npm install && cd ../.. && bash tests/ui/run.sh
```

```text
src/dnslens/
  core.py      query primitive, targets, Answer / Finding types
  tools.py     propagate, wait, bench
  trace.py     iterative resolution from the root
  audit.py     domain health audit (SPF, DMARC, DKIM, delegation, SOA)
  dnssec.py    DS / DNSKEY / RRSIG check
  server.py    DNS server, zone data, cache, reloader
  api.py       HTTP API, probes, metrics
  manage.py    runtime-managed settings, lists, rewrites, accounts (web UI back end)
  web.py       web server: sessions, CSRF, JSON API for the UI
  querylog.py  query log + statistics (SQLite from the standard library)
  storage.py   file storage and the storage selector
  sqlstore.py  SQLAlchemy backend: config, blocklists, query log (PostgreSQL, MySQL/MariaDB, SQLite)
  migrate.py   `dnslens db migrate`
  live.py      per-second live feed (SSE and polling)
  filters.py   blocklist parsing and subscriptions
  webui/       the single-page app (index.html, app.js, charts.js, style.css)
  cli.py       argparse front end
  output.py    tables, colour (Windows-safe)
tests/         fake-server based tests
tests/ui/      browser-less (jsdom) smoke test of the web UI against a live stack
.github/workflows/  ci.yml, release.yml
```

### Release pipeline

```mermaid
flowchart LR
    T["git tag v1.2.3<br/>git push --tags"] --> B1
    subgraph BUILD["build job"]
        B1["tag matches<br/>pyproject version?"] --> B2["run tests"] --> B3["python -m build"] --> B4["twine check --strict"]
    end
    B4 --> PUB["publish-pypi job<br/>environment: pypi<br/>OIDC trusted publishing"]
    PUB --> PYPI[("PyPI")]
    PUB --> GH["github-release job<br/>attach wheel and sdist"]
    M["manual run of the workflow"] --> B1
    B4 -. "manual run only" .-> TP["publish-testpypi job"]
    TP --> TPI[("TestPyPI")]
```

[![Release pipeline](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture14.jpg)](https://raw.githubusercontent.com/licface15/images/refs/heads/main/dnslens/architecture14.jpg)

1. Bump `version` in `pyproject.toml`, update `CHANGELOG.md`, commit.
2. `git tag v1.2.3 && git push --tags`. The workflow refuses to publish if the tag and the package version differ.
3. One-time setup: on PyPI add a **pending publisher** (project `dnslens`, owner `cumulus13`, repository `dnslens`, workflow `release.yml`, environment `pypi`) and create the GitHub environment `pypi`. Repeat on test.pypi.org with environment `testpypi` for dry runs (run the *Release* workflow manually). No API tokens are stored anywhere.

## License

[GPL-3.0](LICENSE) and [EULA](EULA.md)

## 👤 Author
        
[Hadi Cahyadi](mailto:cumulus13@gmail.com)
    

[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/cumulus13)

[![Donate via Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cumulus13)
 
[Support me on Patreon](https://www.patreon.com/cumulus13)
