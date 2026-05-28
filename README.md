# acme

## What is this?

**acme** brings Let's Encrypt-style ACME TLS certificates to a
[spangap](../spangap) device. It runs the ACME flow (account key, order,
challenge, finalization, cert download), drops the cert pair where
`spangap-net`'s `tls` picks it up, and hot-swaps the live HTTPS server's
certificate without dropping sessions.

## What this straddle owns

```
acme/
└── esp-idf/
    ├── include/acme.h
    └── src/acme.cpp
```

Plus a browser panel (under `browser/`) wired into the spangap Settings
UI for the operator to enter contact email, accept terms, and trigger /
observe renewal.

## How others use it

```cpp
acmeInit();    // after netInit + tlsInit
```

State lives under `s.acme.*` (settings) and `secrets.acme.*` (account
key + cert key). The flow runs from cron — daily-ish if the cert is
healthy, sooner if it's near expiry — and on operator request.

## Challenge methods

- **HTTP-01** — handler is **passive code that only compiles when
  `spangap-web` is in the graph.** A web-less build skips HTTP-01
  automatically.
- **DNS-01** — the always-on path, via [duckdns](../duckdns) (the only
  TXT-capable provider wired in today).

A `spangap-web`-less build runs **DNS-01-only** and will error at
runtime if no TXT-capable provider is configured.

## Dependencies

- [spangap-net](../spangap-net) — TLS server it hot-reloads into, plus
  the HTTPS client used to talk to the ACME server.
- [duckdns](../duckdns) (optional but practical) — provides DNS-01.
- [spangap-web](../spangap-web) (optional) — enables HTTP-01.

## What it does NOT own

- The TLS server itself — that's in `spangap-net`.
- DNS — that's in `duckdns` (or whichever provider straddle adds TXT
  support in future).
- The public DNS name — supply your own (via DuckDNS or otherwise).

## Read next

- [INTERNALS.md](INTERNALS.md) — flow details, retry policy, key
  rollover, state-file layout.
- Cross-cutting remote-access doc:
  [spangap-core/docs/remote-access.md](../spangap-core/docs/remote-access.md).
