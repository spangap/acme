# acme — internals

## Flow

1. **Account key** — created on first run, stored under
   `secrets.acme.account_key` (EC P-256 PEM).
2. **Order** — POST `newOrder` for the configured domain(s).
3. **Challenge** — pick HTTP-01 (if `spangap-web` is in the graph) or
   DNS-01 (via `duckdns`).
   - HTTP-01: register the well-known URL prefix with `web`, hand the
     token over the wire, poll `validation`.
   - DNS-01: post a TXT record via the DNS provider, poll
     `validation`. DNS propagation backoff is conservative.
4. **Finalize** — submit CSR built from the cert key (also under
   `secrets.acme.*`).
5. **Download** — pull the cert chain, drop into the TLS server's hot-
   reload slot.

## Passive HTTP-01

The HTTP-01 handler is *passive*: its code path only compiles when
`spangap-web` is in the build graph. The DNS-01 path is the always-on
fallback. A web-less build with no DNS provider will fail at runtime —
not at build time — because the choice is at runtime.

## Cron

`acmeInit()` registers a cron entry that wakes the renewal task:
roughly daily when healthy, and at the renewal threshold (typically 30
days before expiry).

## State on disk

Account key and cert key are under `secrets.acme.*` — never sent to
the browser. The cert itself is a public artefact and lives under
`s.acme.cert` (operator can copy it out for diagnostics).

## Why this is its own straddle

The Phase-2 split moved ACME out of `spangap-core` so devices that
don't need a public cert (LAN-only, LoRa-only) don't carry the ACME
client. Add `requires: spangap/acme` to your `straddle.yaml` only when
you actually want it.
