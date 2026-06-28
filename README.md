# acme — automatic TLS certificates

**acme** obtains and renews real, publicly-trusted TLS certificates for a
[spangap](../spangap) device from an ACME certificate authority (Let's Encrypt
by default). It runs the full ACMEv2 flow — account, order, domain-validation
challenge, CSR, and download — then drops the certificate and key where
[spangap-net](../spangap-net)'s `tls` server picks them up and hot-swaps them
into the live HTTPS listener without dropping sessions.

## Origins

There is no upstream ACME library here. `acme` is a self-contained ACMEv2
([RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)) client built
directly on mbedTLS: ES256 (ECDSA P-256) JWS signing, an mbedTLS X.509 CSR, an
`esp_http_client` HTTPS transport, and a hand-built UDP DNS resolver for
verifying TXT records. The flow, crypto, and challenge plumbing are in
[INTERNALS.md](INTERNALS.md).

## What it does

When the `acme` straddle is in the build it starts automatically — there is no
init call to make. It registers the `acme` CLI command and, on first run, seeds
a daily cron entry that checks the certificate and renews it when it is missing,
self-signed, or close to expiry. Renewal also runs on operator request from the
CLI or the Settings panel.

A renewal needs three things to be in place:

1. **A public DNS name** for the device, in `s.net.dns.fqdn` (owned by
   [spangap-net](../spangap-net); [duckdns](../duckdns) can keep it pointed at a
   changing IP).
2. **`s.acme.enable = 1`**.
3. **A way to answer the CA's challenge** — either a TXT-record provider for
   DNS-01 (duckdns) or inbound reachability on port 80 for HTTP-01.

With those set, enabling acme (or running `acme renew`) gets a certificate; the
cron entry keeps it fresh. The device then serves HTTPS with a browser-trusted
certificate instead of the self-signed pair `tls` generates at first boot.

### How it interacts with the other straddles

```
            s.net.dns.fqdn          dns.txtrecord
  spangap-net ───────────►  acme  ───────────►  duckdns ──► public DNS TXT
   (tls server)   reads          DNS-01 seam        (publishes the record)
        ▲                          │
        │  tls_cert.pem            │  tls_cert.pem / tls_key.pem
        └────  /state/  ◄──────────┘   (acme writes, tls reloads)
```

- **[spangap-net](../spangap-net)** owns the TLS server and the certificate
  files. acme writes the issued `tls_cert.pem` + `tls_key.pem` onto the state
  store and calls `tlsReloadCert()`; `tls` re-reads them and swaps the live
  context. It also supplies the HTTPS client acme uses to reach the CA. The
  domain name lives in `s.net.dns.fqdn`, which net owns.
- **[duckdns](../duckdns)** answers the DNS-01 challenge. acme sets the
  `dns.txtrecord` storage var to the challenge value; duckdns publishes it as a
  TXT record. duckdns also advertises `dns.txtrecord.capable`, which acme reads
  to auto-select its challenge method.
- **[spangap-web](../spangap-web)** answers the HTTP-01 challenge. The handler
  compiles only when web is in the build (`CONFIG_SPANGAP_WEB`); a web-less
  build runs DNS-01 only.

## Challenge methods

acme proves control of the domain with one of two RFC 8555 challenges, selected
by `s.acme.method`:

| `s.acme.method` | Behaviour |
|---|---|
| `""` (auto) | DNS-01 if a TXT provider is present (`dns.txtrecord.capable = 1`), otherwise HTTP-01. |
| `DNS-01` | Force DNS-01. Needs a TXT-capable provider (duckdns). |
| `HTTP-01` | Force HTTP-01. Needs `spangap-web` in the build and inbound port-80 reachability. |

- **DNS-01** sets a `_acme-challenge.<fqdn>` TXT record (via the `dns.txtrecord`
  seam) and verifies it has propagated by querying `8.8.8.8` directly. It needs
  no inbound connectivity, so it is the path that works behind NAT.
- **HTTP-01** serves the challenge token in-memory at
  `/.well-known/acme-challenge/<token>` — no flash writes — and clears it once
  the authorization resolves. It requires the CA to reach the device on port 80.

On a build without `spangap-web`, HTTP-01 is unavailable: auto-select forces
DNS-01, and an explicit `s.acme.method = HTTP-01` fails loudly at renewal time.

## Storage variables

acme has no ITS port and no configuration socket — storage is the control
surface.

### Settings (`s.acme.*`)

| Key | Default | Meaning |
|---|---|---|
| `s.acme.enable` | `0` | Master switch. Renewal does nothing unless this is `1` (and `s.net.dns.fqdn` is set). |
| `s.acme.method` | `""` | Challenge method: `""` (auto), `DNS-01`, or `HTTP-01`. |
| `s.acme.url` | `""` | The ACME **account URL**, written by acme after the account is created and reused (as the JWS `kid`) on later runs. Leave blank on a fresh device. |

The directory endpoint itself is not configurable — it is hard-coded to Let's
Encrypt production (`https://acme-v02.api.letsencrypt.org/directory`).

### Borrowed keys (read/written, owned elsewhere)

| Key | Owner | Use |
|---|---|---|
| `s.net.dns.fqdn` | [spangap-net](../spangap-net) | The domain to certify. Read at renewal; the Settings panel offers a field to set it. |
| `dns.txtrecord.capable` | [duckdns](../duckdns) | Read to auto-select DNS-01 vs HTTP-01. |
| `dns.txtrecord` | [duckdns](../duckdns) | **Written** by acme during a DNS-01 challenge (the value to publish); cleared when the challenge resolves. |

### State files

The account key, domain key, and certificate are **PEM files on the state
store** (`/state`, or `/sdcard/state` when an SD card is present) — not storage
variables, and never sent to the browser:

| File | Contents |
|---|---|
| `acme_key.pem` | The ACME account private key (EC P-256), created on first run. |
| `tls_key.pem` | The certificate's private key (EC P-256). Shared with `tls`. |
| `tls_cert.pem` | The issued certificate chain. Shared with `tls`. |

`tls_key.pem` and `tls_cert.pem` are the same files spangap-net's `tls` reads:
`tls` writes a self-signed pair there at first boot, and acme overwrites them
with the CA-signed certificate (reusing the existing key if one is present).

## CLI

```
acme                      show ACME config + current certificate state
acme renew [days]         get/renew if the cert is within [days] of expiry (default 30)
```

`acme renew` (or a bare day count, e.g. `acme 30`) triggers a check: if the
certificate is missing, self-signed, unparseable, or within `days` of expiry, it
runs a renewal and waits (up to ~3 minutes). Bare `acme` reports whether the
stored certificate is self-signed or CA-signed, its issuer, and its expiry date.
Run on-device with `spangap cli "acme renew"`.

## Dependencies

- [spangap-net](../spangap-net) — the TLS server acme hot-reloads into, and the
  HTTPS client it uses to reach the CA. Hard dependency.
- [duckdns](../duckdns) — provides DNS-01 (the TXT-record provider). Practically
  required for a NAT'd device; injected by the build when staged.
- [spangap-web](../spangap-web) — enables HTTP-01. Optional; the handler
  compiles away when web is absent.

## What it does NOT own

- The TLS server and the HTTPS listener — [spangap-net](../spangap-net).
- The public DNS name and TXT publishing — [duckdns](../duckdns) (or another
  provider you wire to the `dns.txtrecord` seam).

## Read next

- [INTERNALS.md](INTERNALS.md) — the full ACMEv2 flow, JWS/ES256 signing, the
  DNS verifier, challenge-method selection, the renewal task, and pitfalls.
- [spangap-core/docs/remote-access.md](../spangap-core/docs/remote-access.md) —
  the cross-cutting UPnP / DuckDNS / ACME overview.
