# acme — internals

Maintainer reference for the ACMEv2 client. The [README](README.md) is the
operator guide; this document is for changing the code without breaking it.
Everything lives in [`esp-idf/src/acme.cpp`](esp-idf/src/acme.cpp); the public
header is [`esp-idf/include/acme.h`](esp-idf/include/acme.h).

## 1. Everything this straddle owns or touches

acme has no upstream library and no ITS port. Its entire footprint is a CLI
command, a cron entry, a set of storage keys, three PEM files on the state
store, and (when web is present) one HTTP URL handler.

**State files** — on the state store via `fsStateDir()` (`/state`, or
`/sdcard/state` when an SD card is mounted); never hard-coded, never exposed to
the browser:

- `acme_key.pem` — the ACME **account** private key (EC P-256). Created and
  saved on first run; reloaded thereafter so the account is stable.
- `tls_key.pem` — the **certificate** (domain) private key (EC P-256). Shared
  with spangap-net's `tls`: acme reuses an existing one if present, otherwise
  generates and saves it.
- `tls_cert.pem` — the issued certificate chain (leaf + intermediate). Written
  on a successful order; read back by `acme` (CLI status) and by `tls`.

**Storage keys it owns** (`s.acme.*`):

- `s.acme.enable` (default `0`) — master switch, read by `acmeConfigured()`.
- `s.acme.method` (default `""`) — challenge override: `""`/`DNS-01`/`HTTP-01`.
- `s.acme.url` (default `""`) — the ACME **account URL** (RFC 8555 *account*
  resource), written after `newAccount` and reused as the JWS `kid`. This is the
  account, **not** the directory; the directory endpoint is the hard-coded
  `ACME_DIR` constant.

**Borrowed keys** (owned by other straddles):

- `s.net.dns.fqdn` (spangap-net) — read as the domain to certify.
- `dns.txtrecord.capable` (duckdns) — read for auto method selection.
- `dns.txtrecord` (duckdns) — **written** with the DNS-01 challenge value, then
  cleared. This is the integration seam: acme sets it, duckdns publishes the TXT
  record on change.

**Cron entry** — `s.cron.tab.acme = "0 3 * * * N acme renew 30"`, present
exactly while ACME is configured (`s.acme.enable` + `s.net.dns.fqdn`):
`acmeApplyCron()` installs it with `storageDefault` (a user's schedule tweak
survives while configured) and removes it on disable, applied at init and via
storage-task-hosted subscriptions on both gate keys. That is **daily at 03:00**,
with the `N` flag ("upstream network required"), running `acme renew 30`.
Renewal is cron-driven: `acmeCheck()` has **no boot-time caller** — nothing runs
it at startup.

**HTTP-01 URL handler** — registered only under `CONFIG_SPANGAP_WEB`:
`webRegisterHandler(".well-known/acme-challenge", acmeHttp01Handler)`. It serves
the challenge response from two in-memory strings; no flash is touched.

**CLI** — `acme` (status) and `acme renew [days]` (check/renew), registered in
`acmeInit()`.

## 2. The renewal task

`acmeCheck(minDays)` runs on the caller's task (cron or CLI). It:

1. Bails unless `acmeConfigured()` (`s.net.dns.fqdn` set **and**
   `s.acme.enable = 1`).
2. Bails if the wall clock is invalid (`time() < 2025-01-01`) — expiry math and
   JWS need a real time.
3. Reads `tls_cert.pem` and decides if renewal is due: **missing**, **parse
   error**, **self-signed** (issuer == subject), or **within `minDays` of
   expiry** all trigger a renewal; a healthy CA-signed cert with margin returns
   without doing anything.
4. If due, spawns the worker task and **blocks on a binary semaphore for up to
   180 s** (`spawnTask(acmeTask, "acme", 16384, sem, prio 1, core 0)`).

The worker runs the ACME flow on a temporary **16 KB** stack and `killSelf()`s
when done, giving the semaphore back. Because `acmeCheck()` blocks until the
worker finishes (or times out), renewals are serialized by construction — cron
and CLI never overlap.

The worker, in order: registers the HTTP-01 handler (lazily — see §5), reads
`s.net.dns.fqdn` into `st.domain`, loads-or-creates the account key, then runs
`acmeFlow()`.

## 3. The ACME flow (`acmeFlow`)

Standard ACMEv2 against `ACME_DIR`
(`https://acme-v02.api.letsencrypt.org/directory`):

1. **Directory** — GET `ACME_DIR`; extract `newNonce`/`newAccount`/`newOrder`.
2. **Nonce** — HEAD `newNonce` for the first `Replay-Nonce`.
3. **Account** — if `s.acme.url` is already stored, reuse it; otherwise POST
   `newAccount` (`termsOfServiceAgreed:true`), take the `Location` header as the
   account URL, and persist it to `s.acme.url`.
4. **Order** — POST `newOrder` with the single DNS identifier; capture the
   authorization, finalize, and order URLs.
5. **Authorization** — POST-as-GET the authz; select the challenge (§5); read
   its `token` and `url`.
6. **Key authorization** — `token + "." + jwkThumbprint(accountKey)`.
7. **Provision** — DNS-01: SHA-256 the key-auth, base64url it, set
   `dns.txtrecord`, and wait for it to appear via direct DNS (§4). HTTP-01:
   stash `(token, keyAuth)` for the URL handler.
8. **Respond** — POST `{}` to the challenge URL.
9. **Poll authz** — POST-as-GET every 5 s for up to 2 minutes; `valid`
   proceeds, `invalid` aborts. The challenge response is cleared on every exit
   path (`clearChallenge`).
10. **CSR** — load-or-create the domain key (`tls_key.pem`), build an mbedTLS
    X.509 CSR (`CN=<domain>`, SHA-256), DER-encode it.
11. **Finalize** — POST the base64url DER CSR to the finalize URL.
12. **Poll order** — POST-as-GET the order URL until a `certificate` URL
    appears (up to 1 minute); `invalid` aborts.
13. **Download** — POST-as-GET the certificate URL; the body is the PEM chain.
14. **Install** — NUL-terminate the chain, write `tls_cert.pem`, re-save
    `tls_key.pem`, and call `tlsReloadCert()` to hot-swap the live listener.

All POSTs go through `acmeJwsPost()`, which builds a JWS (§6) and feeds the
returned `Replay-Nonce` back into state for the next request. POST-as-GET is a
JWS over an empty payload.

## 4. DNS-01 verification

`dnsQueryTxt()` builds a raw DNS TXT query packet by hand and sends it over UDP
to **`8.8.8.8:53`** directly (5 s socket timeout), bypassing any local resolver
cache so a freshly-published record is seen as soon as it propagates to Google's
resolver. It parses the first TXT answer (handling name compression) and
compares it to the expected value. `waitForTxtRecord()` polls this 24 times at
5 s intervals (up to 120 s) before giving up. acme sets `dns.txtrecord` and
trusts duckdns to publish; the direct query is what confirms propagation.

## 5. Challenge-method selection and HTTP-01

Selection happens in `acmeFlow` after the authorization is fetched:

- **With `CONFIG_SPANGAP_WEB`:** an explicit `s.acme.method` wins (anything other
  than `HTTP-01` means DNS-01); empty means auto — DNS-01 when
  `dns.txtrecord.capable` is set, else HTTP-01.
- **Without `CONFIG_SPANGAP_WEB`:** DNS-01 is forced. An explicit
  `s.acme.method = HTTP-01` is rejected with a loud error rather than silently
  falling back.

The HTTP-01 handler (`acmeHttp01Handler`, `#if CONFIG_SPANGAP_WEB`) serves the
key authorization from `http01Token` / `http01KeyAuth` — two static strings set
for the duration of one attempt and cleared afterward. It strict-compares the
requested token against the single in-flight token (no path traversal, no flash
write). The handler is registered at the **start of `acmeTask`**, not in
`acmeInit()`: `acmeInit()` runs before `webInit()`, so registering earlier would
race the web server's startup. `webRegisterHandler` is idempotent.

## 6. JWS signing (ES256)

Every authenticated request is an ES256 JWS:

- The protected header carries `jwk` on the very first request (account
  creation) and `kid` (the account URL) thereafter.
- mbedTLS signs the SHA-256 of `<protected>.<payload>` and returns a **DER**
  ECDSA signature; ACME requires the raw `r || s` form, so `derToRaw()`
  unpacks the DER into a fixed 64-byte buffer (zero-padding each half to 32
  bytes, skipping leading zeros).
- `jwkThumbprint()` builds the canonical (alphabetically-keyed) JWK JSON and
  SHA-256/base64url's it for the key authorization.
- `getEcXY()` pulls the raw P-256 public point out of the mbedTLS
  SubjectPublicKeyInfo DER to populate the JWK `x`/`y`.

JSON parsing is intentionally minimal (`jsonStr` / `jsonArrayFirst` do flat
string-find extraction) — ACME responses are small and well-formed, so there is
no full JSON parser in the path.

## 7. Pitfalls

- **`acmeCheck()` has no boot caller.** Renewal happens only when the cron entry
  fires `acme renew 30` or an operator runs the CLI. Do not assume a fresh boot
  obtains a certificate; the first one is acquired the first time enable is set
  and a renewal is triggered (or the next 03:00 cron tick).
- **Valid wall-clock time is required.** Both the expiry check and JWS rely on a
  real clock; `acmeCheck` bails before 2025-01-01. This is why the cron entry
  carries the `N` flag (real upstream, hence NTP) and why renewal is net-gated.
- **HTTP-01 needs inbound port 80.** The CA fetches the challenge directly, so
  HTTP-01 only works when the device is reachable from the internet (e.g. via
  [upnp](../upnp) or a manual port-forward). Behind NAT with no forward, use
  DNS-01.
- **`tls_key.pem` / `tls_cert.pem` are shared with spangap-net.** `tls` creates
  a self-signed pair into the same files at first boot; acme reuses the existing
  key and overwrites the cert. Don't treat these as acme-private — deleting
  `tls_cert.pem` makes `tls` regenerate self-signed and makes `acmeCheck` decide
  a renewal is due.
- **The account URL is not the directory.** `s.acme.url` is the per-account
  resource URL (JWS `kid`); the directory is the fixed `ACME_DIR`. Clearing
  `s.acme.url` forces a fresh `newAccount` against the same account key
  (`acme_key.pem`), which Let's Encrypt resolves back to the existing account.
- **One order at a time.** `acmeCheck` blocks on the worker's completion
  semaphore, so the single-slot in-memory challenge state (`http01Token`,
  `dns.txtrecord`) is never contended. Don't make `acmeCheck` asynchronous
  without adding real mutual exclusion around that state.
- **Let's Encrypt production only.** `ACME_DIR` is hard-coded to the production
  endpoint — there is no staging switch, so failed attempts count against the
  real rate limits.
