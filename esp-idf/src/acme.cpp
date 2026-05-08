/**
 * ACME / Let's Encrypt client — DNS-01 and HTTP-01 challenge methods.
 *
 * Implements ACMEv2 (RFC 8555) with ES256 JWS signatures.
 * DNS-01: sets dns.txtrecord config var, resolves TXT via 8.8.8.8 to verify.
 * HTTP-01: writes challenge file to s.acme.webdir, served by web task.
 * Runs on a temporary 16KB task for crypto + HTTPS operations.
 */
#include "acme.h"
#include "tls.h"
#include "fs.h"
#include "storage.h"
#include "cron.h"
#include "cli.h"
#include "log.h"
#include "web.h"
#include "compat.h"
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include "esp_heap_caps.h"
#include <lwip/sockets.h>
#include <sys/stat.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>

#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/bignum.h"
#include "mbedtls/error.h"

#define ACME_DIR "https://acme-v02.api.letsencrypt.org/directory"
#define ACME_TASK_STACK 16384

/* Module config version. Bump when adding/changing defaults. See duckdns.cpp. */
#define ACME_VERSION 1

/* ---- State file helpers (certs on /state/ LittleFS partition) ---- */

static std::string statePath(const char* key) {
    return std::string("/state/") + key + ".pem";
}

static bool stateWrite(const char* key, const uint8_t* data, size_t len) {
    auto path = statePath(key);
    int f = fs_open(path.c_str(), "w");
    if (f < 0) return false;
    size_t written = fs_write(data, 1, len, f);
    fs_close(f);
    return written == len;
}

static bool stateRead(const char* key, std::string& out) {
    auto path = statePath(key);
    struct stat st;
    if (fs_stat(path.c_str(), &st) != 0 || st.st_size <= 0) return false;
    int f = fs_open(path.c_str(), "r");
    if (f < 0) return false;
    out.resize((size_t)st.st_size);
    fs_read(out.data(), 1, (size_t)st.st_size, f);
    fs_close(f);
    return true;
}

/* ---- Base64url ---- */

static std::string b64url(const uint8_t* data, size_t len) {
    size_t olen = 0;
    mbedtls_base64_encode(nullptr, 0, &olen, data, len);
    std::string out(olen, '\0');
    mbedtls_base64_encode((uint8_t*)out.data(), olen, &olen, data, len);
    out.resize(olen);
    while (!out.empty() && out.back() == '=') out.pop_back();
    for (auto& c : out) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return out;
}

static std::string b64url(const std::string& s) {
    return b64url((const uint8_t*)s.data(), s.size());
}

/* ---- Simple JSON helpers ---- */

static std::string jsonStr(const std::string& json, const char* key) {
    std::string search = std::string("\"") + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

/* Extract first string from a JSON array for a given key */
static std::string jsonArrayFirst(const std::string& json, const char* key) {
    std::string search = std::string("\"") + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find('[', pos);
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos) return "";
    return json.substr(pos + 1, end - pos - 1);
}

/* ---- DER signature to raw r||s ---- */

static bool derToRaw(const uint8_t* der, size_t derLen, uint8_t raw[64]) {
    if (derLen < 8 || der[0] != 0x30) return false;
    int idx = 2;
    if (der[1] & 0x80) idx++;  // long form length (unlikely for ECDSA)

    /* R */
    if (der[idx++] != 0x02) return false;
    int rLen = der[idx++];
    const uint8_t* r = &der[idx];
    idx += rLen;

    /* S */
    if (idx >= (int)derLen || der[idx++] != 0x02) return false;
    int sLen = der[idx++];
    const uint8_t* s = &der[idx];

    /* Copy with zero-padding to 32 bytes each, skip leading zeros */
    memset(raw, 0, 64);
    if (rLen > 32) { r += (rLen - 32); rLen = 32; }
    memcpy(raw + (32 - rLen), r, rLen);
    if (sLen > 32) { s += (sLen - 32); sLen = 32; }
    memcpy(raw + 32 + (32 - sLen), s, sLen);
    return true;
}

/* ---- HTTP client with header capture ---- */

struct acme_http_ctx_t {
    std::string body;
    std::string nonce;
    std::string location;
};

static esp_err_t acmeHttpEvent(esp_http_client_event_t* evt) {
    auto* ctx = (acme_http_ctx_t*)evt->user_data;
    if (!ctx) return ESP_OK;
    switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            ctx->body.append((const char*)evt->data, evt->data_len);
            break;
        case HTTP_EVENT_ON_HEADER:
            if (strcasecmp(evt->header_key, "replay-nonce") == 0)
                ctx->nonce = evt->header_value;
            else if (strcasecmp(evt->header_key, "location") == 0)
                ctx->location = evt->header_value;
            break;
        default: break;
    }
    return ESP_OK;
}

struct acme_response_t {
    int status = 0;
    std::string body;
    std::string nonce;
    std::string location;
};

static acme_response_t acmeGet(const char* url) {
    acme_http_ctx_t ctx;
    esp_http_client_config_t config = {};
    config.url = url;
    config.event_handler = acmeHttpEvent;
    config.user_data = &ctx;
    config.timeout_ms = 15000;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.disable_auto_redirect = true;
    auto client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    if (err != ESP_OK) return {};
    return {status, std::move(ctx.body), std::move(ctx.nonce), std::move(ctx.location)};
}

static acme_response_t acmeHead(const char* url) {
    acme_http_ctx_t ctx;
    esp_http_client_config_t config = {};
    config.url = url;
    config.event_handler = acmeHttpEvent;
    config.user_data = &ctx;
    config.timeout_ms = 10000;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.method = HTTP_METHOD_HEAD;
    auto client = esp_http_client_init(&config);
    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    if (err != ESP_OK) return {};
    return {status, "", std::move(ctx.nonce), ""};
}

static acme_response_t acmePost(const char* url, const std::string& jwsBody) {
    acme_http_ctx_t ctx;
    esp_http_client_config_t config = {};
    config.url = url;
    config.event_handler = acmeHttpEvent;
    config.user_data = &ctx;
    config.timeout_ms = 15000;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.method = HTTP_METHOD_POST;
    config.disable_auto_redirect = true;
    auto client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "Content-Type", "application/jose+json");
    esp_http_client_set_post_field(client, jwsBody.c_str(), (int)jwsBody.size());
    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    if (err != ESP_OK) return {};
    return {status, std::move(ctx.body), std::move(ctx.nonce), std::move(ctx.location)};
}

/* ---- DNS TXT resolution via UDP (8.8.8.8, bypasses local cache) ---- */

static bool dnsQueryTxt(const char* name, std::string& out) {
    /* Build DNS query packet for TXT record */
    uint8_t pkt[512];
    int pos = 0;
    /* Header: ID=0x1234, RD=1, QDCOUNT=1 */
    pkt[pos++] = 0x12; pkt[pos++] = 0x34;  /* ID */
    pkt[pos++] = 0x01; pkt[pos++] = 0x00;  /* flags: RD=1 */
    pkt[pos++] = 0x00; pkt[pos++] = 0x01;  /* QDCOUNT=1 */
    pkt[pos++] = 0x00; pkt[pos++] = 0x00;  /* ANCOUNT */
    pkt[pos++] = 0x00; pkt[pos++] = 0x00;  /* NSCOUNT */
    pkt[pos++] = 0x00; pkt[pos++] = 0x00;  /* ARCOUNT */
    /* QNAME: encode dot-separated labels */
    const char* p = name;
    while (*p) {
        const char* dot = strchr(p, '.');
        int labelLen = dot ? (int)(dot - p) : (int)strlen(p);
        if (labelLen > 63 || pos + labelLen + 2 > 480) return false;
        pkt[pos++] = (uint8_t)labelLen;
        memcpy(pkt + pos, p, labelLen); pos += labelLen;
        p = dot ? dot + 1 : p + labelLen;
    }
    pkt[pos++] = 0;  /* root label */
    pkt[pos++] = 0x00; pkt[pos++] = 0x10;  /* QTYPE=TXT(16) */
    pkt[pos++] = 0x00; pkt[pos++] = 0x01;  /* QCLASS=IN */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dns = {};
    dns.sin_family = AF_INET;
    dns.sin_port = htons(53);
    dns.sin_addr.s_addr = inet_addr("8.8.8.8");
    sendto(fd, pkt, pos, 0, (struct sockaddr*)&dns, sizeof(dns));

    uint8_t resp[512];
    int n = recv(fd, resp, sizeof(resp), 0);
    close(fd);
    if (n < 12) return false;

    /* Check response: ID match, QR=1, no error */
    if (resp[0] != 0x12 || resp[1] != 0x34) return false;
    if (!(resp[2] & 0x80)) return false;  /* QR bit */
    if ((resp[3] & 0x0F) != 0) return false;  /* RCODE */
    int anCount = (resp[4] << 8) | resp[5];
    if (anCount == 0) return false;

    /* Skip question section */
    int rpos = 12;
    while (rpos < n && resp[rpos] != 0) {
        if (resp[rpos] & 0xC0) { rpos += 2; break; }
        rpos += 1 + resp[rpos];
    }
    if (resp[rpos] == 0) rpos++;  /* skip root */
    rpos += 4;  /* QTYPE + QCLASS */

    /* Parse first answer */
    for (int a = 0; a < anCount && rpos + 12 <= n; a++) {
        /* Skip name (may be compressed) */
        if (resp[rpos] & 0xC0) rpos += 2;
        else { while (rpos < n && resp[rpos] != 0) rpos += 1 + resp[rpos]; rpos++; }
        if (rpos + 10 > n) return false;
        int atype = (resp[rpos] << 8) | resp[rpos + 1]; rpos += 2;
        rpos += 2;  /* class */
        rpos += 4;  /* TTL */
        int rdlen = (resp[rpos] << 8) | resp[rpos + 1]; rpos += 2;
        if (atype == 16 && rdlen > 1 && rpos + rdlen <= n) {
            /* TXT: first byte is string length */
            int txtLen = resp[rpos];
            if (txtLen > 0 && rpos + 1 + txtLen <= n) {
                out.assign((const char*)&resp[rpos + 1], txtLen);
                return true;
            }
        }
        rpos += rdlen;
    }
    return false;
}

/* Wait for TXT record to appear via DNS resolution (up to 120s) */
static bool waitForTxtRecord(const char* name, const char* expected) {
    for (int i = 0; i < 24; i++) {
        std::string txt;
        if (dnsQueryTxt(name, txt) && txt == expected) {
            info("ACME: TXT record verified\n");
            return true;
        }
        dbg("ACME: TXT not ready (%d/24)\n", i + 1);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
    err("ACME: TXT record not found after 120s\n");
    return false;
}

/* ---- HTTP-01 challenge file helpers ---- */

/* fs_mkdirp() is in fs.h */

/* ---- ACME client state ---- */

struct acme_state_t {
    mbedtls_pk_context accountKey;
    mbedtls_ctr_drbg_context rng;
    mbedtls_entropy_context entropy;
    std::string accountUrl;
    std::string nonce;

    /* Directory URLs */
    std::string newNonce;
    std::string newAccount;
    std::string newOrder;

    std::string domain;

    bool init() {
        mbedtls_pk_init(&accountKey);
        mbedtls_ctr_drbg_init(&rng);
        mbedtls_entropy_init(&entropy);
        return mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy,
                                      (const uint8_t*)"acme", 4) == 0;
    }

    void cleanup() {
        mbedtls_pk_free(&accountKey);
        mbedtls_ctr_drbg_free(&rng);
        mbedtls_entropy_free(&entropy);
    }
};

/* ---- EC P-256 public key extraction ---- */

static bool getEcXY(mbedtls_pk_context* key, uint8_t x[32], uint8_t y[32]) {
    uint8_t der[128];
    int len = mbedtls_pk_write_pubkey_der(key, der, sizeof(der));
    if (len < 65) return false;
    /* P-256 SubjectPublicKeyInfo is 91 bytes, point at offset 26: 04||x(32)||y(32) */
    const uint8_t* p = der + sizeof(der) - len;
    /* Find the uncompressed point marker */
    for (int i = len - 65; i >= 0; i--) {
        if (p[i] == 0x04) {
            memcpy(x, p + i + 1, 32);
            memcpy(y, p + i + 33, 32);
            return true;
        }
    }
    return false;
}

/* ---- JWK thumbprint ---- */

static std::string jwkThumbprint(mbedtls_pk_context* key) {
    uint8_t x[32], y[32];
    if (!getEcXY(key, x, y)) return "";

    /* Canonical JWK (alphabetical keys) */
    std::string jwk = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" +
                       b64url(x, 32) + "\",\"y\":\"" + b64url(y, 32) + "\"}";

    uint8_t hash[32];
    mbedtls_sha256((const uint8_t*)jwk.c_str(), jwk.size(), hash, 0);
    return b64url(hash, 32);
}

/* ---- JWS signing ---- */

static std::string buildJws(acme_state_t& st, const char* url, const std::string& payload) {
    /* Protected header */
    std::string prot;
    if (st.accountUrl.empty()) {
        /* First request: use JWK */
        uint8_t x[32], y[32];
        if (!getEcXY(&st.accountKey, x, y)) return "";
        prot = "{\"alg\":\"ES256\",\"jwk\":{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" +
               b64url(x, 32) + "\",\"y\":\"" + b64url(y, 32) +
               "\"},\"nonce\":\"" + st.nonce + "\",\"url\":\"" + url + "\"}";
    } else {
        /* Subsequent: use kid */
        prot = "{\"alg\":\"ES256\",\"kid\":\"" + st.accountUrl +
               "\",\"nonce\":\"" + st.nonce + "\",\"url\":\"" + url + "\"}";
    }

    std::string protB64 = b64url(prot);
    std::string payloadB64 = payload.empty() ? "" : b64url(payload);
    std::string sigInput = protB64 + "." + payloadB64;

    /* SHA-256 hash of signing input */
    uint8_t hash[32];
    mbedtls_sha256((const uint8_t*)sigInput.c_str(), sigInput.size(), hash, 0);

    /* ECDSA sign */
    uint8_t sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sigLen = 0;
    int ret = mbedtls_pk_sign(&st.accountKey, MBEDTLS_MD_SHA256, hash, 32,
                               sig, sizeof(sig), &sigLen,
                               mbedtls_ctr_drbg_random, &st.rng);
    if (ret != 0) {
        err("JWS sign failed: -0x%04x\n", -ret);
        return "";
    }

    /* DER → raw r||s */
    uint8_t rawSig[64];
    if (!derToRaw(sig, sigLen, rawSig)) {
        err("DER→raw conversion failed\n");
        return "";
    }

    /* Build JWS JSON */
    return "{\"protected\":\"" + protB64 +
           "\",\"payload\":\"" + payloadB64 +
           "\",\"signature\":\"" + b64url(rawSig, 64) + "\"}";
}

/* ---- ACME POST with nonce update ---- */

static acme_response_t acmeJwsPost(acme_state_t& st, const char* url,
                                    const std::string& payload) {
    std::string jws = buildJws(st, url, payload);
    if (jws.empty()) return {};
    auto resp = acmePost(url, jws);
    if (!resp.nonce.empty()) st.nonce = resp.nonce;
    return resp;
}

/* ---- ACME flow ---- */

static bool acmeLoadOrCreateAccountKey(acme_state_t& st) {
    std::string keyPem;
    if (stateRead("acme_key", keyPem)) {
        int ret = mbedtls_pk_parse_key(&st.accountKey, (const uint8_t*)keyPem.c_str(),
                                        keyPem.size(), nullptr, 0,
                                        mbedtls_ctr_drbg_random, &st.rng);
        if (ret == 0) {
            info("loaded ACME account key\n");
            return true;
        }
        err("failed to parse acme_key: -0x%04x\n", -ret);
    }

    /* Generate new account key */
    info("generating ACME account key...\n");
    int ret = mbedtls_pk_setup(&st.accountKey,
                                mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) return false;
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                               mbedtls_pk_ec(st.accountKey),
                               mbedtls_ctr_drbg_random, &st.rng);
    if (ret != 0) { err("keygen: -0x%04x\n", -ret); return false; }

    /* Save to /state/ */
    uint8_t buf[512];
    ret = mbedtls_pk_write_key_pem(&st.accountKey, buf, sizeof(buf));
    if (ret != 0) return false;
    size_t len = strlen((char*)buf) + 1;
    stateWrite("acme_key", buf, len);
    info("ACME account key saved\n");
    return true;
}

static bool acmeLoadOrCreateDomainKey(mbedtls_pk_context* key, mbedtls_ctr_drbg_context* rng) {
    std::string keyPem;
    if (stateRead("tls_key", keyPem)) {
        int ret = mbedtls_pk_parse_key(key, (const uint8_t*)keyPem.c_str(),
                                        keyPem.size(), nullptr, 0,
                                        mbedtls_ctr_drbg_random, rng);
        if (ret == 0) return true;
    }

    /* Generate new domain key */
    info("generating domain key...\n");
    int ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) return false;
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*key),
                               mbedtls_ctr_drbg_random, rng);
    if (ret != 0) return false;

    uint8_t buf[512];
    ret = mbedtls_pk_write_key_pem(key, buf, sizeof(buf));
    if (ret != 0) return false;
    size_t len = strlen((char*)buf) + 1;
    stateWrite("tls_key", buf, len);
    return true;
}

static bool acmeFlow(acme_state_t& st) {
    /* 1. Fetch directory */
    cliPrintf("  Contacting server: %s\n", ACME_DIR);
    info("ACME: fetching directory\n");
    auto dir = acmeGet(ACME_DIR);
    if (dir.status != 200) { err("ACME directory: %d\n", dir.status); return false; }
    st.newNonce = jsonStr(dir.body, "newNonce");
    st.newAccount = jsonStr(dir.body, "newAccount");
    st.newOrder = jsonStr(dir.body, "newOrder");
    if (st.newNonce.empty() || st.newAccount.empty() || st.newOrder.empty()) {
        err("ACME: bad directory\n");
        return false;
    }

    /* 2. Get initial nonce */
    auto nonceResp = acmeHead(st.newNonce.c_str());
    st.nonce = nonceResp.nonce;
    if (st.nonce.empty()) { err("ACME: no nonce\n"); return false; }

    /* 3. Create or find account */
    {
        /* Check if we have a stored account URL */
        char storedUrl[256] = {};
        storageGetStr("s.acme.url", storedUrl, sizeof(storedUrl));
        if (storedUrl[0]) {
            st.accountUrl = storedUrl;
            info("ACME: using account %s\n", st.accountUrl.c_str());
        } else {
            std::string payload =
                "{\"termsOfServiceAgreed\":true,\"onlyReturnExisting\":false}";
            auto resp = acmeJwsPost(st, st.newAccount.c_str(), payload);
            if (resp.status != 200 && resp.status != 201) {
                err("ACME account: %d %s\n", resp.status, resp.body.c_str());
                return false;
            }
            st.accountUrl = resp.location;
            if (st.accountUrl.empty()) { err("ACME: no account URL\n"); return false; }
            storageSet("s.acme.url", st.accountUrl.c_str());
            info("ACME: account created %s\n", st.accountUrl.c_str());
        }
    }

    /* 4. New order */
    info("ACME: creating order for %s\n", st.domain.c_str());
    {
        std::string payload = "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"" +
                               st.domain + "\"}]}";
        auto resp = acmeJwsPost(st, st.newOrder.c_str(), payload);
        if (resp.status != 201) {
            err("ACME order: %d %s\n", resp.status, resp.body.c_str());
            return false;
        }

        std::string authzUrl = jsonArrayFirst(resp.body, "authorizations");
        std::string finalizeUrl = jsonStr(resp.body, "finalize");
        std::string orderUrl = resp.location;
        if (authzUrl.empty() || finalizeUrl.empty()) {
            err("ACME: bad order response\n");
            return false;
        }

        /* 5. Get authorization */
        auto authz = acmeJwsPost(st, authzUrl.c_str(), "");  // POST-as-GET
        if (authz.status != 200) {
            err("ACME authz: %d\n", authz.status);
            return false;
        }

        /* Determine challenge method: explicit override, or auto (DNS-01 if capable, else HTTP-01) */
        char method[16];
        storageGetStr("s.acme.method", method, sizeof(method));
        bool useDns01;
        if (method[0])
            useDns01 = (strcasecmp(method, "HTTP-01") != 0);
        else
            useDns01 = (storageGetInt("dns.txtrecord.capable", 0) != 0);
        const char* challType = useDns01 ? "dns-01" : "http-01";

        /* Find challenge of the selected type */
        auto typePos = authz.body.find(std::string("\"") + challType + "\"");
        if (typePos == std::string::npos) {
            err("ACME: no %s challenge\n", challType);
            return false;
        }
        auto challStart = authz.body.rfind('{', typePos);
        auto challEnd = authz.body.find('}', typePos);
        if (challStart == std::string::npos || challEnd == std::string::npos) return false;
        std::string challObj = authz.body.substr(challStart, challEnd - challStart + 1);
        std::string token = jsonStr(challObj, "token");
        std::string challUrl = jsonStr(challObj, "url");
        if (token.empty() || challUrl.empty()) {
            err("ACME: no token/url in challenge\n");
            return false;
        }

        /* 6. Compute key authorization */
        std::string thumbprint = jwkThumbprint(&st.accountKey);
        std::string keyAuth = token + "." + thumbprint;

        /* 7. Provision challenge response */
        if (useDns01) {
            /* DNS-01: set TXT record via config var, wait for DNS propagation */
            uint8_t keyAuthHash[32];
            mbedtls_sha256((const uint8_t*)keyAuth.c_str(), keyAuth.size(), keyAuthHash, 0);
            std::string txtValue = b64url(keyAuthHash, 32);
            cliPrintf("  Setting DNS TXT record: %s\n", txtValue.c_str());
            info("ACME: setting dns.txtrecord for DNS-01\n");
            storageSet("dns.txtrecord", txtValue.c_str());
            /* Verify TXT record appears via DNS resolution */
            std::string acmeName = "_acme-challenge." + st.domain;
            if (!waitForTxtRecord(acmeName.c_str(), txtValue.c_str())) {
                storageSet("dns.txtrecord", "");
                return false;
            }
        } else {
            /* HTTP-01: write challenge file to s.acme.webdir (dir created in acmeInit) */
            char webdir[128];
            storageGetStr("s.acme.webdir", webdir, sizeof(webdir), "/state/.well-known/acme-challenge");
            char challPath[192];
            snprintf(challPath, sizeof(challPath), "%.127s/%.60s", webdir, token.c_str());
            int cf = fs_open(challPath, "w");
            if (cf < 0) { err("ACME: failed to write %s\n", challPath); return false; }
            fs_write(keyAuth.c_str(), 1, keyAuth.size(), cf);
            fs_close(cf);
            cliPrintf("  Writing HTTP-01 challenge: %s\n", challPath);
            info("ACME: challenge file written to %s\n", challPath);
        }

        /* 8. Respond to challenge */
        info("ACME: responding to challenge\n");
        auto challResp = acmeJwsPost(st, challUrl.c_str(), "{}");
        if (challResp.status != 200) {
            err("ACME challenge: %d %s\n", challResp.status, challResp.body.c_str());
            if (useDns01) storageSet("dns.txtrecord", "");
            return false;
        }

        /* 9. Poll authorization until valid */
        cliPrintf("  Waiting for CA\n");
        info("ACME: polling authorization\n");
        for (int i = 0; i < 24; i++) {  // up to 2 minutes
            vTaskDelay(pdMS_TO_TICKS(5000));
            auto poll = acmeJwsPost(st, authzUrl.c_str(), "");  // POST-as-GET
            std::string status = jsonStr(poll.body, "status");
            if (status == "valid") {
                info("ACME: authorization valid\n");
                break;
            }
            if (status == "invalid") {
                err("ACME: authorization invalid: %s\n", poll.body.c_str());
                if (useDns01) storageSet("dns.txtrecord", "");
                return false;
            }
            dbg("ACME: authz status=%s\n", status.c_str());
        }

        /* 10. Clean up challenge */
        if (useDns01) storageSet("dns.txtrecord", "");

        /* 11. Generate CSR */
        info("ACME: generating CSR\n");
        mbedtls_pk_context domainKey;
        mbedtls_pk_init(&domainKey);
        if (!acmeLoadOrCreateDomainKey(&domainKey, &st.rng)) {
            err("ACME: domain key failed\n");
            mbedtls_pk_free(&domainKey);
            return false;
        }

        mbedtls_x509write_csr csr;
        mbedtls_x509write_csr_init(&csr);
        mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
        std::string cn = "CN=" + st.domain;
        mbedtls_x509write_csr_set_subject_name(&csr, cn.c_str());
        mbedtls_x509write_csr_set_key(&csr, &domainKey);

        uint8_t csrBuf[1024];
        int csrLen = mbedtls_x509write_csr_der(&csr, csrBuf, sizeof(csrBuf),
                                                 mbedtls_ctr_drbg_random, &st.rng);
        mbedtls_x509write_csr_free(&csr);
        if (csrLen < 0) {
            err("ACME: CSR failed: -0x%04x\n", -csrLen);
            mbedtls_pk_free(&domainKey);
            return false;
        }
        /* DER is written at end of buffer */
        std::string csrB64 = b64url(csrBuf + sizeof(csrBuf) - csrLen, (size_t)csrLen);

        /* 12. Finalize order */
        info("ACME: finalizing order\n");
        std::string finPayload = "{\"csr\":\"" + csrB64 + "\"}";
        auto fin = acmeJwsPost(st, finalizeUrl.c_str(), finPayload);
        if (fin.status != 200) {
            err("ACME finalize: %d %s\n", fin.status, fin.body.c_str());
            mbedtls_pk_free(&domainKey);
            return false;
        }

        /* 13. Poll order for certificate URL */
        std::string certUrl;
        for (int i = 0; i < 12; i++) {  // up to 1 minute
            /* Check this response first */
            certUrl = jsonStr(fin.body, "certificate");
            if (!certUrl.empty()) break;
            std::string orderStatus = jsonStr(fin.body, "status");
            if (orderStatus == "invalid") {
                err("ACME: order invalid\n");
                mbedtls_pk_free(&domainKey);
                return false;
            }
            vTaskDelay(pdMS_TO_TICKS(5000));
            fin = acmeJwsPost(st, orderUrl.c_str(), "");  // POST-as-GET
        }
        if (certUrl.empty()) {
            err("ACME: no certificate URL\n");
            mbedtls_pk_free(&domainKey);
            return false;
        }

        /* 14. Download certificate chain */
        info("ACME: downloading certificate\n");
        auto cert = acmeJwsPost(st, certUrl.c_str(), "");  // POST-as-GET
        if (cert.status != 200 || cert.body.empty()) {
            err("ACME cert download: %d\n", cert.status);
            mbedtls_pk_free(&domainKey);
            return false;
        }

        /* 15. Store cert chain to /state/ */
        /* cert.body is the PEM chain (server cert + intermediate) */
        std::string certPem = cert.body;
        if (certPem.back() != '\0') certPem.push_back('\0');  // NUL-terminate for mbedTLS
        info("ACME: cert chain %d bytes\n", (int)certPem.size());
        if (!stateWrite("tls_cert", (const uint8_t*)certPem.c_str(), certPem.size())) {
            err("ACME: failed to save cert to /state/ (%d bytes)\n", (int)certPem.size());
            mbedtls_pk_free(&domainKey);
            return false;
        }

        /* Save domain key PEM (may already be saved, but ensure consistency) */
        uint8_t keyBuf[512];
        int keyRet = mbedtls_pk_write_key_pem(&domainKey, keyBuf, sizeof(keyBuf));
        mbedtls_pk_free(&domainKey);
        if (keyRet == 0) {
            size_t keyLen = strlen((char*)keyBuf) + 1;
            if (!stateWrite("tls_key", keyBuf, keyLen))
                err("ACME: failed to save key to /state/\n");
        }

        /* 16. Reload TLS */
        tlsReloadCert();
        info("ACME: certificate installed for %s\n", st.domain.c_str());
    }

    return true;
}

/* ---- Task ---- */

static void acmeTask(void* arg) {
    acme_state_t st;
    if (!st.init()) { err("ACME: init failed\n"); goto done; }

    {
        char fqdn[64];
        storageGetStr("s.net.dns.fqdn", fqdn, sizeof(fqdn));
        if (!fqdn[0]) { err("ACME: no s.net.dns.fqdn\n"); goto done; }
        st.domain = fqdn;
    }

    if (!acmeLoadOrCreateAccountKey(st)) { err("ACME: account key failed\n"); goto done; }

    if (acmeFlow(st))
        info("ACME: renewal complete\n");
    else
        err("ACME: renewal failed\n");

done:
    st.cleanup();
    auto sem = (SemaphoreHandle_t)arg;
    if (sem) xSemaphoreGive(sem);
    killSelf();
}

/* ---- Public API ---- */

static bool acmeConfigured() {
    char fqdn[64];
    storageGetStr("s.net.dns.fqdn", fqdn, sizeof(fqdn));
    return fqdn[0] && storageGetInt("s.acme.enable");
}

void acmeCheck(int minDays) {
    if (!acmeConfigured()) return;

    /* Need valid time for expiry check */
    time_t now = time(nullptr);
    if (now < 1735689600) return;  // before 2025-01-01

    /* Decide whether renewal is needed and build a user-visible reason */
    bool needRenew = false;
    char reason[96] = {};
    std::string certPem;
    if (stateRead("tls_cert", certPem)) {
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);
        int ret = mbedtls_x509_crt_parse(&crt, (const uint8_t*)certPem.c_str(), certPem.size());
        if (ret == 0) {
            bool selfSigned = (crt.issuer_raw.len == crt.subject_raw.len &&
                               memcmp(crt.issuer_raw.p, crt.subject_raw.p, crt.issuer_raw.len) == 0);
            if (selfSigned) {
                snprintf(reason, sizeof(reason), "No CA-signed cert found");
                needRenew = true;
            } else {
                struct tm expiry = {};
                expiry.tm_year = crt.valid_to.year - 1900;
                expiry.tm_mon = crt.valid_to.mon - 1;
                expiry.tm_mday = crt.valid_to.day;
                expiry.tm_hour = crt.valid_to.hour;
                expiry.tm_min = crt.valid_to.min;
                expiry.tm_sec = crt.valid_to.sec;
                time_t expiryTime = mktime(&expiry);
                int daysLeft = (int)((expiryTime - now) / 86400);
                if (daysLeft > minDays) {
                    mbedtls_x509_crt_free(&crt);
                    return;  // cert is fine, nothing to do
                }
                snprintf(reason, sizeof(reason),
                         "Cert not valid for at least %d more days (%d left)",
                         minDays, daysLeft);
                needRenew = true;
            }
        } else {
            snprintf(reason, sizeof(reason), "Existing cert unparseable");
            needRenew = true;
        }
        mbedtls_x509_crt_free(&crt);
    } else {
        snprintf(reason, sizeof(reason), "No CA-signed cert found");
        needRenew = true;
    }

    if (!needRenew) return;

    char fqdn[64] = {};
    storageGetStr("s.net.dns.fqdn", fqdn, sizeof(fqdn));
    cliPrintf("  %s\n", reason);
    cliPrintf("  Requesting ACME cert for %s (3 min timeout)\n", fqdn[0] ? fqdn : "?");
    info("ACME: %s — requesting cert for %s\n", reason, fqdn[0] ? fqdn : "?");

    /* Spawn renewal task and wait */
    SemaphoreHandle_t sem = xSemaphoreCreateBinary();
    spawnTask(acmeTask, "acme", ACME_TASK_STACK, sem, 1, 0);
    xSemaphoreTake(sem, pdMS_TO_TICKS(180000));  // 3 minute timeout
    vSemaphoreDelete(sem);
}

void acmeInit() {
    /* Self-register: install own defaults + cron entry on first run / upgrade. */
    int v = storageGetInt("s.acme.version", 0);
    if (v < ACME_VERSION) {
        storageDefault("s.acme.enable", 0);
        storageDefault("s.acme.url", "");
        storageDefault("s.acme.method", "");
        storageDefault("s.acme.webdir", FS_STATE "/.well-known/acme-challenge");
        cronDefault("0 3 * * * N", "cert acme 30");
        storageSet("s.acme.version", ACME_VERSION);
    }

    /* HTTP-01 challenge serving: web maps /.well-known to /state/.well-known. */
    webMapAddIfAbsent("/.well-known", FS_STATE "/.well-known", 0, 0, nullptr);

    /* Pre-create webdir (fs_mkdirp handles PSRAM-safety automatically) */
    char webdir[128];
    storageGetStr("s.acme.webdir", webdir, sizeof(webdir), FS_STATE "/.well-known/acme-challenge");
    fs_mkdirp(webdir);

    cliRegisterCmd("cert acme", [](const char* a) {
        if (strcmp(a, "help") == 0) {
            cliPrintf("  %-*s get/renew ACME cert\n", CLI_HELP_COL, "cert acme [days]");
            return;
        }
        if (!acmeConfigured()) {
            cliPrintf("  ACME not configured (need s.net.dns.fqdn + s.acme.enable=1)\n");
            return;
        }
        int days = *a ? atoi(a) : 30;
        acmeCheck(days);

        /* Report result by re-reading the cert. */
        std::string certPem;
        if (!stateRead("tls_cert", certPem)) { cliPrintf("  No TLS certificate\n"); return; }
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);
        int pr = mbedtls_x509_crt_parse(&crt, (const uint8_t*)certPem.c_str(), certPem.size());
        if (pr == 0) {
            bool selfSigned = (crt.issuer_raw.len == crt.subject_raw.len &&
                               memcmp(crt.issuer_raw.p, crt.subject_raw.p, crt.issuer_raw.len) == 0);
            char buf[128];
            mbedtls_x509_dn_gets(buf, sizeof(buf), &crt.issuer);
            cliPrintf("  Done: %s, %s until %04d-%02d-%02d\n",
                      selfSigned ? "self-signed" : "CA-signed",
                      buf,
                      crt.valid_to.year, crt.valid_to.mon, crt.valid_to.day);
        } else {
            cliPrintf("  Done (cert parse error)\n");
        }
        mbedtls_x509_crt_free(&crt);
    });
}
