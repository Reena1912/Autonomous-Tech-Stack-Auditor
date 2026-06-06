# 🔍 Tech Stack Audit Report

**Repo:** `/home/runner/work/Autonomous-Tech-Stack-Auditor/Autonomous-Tech-Stack-Auditor`
**Scanned:** 2026-06-06 18:57 UTC
**Overall status:** 🚨 Critical — immediate action required

| 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low | Total |
|:-----------:|:-------:|:---------:|:------:|:-----:|
| 3 | 2 | 0 | 7 | 12 |

---

##  Urgent — Action Required

> These packages have CVEs, are yanked, or are known-deprecated. Do not ship without addressing these.

### 🔴 `flask` — `CRITICAL`

**1 CVE(s) detected:**

- **CVE-2026-27205** → fix in `3.1.3`
  > When the `session` object is accessed, Flask should set the `Vary: Cookie` header. This instructs caches not to cache the response, as it may contain information specific to a logg

**Current spec:** `==2.2.5`  **Latest:** `3.1.3`

---

### 🔴 `urllib3` — `CRITICAL`

**5 CVE(s) detected:**

- **PYSEC-2026-141** → fix in `2.7.0`
  > urllib3 is an HTTP client library for Python. From 1.23 to before 2.7.0, cross-origin redirects followed from the low-level API via ProxyManager.connection_from_url().urlopen(..., 
- **CVE-2025-50181** → fix in `2.5.0`
  > urllib3 handles redirects and retries using the same mechanism, which is controlled by the `Retry` object. The most common way to disable redirects is at the request level, as foll
- **CVE-2025-66418** → fix in `2.6.0`
  > ## Impact  urllib3 supports chained HTTP encoding algorithms for response content according to RFC 9110 (e.g., `Content-Encoding: gzip, zstd`).  However, the number of links in the
- **CVE-2025-66471** → fix in `2.6.0`
  > ### Impact  urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.5.0/advanced-usage.html#streaming-and-i-o) is designed for the efficient handling of large HTTP responses 
- **CVE-2026-21441** → fix in `2.6.3`
  > ### Impact  urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.6.2/advanced-usage.html#streaming-and-i-o) is designed for the efficient handling of large HTTP responses 

**Current spec:** `<2.0`  **Latest:** `2.7.0`

---

### 🔴 `pyjwt` — `CRITICAL`

**6 CVE(s) detected:**

- **PYSEC-2026-120** → fix in `2.12.0`
  > PyJWT is a JSON Web Token implementation in Python. Prior to 2.12.0, PyJWT does not validate the crit (Critical) Header Parameter defined in RFC 7515 §4.1.11. When a JWS token cont
- **PYSEC-2025-183** → fix in `no fix available yet`
  > pyjwt v2.10.1 was discovered to contain weak encryption. NOTE: this is disputed by the Supplier because the key length is chosen by the application that uses the library (admittedl
- **PYSEC-2026-179** → fix in `2.13.0`
  > PyJWT is a JSON Web Token implementation in Python. Prior to 2.13.0, when the verifier is decoding JSON Web Tokens, while supporting both asymmetric and HMAC algorithms, the librar
- **PYSEC-2026-175** → fix in `2.13.0`
  > PyJWT is a JSON Web Token implementation in Python. Prior to 2.13.0, PyJWKClient passes its uri argument directly to urllib.request.urlopen() which uses Python stdlib's default Ope
- **PYSEC-2026-177** → fix in `2.13.0`
  > PyJWT is a JSON Web Token implementation in Python. Prior to 2.13.0, PyJWKClient.get_signing_key() forces a fresh HTTP request to the JWKS endpoint for every JWT with an unknown ki
- **PYSEC-2026-178** → fix in `2.13.0`
  > PyJWT is a JSON Web Token implementation in Python. From 2.8.0 to 2.12.1, when verifying detached JWS tokens using the unencoded-payload option ("b64": false, RFC 7797), PyJWT perf

**Current spec:** `==2.8.0`  **Latest:** `2.13.0`

---

### 🟠 `nose` — `HIGH`

- **Deprecated** — replace with `pytest`

**Current spec:** `==1.3.7`  **Latest:** `1.3.7`

---

### 🟠 `mock` — `HIGH`

- **Deprecated** — replace with `unittest.mock (stdlib)`

**Current spec:** `==5.1.0`  **Latest:** `5.2.0`

---

## ✅ Healthy — No Action Needed

| Package | Spec | Latest | Last Updated |
|---------|------|--------|-------------|
| `cryptography` | `>=41.0` | `48.0.0` | 1mo ago |
| `numpy` | `>=1.24` | `2.4.6` | 4d ago |
| `pandas` | `~=2.0.3` | `3.0.3` | 26d ago |
| `pytest` | `>=7.4` | `9.0.3` | 2mo ago |
| `requests` | `>=2.31.0` | `2.34.2` | 22d ago |
| `scikit-learn` | `>=1.3` | `1.9.0` | 4d ago |
| `sqlalchemy` | `>=2.0` | `2.0.50` | 12d ago |

## 📋 Action Plan

- [ ] **Upgrade `flask`** to `3.1.3` to patch CVE-2026-27205
- [ ] **Upgrade `urllib3`** to `2.7.0` to patch PYSEC-2026-141
- [ ] **Upgrade `urllib3`** to `2.5.0` to patch CVE-2025-50181
- [ ] **Upgrade `urllib3`** to `2.6.0` to patch CVE-2025-66418
- [ ] **Upgrade `urllib3`** to `2.6.0` to patch CVE-2025-66471
- [ ] **Upgrade `urllib3`** to `2.6.3` to patch CVE-2026-21441
- [ ] **Upgrade `pyjwt`** to `2.12.0` to patch PYSEC-2026-120
- [ ] **Investigate `pyjwt`** — PYSEC-2025-183 has no fix yet; consider alternatives
- [ ] **Upgrade `pyjwt`** to `2.13.0` to patch PYSEC-2026-179
- [ ] **Upgrade `pyjwt`** to `2.13.0` to patch PYSEC-2026-175
- [ ] **Upgrade `pyjwt`** to `2.13.0` to patch PYSEC-2026-177
- [ ] **Upgrade `pyjwt`** to `2.13.0` to patch PYSEC-2026-178
- [ ] **Replace `nose`** with `pytest`
- [ ] **Review `nose`** — no release in 11+ years; check for maintained fork
- [ ] **Replace `mock`** with `unittest.mock (stdlib)`

---

*Generated by **Tech Stack Auditor** · Sources: PyPI JSON API, pip-audit (OSS vulnerability DB)*
*This report is a starting point — always verify CVE applicability to your specific usage.*
