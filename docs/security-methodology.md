# SentinelScan — Security Assessment Methodology

## 1. Defensive & Non-Destructive Principles

SentinelScan adheres strictly to defensive security analysis guidelines:
* **No Active Exploitation**: Does not inject payloads, exploit race conditions, attempt SQL injection, or tamper with business logic.
* **No Credential Attacks**: Does not perform password guessing, brute force, or credential stuffing.
* **No Resource Exhaustion**: Imposes strict 2 MB response limits, small request windows, and connection timeouts to prevent denial of service.
* **Strict Privacy & Redaction**: Never logs or records sensitive cookie values, session tokens, or API secrets.

---

## 2. Assessment Modules (Check Suite)

### Check A: HTTPS Redirect & Protocol Enforcement
* **Objective**: Ensure that all unencrypted HTTP traffic is systematically upgraded to TLS-encrypted HTTPS.
* **Mechanism**: Initiates a plaintext HTTP request to the target domain on port 80 and analyzes the response:
  * Verifies redirection to an `https://` target URL.
  * Evaluates redirect status codes (`301 Moved Permanently` or `308 Permanent Redirect` are preferred; `302/307` temporary redirects trigger warnings).
  * Evaluates immediate TLS handshake and HSTS presence.
* **CWE Mapping**: CWE-311 (Missing Encryption of Sensitive Data), CWE-319 (Cleartext Transmission of Sensitive Information).
* **OWASP**: A02:2021 – Cryptographic Failures.

### Check B: HTTP Security Response Headers
* **Objective**: Verify browser defense headers designed to mitigate XSS, clickjacking, MIME sniffing, and unintended cross-origin embedding.
* **Inspected Headers**:
  * `Content-Security-Policy (CSP)`: Requires restrictive directives (`default-src`, `script-src`). Flags missing policies (Medium/High) or unsafe constructs like `unsafe-inline` and `unsafe-eval` without nonces/hashes.
  * `Strict-Transport-Security (HSTS)`: Requires `max-age` >= 15724800 (6 months). Recommends `includeSubDomains` and `preload`.
  * `X-Content-Type-Options`: Requires `nosniff` to prevent browser MIME-type confusion attacks.
  * `X-Frame-Options`: Requires `DENY` or `SAMEORIGIN` to mitigate UI redress / clickjacking.
  * `Referrer-Policy`: Requires safe leak-prevention policies (e.g., `strict-origin-when-cross-origin`, `no-referrer`).
  * `Permissions-Policy`: Requires explicit restriction of sensitive browser hardware APIs (e.g., `camera=()`, `microphone=()`, `geolocation=()`).
* **CWE Mapping**: CWE-693 (Protection Mechanism Failure), CWE-1021 (Improper Restriction of Rendered UI Layers).

### Check C: Cookie Security Attributes
* **Objective**: Guarantee that all cookies transmitted by the server are protected against eavesdropping and cross-site theft.
* **Attributes Audited**:
  * `Secure` flag: Missing on HTTPS contexts triggers High/Medium finding.
  * `HttpOnly` flag: Missing on session/stateful cookies triggers High/Medium finding.
  * `SameSite` attribute: Must be set to `Lax`, `Strict`, or explicitly configured `None; Secure`. Missing `SameSite` flags potential CSRF exposure.
  * Cookie Scope: Excessive domain scope (e.g., `.domain.com` exposing subdomains) or open path (`/`).
* **Data Masking**: All cookie values are automatically stripped and replaced with `***REDACTED***` prior to storage or display.
* **CWE Mapping**: CWE-614 (Sensitive Cookie in HTTPS Without 'Secure' Attribute), CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag), CWE-1275 (Sensitive Cookie with Improper SameSite Attribute).

### Check D: Cross-Origin Resource Sharing (CORS) Policy
* **Objective**: Detect permissive or dynamically reflected cross-origin sharing headers that expose authenticated API endpoints to attacker-controlled origins.
* **Probes**:
  * Origin reflection probe with arbitrary third-party origin: `https://evil-untrusted-origin.com`.
  * Null origin probe: `Origin: null`.
* **Vulnerability Criteria**:
  * **Critical**: Target reflects untrusted origin in `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true`.
  * **Medium**: Target uses wildcard `*` with sensitive API endpoints.
* **CWE Mapping**: CWE-346 (Origin Validation Error), CWE-942 (Permissive Cross-Domain Policy with Untrusted Domains).

### Check E: TLS Certificate & Cipher Integrity
* **Objective**: Validate the cryptographic validity, expiration, and coverage of the target's public key certificate.
* **Evaluated Parameters**:
  * Certificate Expiration: Calculates remaining days until expiry. Flags expired (< 0 days) as High, expiring soon (< 30 days) as Medium, (< 7 days) as High.
  * Hostname Matching: Verifies Common Name (CN) and Subject Alternative Names (SAN) match the target domain.
  * Trust Chain: Validates CA signature and trust store status.
* **CWE Mapping**: CWE-295 (Improper Certificate Validation), CWE-298 (Impending Expiration of Certificate).

### Check F: Server Information Disclosure
* **Objective**: Identify headers and banners that leak server software, runtime versions, or infrastructure topologies to potential adversaries.
* **Inspected Headers**:
  * `Server`: Version disclosure (e.g., `Apache/2.4.41`, `nginx/1.18.0`).
  * `X-Powered-By`: Framework disclosure (e.g., `PHP/7.4.3`, `Express`, `ASP.NET`).
  * `X-AspNet-Version`, `X-Runtime`, `X-Generator`.
* **CWE Mapping**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

### Check G: Response Hygiene & Error Leakage
* **Objective**: Audit HTTP responses for leaked debugging information, stack traces, internal paths, or unencrypted assets.
* **Detection Criteria**:
  * Unhandled exception stack traces: Python (`Traceback (most recent call last)`), Java (`Exception in thread`, `java.lang.NullPointerException`), PHP fatal error traces.
  * Active debug modes: Django debug page, Laravel Whoops screen, ASP.NET yellow screen of death.
  * Protocol Downgrade: Mixed content resource references (`http://` assets on an `https://` page).
* **CWE Mapping**: CWE-209 (Generation of Error Message Containing Sensitive Information).

---

## 3. Scoring & Grade Rubric

SentinelScan calculates a deterministic Risk Score ($R \in [0, 100]$) and maps it to an industry-standard Security Letter Grade:

$$\text{Risk Score} = \min(100, \sum \text{Finding Penalties})$$

### Finding Severity Deductions
| Severity | Penalty Points | Action Required |
|:---|:---:|:---|
| **CRITICAL** | 40 | Immediate intervention required; critical exposure. |
| **HIGH** | 20 | Remediate within 24-48 hours. |
| **MEDIUM** | 10 | Remediate during standard sprint cycle. |
| **LOW** | 5 | Defense-in-depth hardening. |
| **INFO** | 0 | Informational hygiene finding; no score deduction. |

### Letter Grade Mapping
* **Grade A+**: Risk Score 0 (Zero findings, all hardening headers present and strict).
* **Grade A**: Risk Score 1 – 15 (Minor informational or low findings).
* **Grade B**: Risk Score 16 – 30 (Few low or single medium finding).
* **Grade C**: Risk Score 31 – 50 (Multiple medium findings).
* **Grade D**: Risk Score 51 – 75 (High severity finding or extensive misconfigurations).
* **Grade F**: Risk Score > 75 or any **CRITICAL** finding present.
