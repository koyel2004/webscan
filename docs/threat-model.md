# SentinelScan — Threat Model & Security Posture Analysis

## 1. Scope & Objective

SentinelScan executes outbound network probes against user-specified web targets. In doing so, it processes untrusted input (target URLs) and ingests untrusted remote HTTP response payloads (headers, cookies, status codes, HTML snippets).

This document details the threat modeling conducted using the **STRIDE** methodology and outlines the defense-in-depth mitigations implemented across the platform.

---

## 2. STRIDE Threat Matrix & Mitigations

| Threat Category | Potential Attack Vector | Severity | Implemented Mitigation | Verification Mechanism |
|:---|:---|:---:|:---|:---|
| **Spoofing** | Attacker scans targets under unauthorized identity. | Low | Scans require explicit confirmation of audit authorization. | API contract enforces `authorized_confirmation: true`. |
| **Tampering** | Attacker modifies stored findings or report files. | Medium | SQLite/PostgreSQL foreign key constraints, parameterized queries via SQLAlchemy 2.0 ORM. | Immutable scan IDs (UUIDv4) and cascading deletion integrity. |
| **Repudiation** | Operator denies initiating an outbound scan. | Low | All scan events, timestamps, and target resolutions are logged to structured logs. | Timestamped scan records with started/completed timestamps. |
| **Information Disclosure** | Leakage of sensitive session tokens, passwords, or cookies in scan results. | **High** | Automatic token and cookie value redaction before persistence or logging. | Unit tests verify `AUTH_COOKIE=***REDACTED***` in DB and PDF reports. |
| **Information Disclosure** | Cloud metadata extraction via SSRF (`169.254.169.254`). | **Critical** | Socket IP pre-resolution and blocklist against link-local, RFC 1918, and metadata CIDR ranges. | Multi-tier `TargetValidator` unit test suite rejecting metadata IPs. |
| **Denial of Service** | Infinite streaming response or gzip compression bomb from hostile target. | **High** | Hard limit of 2,097,152 bytes (2 MB) on incoming HTTP response bodies; timeout limits. | `SafeHttpClient` enforces streaming buffer caps and 30s timeouts. |
| **Denial of Service** | Scanner exhaustion via unbounded concurrent scans. | Medium | Asynchronous semaphore gating (`MAX_CONCURRENT_SCANS=5`). | Requests queued cleanly without starving event loop. |
| **Elevation of Privilege** | Stored XSS via malicious target headers (e.g. `<script>` in `Server:` header). | **High** | React JSX auto-escaping; strict Content-Security-Policy headers in backend and frontend. | Strict CSP `default-src 'self'` prevents injected inline scripts. |

---

## 3. Deep-Dive: Server-Side Request Forgery (SSRF) Defense

Because SentinelScan acts as an HTTP client, SSRF is the primary threat vector. The platform enforces a multi-tier defense:

```
[User Input URL]
       |
       v
[Syntactic Validation]
       |-- Allowed schemes: http, https only
       |-- Block embedded credentials (user:pass@host)
       |-- Reject prohibited ports (SSH:22, Redis:6379, SMTP:25, etc.)
       v
[DNS IP Resolution & Blocklist Barrier]
       |-- Resolve hostname to IPv4/IPv6 addresses via getaddrinfo
       |-- Check each IP against reserved subnets:
       |      - 127.0.0.0/8 & ::1 (Loopback)
       |      - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918)
       |      - 169.254.0.0/16 & fe80::/10 (Link-Local / Cloud Metadata)
       |      - 100.64.0.0/10 (Carrier-Grade NAT)
       |      - 0.0.0.0/8, 224.0.0.0/4 (Multicast/Reserved)
       v
[Controlled Outbound Probe via SafeHttpClient]
       |-- Disallow automated redirect following
       |-- For each HTTP 3xx redirect:
       |      - Extract 'Location' target
       |      - Route 'Location' through DNS IP Resolution & Blocklist Barrier
       |      - Abort if target resolves to private/prohibited subnet
       v
[Payload Inspection with Size Limit (<= 2MB)]
```

### Protection Against Blind Redirect SSRF
A common bypass in naive scanners is pointing the scanner to a public server (`https://attacker.com/redirect`) that returns an HTTP `302 Found` redirecting to `http://169.254.169.254/latest/meta-data/`.
In SentinelScan:
1. `SafeHttpClient` sets `follow_redirects=False` in HTTPX.
2. Every redirect status (`301`, `302`, `303`, `307`, `308`) is intercepted manually.
3. The destination URL is extracted, resolved, and verified against `TargetValidator` before any secondary request is dispatched.
4. If the destination targets a private or metadata address, the redirect chain immediately halts and records a validation error.

---

## 4. Sensitive Data Masking & Privacy

Web scanners frequently encounter cookies and authorization headers containing active session tokens, OAuth tokens, or JWTs. SentinelScan guarantees:
* **Log Redaction**: A specialized `SensitiveDataFilter` operates at the standard library `logging` level, scrubbing all patterns matching `Bearer ...`, `Cookie: ...`, `token=...`, and `password=...`.
* **Database & Report Sanitization**: The `cookie_security` check inspects cookie attributes (`Secure`, `HttpOnly`, `SameSite`) while systematically overwriting the cookie value string with `***REDACTED***`.
* **Zero Persistence of Credentials**: No credentials or sensitive payload values are stored in SQLite or PostgreSQL tables.
