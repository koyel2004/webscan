# SentinelScan — User Guide & Operator Manual

## 1. Introduction

SentinelScan is a comprehensive, non-destructive web security auditing platform. It evaluates the defensive perimeter of web applications by inspecting HTTP security headers, cookie flags, CORS configuration, TLS certificates, information disclosure, and error leakage.

---

## 2. Navigating the Interface

The SentinelScan web interface is organized into 9 specialized workspaces:

1. **Overview**: Executive dashboard showing aggregate risk posture, vulnerability distribution charts (Recharts), recent scans, and common misconfigurations across all audited targets.
2. **New Scan**: Security assessment launcher with real-time target validation, authorization confirmation checkbox, and live progress tracker.
3. **Scan History**: Searchable and filterable registry of all past scans, with status badges, risk scores, duration, and direct links to reports.
4. **Scan Detail**: In-depth inspection view for a specific scan. Displays target metadata, a real-time 7-check execution matrix with millisecond timing, and findings with evidence and remediation code.
5. **Findings Explorer**: Cross-target vulnerability triage table with category filters, severity selectors, search, and a detailed slide-over inspection drawer.
6. **Executive Reports**: Dedicated report generation hub offering one-click downloads of formatted PDF audit reports and machine-readable JSON exports.
7. **Security Methodology**: Public assessment transparency catalog explaining the technical mechanics of all 7 check modules and their CWE/OWASP mappings.
8. **Settings**: Platform operational controls, system health ping, immutable SSRF safety rule display, and one-click demo data seeding.
9. **About & Architecture**: Architectural overview, technical stack description, defensive guarantees, and legal assessment disclaimer.

---

## 3. How to Launch a Security Assessment

### Step 1: Navigate to "New Scan"
Click **New Scan** in the sidebar navigation or click **Launch New Scan** on the Overview dashboard.

### Step 2: Enter Target URL
Enter the fully qualified URL of the target application:
* Examples: `https://example.com`, `https://subdomain.company.org:8443`
* **Supported protocols**: `http://` and `https://`
* **Prohibited inputs**: Local addresses (`http://localhost`, `http://127.0.0.1`), private networks (`http://192.168.1.1`), and cloud metadata (`http://169.254.169.254`) will be rejected by the SSRF safety validator.

### Step 3: Confirm Authorization
Check the mandatory checkbox:
> *"I confirm that I am authorized to perform defensive security assessments against this target domain."*
The launch button remains disabled until this confirmation is checked.

### Step 4: Initiate Scan
Click **Start Security Assessment**. The platform will:
1. Validate URL syntax and verify DNS resolution against public IP ranges.
2. Initialize the scan record in the database.
3. Launch 7 modular security checks asynchronously.
4. Stream check progress in real time.

### In-Flight Cancellation
If you need to halt a running scan, click the red **Cancel Scan** button on the progress banner. The scan engine will abort outstanding HTTP probes and mark the scan status as `CANCELLED`.

---

## 4. Interpreting Results & Grades

### Security Letter Grades
* **Grade A+ (Risk Score 0)**: Flawless defensive posture. Full HSTS, strict CSP, hardened cookies, secure CORS, and minimal information exposure.
* **Grade A (Risk Score 1 – 15)**: Strong defensive configuration with only minor informational findings.
* **Grade B (Risk Score 16 – 30)**: Good security baseline; missing one or two defense-in-depth headers (e.g. Permissions-Policy).
* **Grade C (Risk Score 31 – 50)**: Moderate risk; multiple missing security headers or cookies without `SameSite` flags.
* **Grade D (Risk Score 51 – 75)**: High risk; cookies missing `Secure` or `HttpOnly` flags, or missing HSTS.
* **Grade F (Risk Score > 75 or any Critical Finding)**: Severe security exposure (e.g., CORS origin reflection with credentials enabled, or certificate expiration).

---

## 5. Exporting Security Reports

From either the **Scan Detail** view or the **Reports** workspace:
* **Download Executive PDF**: Generates a professional, print-ready PDF containing executive summaries, posture scorecards, check status tables, and remediation action items.
* **Export JSON Manifest**: Downloads a machine-readable JSON object conforming to security compliance schemas, ideal for automated DevSecOps pipelines.

---

## 6. Frequently Asked Questions & Troubleshooting

### Why is my local development server rejected with an SSRF error?
SentinelScan enforces strict enterprise SSRF safeguards. By default, queries to `localhost`, `127.0.0.1`, RFC 1918 subnets (`192.168.x.x`, `10.x.x.x`), and cloud metadata services are blocked at the socket layer to prevent server-side privilege escalation. To test SentinelScan, use public domains (e.g., `https://example.com`) or seed mock records via **Settings > Populate Demonstration Data**.

### What does "Target Connection Timeout" mean?
If the remote target does not reply within 30 seconds or drops incoming TCP handshakes on port 80/443, the check records a timeout. Check if the target server is active and accessible from the public internet.

### Are cookie values recorded in the database?
Never. In compliance with security and privacy standards, SentinelScan extracts only metadata and flags (`Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`) and replaces all raw cookie values with `***REDACTED***`.
