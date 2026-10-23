# SentinelScan — REST API Reference Specification

All endpoints are versioned under the `/api/v1` namespace.

---

## 1. System & Health

### `GET /api/v1/health`
Retrieves service operational health and database connectivity.
* **Response (200 OK)**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": "connected",
  "active_scans": 0,
  "timestamp": "2026-10-22T12:00:00Z"
}
```

### `GET /api/v1/methodology`
Returns catalog of active security check suites and their CWE associations.
* **Response (200 OK)**:
```json
{
  "checks": [
    {
      "check_type": "https_redirect",
      "name": "HTTPS Redirect & Enforcement",
      "description": "Verifies that unencrypted HTTP requests are permanently redirected to HTTPS.",
      "cwe_ids": ["CWE-311", "CWE-319"]
    },
    {
      "check_type": "security_headers",
      "name": "HTTP Security Headers",
      "description": "Analyzes presence and strength of CSP, HSTS, XCTO, XFO, Referrer, and Permissions policies.",
      "cwe_ids": ["CWE-693", "CWE-1021"]
    }
  ]
}
```

---

## 2. Dashboard & Analytics

### `GET /api/v1/dashboard`
Aggregated security metrics, posture statistics, and recent activity.
* **Response (200 OK)**:
```json
{
  "total_scans": 12,
  "total_findings": 47,
  "average_risk_score": 28.5,
  "severity_breakdown": {
    "CRITICAL": 1,
    "HIGH": 6,
    "MEDIUM": 18,
    "LOW": 14,
    "INFO": 8
  },
  "grade_distribution": {
    "A+": 2,
    "A": 3,
    "B": 4,
    "C": 2,
    "D": 1,
    "F": 0
  },
  "recent_scans": [
    {
      "id": "c1f7a4e0-...",
      "target_url": "https://example.com",
      "status": "COMPLETED",
      "security_grade": "A",
      "risk_score": 10,
      "findings_count": 2,
      "started_at": "2026-10-22T10:30:00Z"
    }
  ],
  "common_misconfigurations": [
    {
      "title": "Missing Content-Security-Policy (CSP) Header",
      "count": 9,
      "severity": "MEDIUM"
    }
  ]
}
```

### `POST /api/v1/dashboard/seed-demo`
Populates the database with realistic demonstration assessment records for evaluation.
* **Response (200 OK)**:
```json
{
  "message": "Demo data populated successfully",
  "scans_created": 3
}
```

---

## 3. Scans Management

### `POST /api/v1/scans`
Initiates a new defensive security assessment.
* **Request Body**:
```json
{
  "target_url": "https://example.com",
  "authorized_confirmation": true
}
```
* **Validation Rules**:
  * `target_url`: Must be a valid HTTP or HTTPS URL.
  * Target must resolve to a valid, publicly routable IP address (SSRF protection blocks `localhost`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, etc.).
  * `authorized_confirmation`: Must be explicitly `true`.
* **Response (201 Created)**:
```json
{
  "id": "e2d3b4a5-...",
  "target_url": "https://example.com",
  "status": "PENDING",
  "total_checks": 7,
  "completed_checks": 0,
  "created_at": "2026-10-22T12:00:00Z"
}
```

### `GET /api/v1/scans`
List past scans with pagination and status filters.
* **Query Parameters**:
  * `status` (optional): `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`
  * `limit` (default: 50, max: 100)
  * `offset` (default: 0)
* **Response (200 OK)**: Array of scan summaries.

### `GET /api/v1/scans/{scan_id}`
Retrieves complete scan execution details, check status matrix, and all associated findings.
* **Response (200 OK)**:
```json
{
  "id": "e2d3b4a5-...",
  "target_url": "https://example.com",
  "status": "COMPLETED",
  "total_checks": 7,
  "completed_checks": 7,
  "risk_score": 15,
  "security_grade": "A",
  "duration_seconds": 2.45,
  "check_results": [
    {
      "check_type": "https_redirect",
      "status": "SUCCESS",
      "execution_time_ms": 280,
      "findings_count": 0
    }
  ],
  "findings": [
    {
      "id": "f9a8b7c6-...",
      "check_type": "security_headers",
      "severity": "LOW",
      "title": "Missing Permissions-Policy Header",
      "description": "The server does not restrict browser APIs such as geolocation or microphone.",
      "evidence": "Header 'Permissions-Policy' was not found in response.",
      "remediation": "Add Permissions-Policy: camera=(), microphone=(), geolocation=() to server config.",
      "cwe_id": "CWE-693"
    }
  ]
}
```

### `POST /api/v1/scans/{scan_id}/cancel`
Cancels an actively running scan.
* **Response (200 OK)**:
```json
{
  "message": "Scan cancellation requested successfully",
  "id": "e2d3b4a5-...",
  "status": "CANCELLED"
}
```

### `DELETE /api/v1/scans/{scan_id}`
Deletes a scan record and cascades deletion to all findings and check logs.
* **Response (204 No Content)**.

---

## 4. Findings Explorer

### `GET /api/v1/findings`
Query findings across all scans with comprehensive filters.
* **Query Parameters**:
  * `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
  * `check_type`: e.g., `security_headers`, `cors_config`, `cookie_security`
  * `query`: Keyword search against title, description, or CWE ID
  * `limit`: Page size
  * `offset`: Page offset
* **Response (200 OK)**:
```json
{
  "total": 1,
  "items": [
    {
      "id": "f9a8b7c6-...",
      "scan_id": "e2d3b4a5-...",
      "target_url": "https://example.com",
      "check_type": "cors_config",
      "severity": "CRITICAL",
      "title": "Insecure CORS Policy with Reflected Origin and Credentials",
      "cwe_id": "CWE-942"
    }
  ]
}
```

---

## 5. Security Reports

### `GET /api/v1/reports/{scan_id}/pdf`
Generates or retrieves a formatted, executive and technical PDF audit report.
* **Response (200 OK)**: `application/pdf` with header `Content-Disposition: attachment; filename="SentinelScan-Report-{scan_id}.pdf"`.

### `GET /api/v1/reports/{scan_id}/json`
Generates or retrieves structured JSON security audit results for automation and SIEM.
* **Response (200 OK)**: `application/json` with complete audit metadata, telemetry, check matrices, and sanitized findings.
