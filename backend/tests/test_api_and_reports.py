"""
Integration Tests for REST Endpoints, Reporting Engines, and Database Operations
"""
import logging

from app.core.logging import SensitiveDataFilter
from app.models.scan import Scan, ScanStatus


def test_health_endpoint(client):
    """Health check endpoint returns healthy status and metadata."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app_name"] == "SentinelScan"
    assert "database" in data


def test_methodology_endpoint(client):
    """Methodology endpoint returns documented check specifications and boundaries."""
    response = client.get("/api/methodology")
    assert response.status_code == 200
    data = response.json()
    assert len(data["checks"]) >= 7
    assert "severity_model" in data
    assert "operational_boundaries" in data


def test_create_scan_validation_rules(client):
    """Scan creation must reject unconfirmed authorization and SSRF targets."""
    # 1. Unconfirmed authorization
    res = client.post("/api/scans", json={
        "target_url": "https://example.com",
        "user_authorized": False
    })
    assert res.status_code == 403

    # 2. SSRF Loopback Target
    res = client.post("/api/scans", json={
        "target_url": "http://127.0.0.1",
        "user_authorized": True
    })
    assert res.status_code == 400
    res_str = str(res.json()).lower()
    assert "private" in res_str or "loopback" in res_str or "ssrf" in res_str

    # 3. Invalid port
    res = client.post("/api/scans", json={
        "target_url": "https://example.com:22",
        "user_authorized": True
    })
    assert res.status_code == 400


def test_dashboard_seed_and_summary_flow(client, db_session):
    """Tests seeding demonstration records and reading aggregated metrics."""
    # Seed demo data
    seed_res = client.post("/api/dashboard/seed")
    assert seed_res.status_code == 201

    # Check dashboard summary
    summary_res = client.get("/api/dashboard/summary")
    assert summary_res.status_code == 200
    summary = summary_res.json()

    assert summary["total_scans"] >= 2
    assert summary["total_findings"] >= 6
    assert summary["critical_findings"] >= 1
    assert "CRITICAL" in summary["severity_distribution"]
    assert len(summary["recent_scans"]) >= 2
    assert len(summary["common_misconfigurations"]) >= 1


def test_findings_filtering_and_pagination(client, db_session):
    """Tests querying findings with severity and category filters."""
    client.post("/api/dashboard/seed")

    # Filter by CRITICAL severity
    res = client.get("/api/findings?severity=CRITICAL")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert all(f["severity"] == "CRITICAL" for f in data["items"])

    # Filter by category
    res = client.get("/api/findings?category=tls")
    assert res.status_code == 200
    data = res.json()
    assert all(f["category"] == "tls" for f in data["items"])


def test_pdf_and_json_report_generation(client, db_session):
    """Tests PDF and JSON generation from real saved scan records."""
    client.post("/api/dashboard/seed")
    scan = db_session.query(Scan).first()
    assert scan is not None

    # 1. JSON Report
    json_res = client.get(f"/api/scans/{scan.id}/report.json")
    assert json_res.status_code == 200
    report_json = json_res.json()
    assert report_json["scan_metadata"]["scan_id"] == scan.id
    assert report_json["executive_summary"]["total_findings"] == scan.total_findings
    assert "findings" in report_json

    # 2. PDF Report
    pdf_res = client.get(f"/api/scans/{scan.id}/report.pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000  # Non-trivial PDF binary generated
    assert pdf_res.content.startswith(b"%PDF")


def test_scan_cancellation_and_deletion(client, db_session):
    """Tests scan cancellation and cascading deletion."""
    # Create scan record directly
    scan = Scan(
        target_url="https://test-cancel.com",
        target_hostname="test-cancel.com",
        status=ScanStatus.PENDING,
        user_authorized=True
    )
    db_session.add(scan)
    db_session.commit()

    # Cancel scan
    cancel_res = client.post(f"/api/scans/{scan.id}/cancel")
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

    # Delete scan
    del_res = client.delete(f"/api/scans/{scan.id}")
    assert del_res.status_code == 204

    # Confirm scan no longer exists
    get_res = client.get(f"/api/scans/{scan.id}")
    assert get_res.status_code == 404


def test_sensitive_data_log_filter():
    """Confirms SensitiveDataFilter scrubs credentials and cookies."""
    log_filter = SensitiveDataFilter()

    # Cookie scrubbing
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="Set-Cookie: session_id=SECRET_TOKEN_12345; Secure; HttpOnly",
        args=(), exc_info=None
    )
    log_filter.filter(record)
    assert "SECRET_TOKEN_12345" not in record.msg
    assert "[REDACTED]" in record.msg

    # Auth token scrubbing
    record2 = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="Authorization: Bearer my_secret_jwt_token_here",
        args=(), exc_info=None
    )
    log_filter.filter(record2)
    assert "my_secret_jwt_token_here" not in record2.msg
    assert "[REDACTED]" in record2.msg
