"""
PDF Report Generator for SentinelScan
Builds executive cybersecurity assessment reports using ReportLab.
Includes cover page, metadata tables, findings by severity, evidence, and remediation.
"""
import io
from datetime import UTC, datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.finding import SeverityLevel
from app.models.scan import Scan


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for dynamic total page count in footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count: int):
        if self._pageNumber > 1:  # Skip footer on cover page
            self.saveState()
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(54, 36, "CONFIDENTIAL — SentinelScan Security Assessment")
            page_text = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(letter[0] - 54, 36, page_text)
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 48, letter[0] - 54, 48)
            self.restoreState()


class PDFReportGenerator:
    """Generates professional PDF assessment reports."""

    @classmethod
    def generate_pdf(cls, scan: Scan) -> bytes:
        """Renders scan results to PDF binary buffer."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        styles = getSampleStyleSheet()

        # Custom Palette & Styles
        primary_color = colors.HexColor("#0f172a")  # Slate 900
        accent_color = colors.HexColor("#0284c7")   # Sky 600
        text_dark = colors.HexColor("#1e293b")      # Slate 800

        title_style = ParagraphStyle(
            "CoverTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=primary_color,
            alignment=0,
            spaceAfter=10,
        )
        subtitle_style = ParagraphStyle(
            "CoverSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=13,
            leading=18,
            textColor=accent_color,
            spaceAfter=24,
        )
        h1_style = ParagraphStyle(
            "SectionH1",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=primary_color,
            spaceBefore=14,
            spaceAfter=8,
        )
        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=accent_color,
            spaceBefore=10,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=text_dark,
            spaceAfter=6,
        )
        meta_label = ParagraphStyle(
            "MetaLabel",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=primary_color,
        )
        meta_val = ParagraphStyle(
            "MetaVal",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=text_dark,
        )
        code_style = ParagraphStyle(
            "CodeBox",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
            backColor=colors.HexColor("#f1f5f9"),
            borderColor=colors.HexColor("#cbd5e1"),
            borderWidth=0.5,
            borderPadding=4,
            spaceAfter=6,
        )

        elements: list[Any] = []

        # =========================================================================
        # 1. COVER PAGE
        # =========================================================================
        elements.append(Spacer(1, 40))
        elements.append(Paragraph("SENTINELSCAN", ParagraphStyle(
            "BrandHeader", fontName="Helvetica-Bold", fontSize=14, leading=16, textColor=accent_color, spaceAfter=8
        )))
        elements.append(Paragraph("Web Security Assessment & Vulnerability Analysis", title_style))
        elements.append(Paragraph("Automated Defensive Security Audit Report", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=2, color=accent_color, spaceAfter=30))

        # Cover details card
        cover_meta = [
            [Paragraph("Target Hostname:", meta_label), Paragraph(scan.target_hostname, meta_val)],
            [Paragraph("Target URL:", meta_label), Paragraph(scan.target_url, meta_val)],
            [Paragraph("Observed IP:", meta_label), Paragraph(scan.target_ip or "N/A", meta_val)],
            [Paragraph("Scan Identifier:", meta_label), Paragraph(scan.id, meta_val)],
            [Paragraph("Assessment Date:", meta_label), Paragraph(datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"), meta_val)],
            [Paragraph("Audit Duration:", meta_label), Paragraph(f"{scan.duration_seconds or 0.0} seconds", meta_val)],
            [Paragraph("Executive Grade:", meta_label), Paragraph(f"<b>{cls._compute_grade(scan)}</b>", meta_val)],
        ]
        t_cover = Table(cover_meta, colWidths=[1.8 * inch, 5.0 * inch])
        t_cover.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_cover)

        elements.append(Spacer(1, 40))
        disclaimer_cover = (
            "<b>NOTICE OF AUTHORIZATION & CLASSIFICATION</b><br/>"
            "This report contains sensitive vulnerability assessment information conducted with safe, "
            "non-destructive defensive security probes. Distribution should be restricted to authorized "
            "technical personnel, system owners, and compliance auditors."
        )
        elements.append(Paragraph(disclaimer_cover, body_style))
        elements.append(PageBreak())

        # =========================================================================
        # 2. EXECUTIVE SUMMARY & METRICS
        # =========================================================================
        elements.append(Paragraph("Executive Summary", h1_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=12))

        exec_text = (
            f"An automated security configuration audit of <b>{scan.target_hostname}</b> was performed by SentinelScan. "
            f"The scanner completed <b>{scan.total_checks}</b> security checks, identifying a total of "
            f"<b>{scan.total_findings}</b> security findings requiring review and remediation."
        )
        elements.append(Paragraph(exec_text, body_style))
        elements.append(Spacer(1, 10))

        # Severity breakdown table
        sev_table_data = [
            ["Severity Level", "Count", "Risk Level", "Recommended Action"],
            ["CRITICAL", str(scan.critical_count), "Immediate Threat", "Resolve within 24 hours"],
            ["HIGH", str(scan.high_count), "Elevated Risk", "Resolve within 7 days"],
            ["MEDIUM", str(scan.medium_count), "Moderate Risk", "Remediate in next release sprint"],
            ["LOW", str(scan.low_count), "Low Exposure", "Address during routine maintenance"],
            ["INFORMATIONAL", str(scan.info_count), "Defense-in-Depth", "Adopt recommended best practice"],
        ]
        t_sev = Table(sev_table_data, colWidths=[1.8 * inch, 0.8 * inch, 1.8 * inch, 2.4 * inch])
        t_sev.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), primary_color),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(t_sev)
        elements.append(Spacer(1, 16))

        # =========================================================================
        # 3. METHODOLOGY & SCOPE
        # =========================================================================
        elements.append(Paragraph("Scope and Methodology", h1_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

        method_text = (
            "SentinelScan employs a modular, non-destructive assessment methodology designed to evaluate "
            "external attack surfaces without causing service degradation. The audit includes:<br/>"
            "• <b>HTTPS Enforcement:</b> Evaluation of TLS reachability and automatic HTTP-to-HTTPS redirect rules.<br/>"
            "• <b>Security Headers:</b> Strict inspection of CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and X-Frame-Options.<br/>"
            "• <b>Cookie Hardening:</b> Analysis of Secure, HttpOnly, and SameSite attributes (raw cookie values strictly redacted).<br/>"
            "• <b>CORS Policies:</b> Controlled origin probes testing for arbitrary origin reflection and wildcard credential exposures.<br/>"
            "• <b>TLS Certificate Security:</b> Certificate validity, expiration date calculation, and Subject Alternative Name verification.<br/>"
            "• <b>Information Disclosure:</b> Public server banner analysis and debug trace detection in ordinary HTTP responses."
        )
        elements.append(Paragraph(method_text, body_style))
        elements.append(Spacer(1, 14))

        # =========================================================================
        # 4. CHECK RESULTS SUMMARY
        # =========================================================================
        elements.append(Paragraph("Security Checks Summary Matrix", h1_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

        matrix_rows = [["Security Check", "Category", "Status", "Duration (ms)"]]
        for cr in scan.check_results:
            matrix_rows.append([
                Paragraph(cr.check_name, body_style),
                Paragraph(cr.category.upper(), body_style),
                Paragraph(f"<b>{cr.status.value}</b>", body_style),
                f"{cr.duration_ms:.1f}",
            ])

        t_matrix = Table(matrix_rows, colWidths=[3.2 * inch, 1.4 * inch, 1.3 * inch, 0.9 * inch])
        t_matrix.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), primary_color),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_matrix)
        elements.append(Spacer(1, 16))

        # =========================================================================
        # 5. DETAILED FINDINGS
        # =========================================================================
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Security Findings", h1_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=14))

        if not scan.findings:
            elements.append(Paragraph("No vulnerabilities or misconfigurations were detected during this assessment.", body_style))
        else:
            for idx, finding in enumerate(scan.findings, 1):
                f_elements: list[Any] = []
                sev_color = cls._get_severity_color(finding.severity)

                # Finding Title Banner
                title_text = f"<b>#{idx}. {finding.title}</b>"
                f_elements.append(Paragraph(title_text, h2_style))

                # Metadata table
                f_meta = [
                    [
                        Paragraph(f"<b>Severity:</b> <font color='{sev_color.hexval()}'>{finding.severity.value}</font>", body_style),
                        Paragraph(f"<b>Category:</b> {finding.category.upper()}", body_style),
                        Paragraph(f"<b>Confidence:</b> {finding.confidence.value}", body_style),
                        Paragraph(f"<b>CWE:</b> {finding.cwe_id or 'N/A'}", body_style),
                    ]
                ]
                t_f_meta = Table(f_meta, colWidths=[1.8 * inch, 1.8 * inch, 1.8 * inch, 1.4 * inch])
                t_f_meta.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("PADDING", (0, 0), (-1, -1), 3),
                ]))
                f_elements.append(t_f_meta)
                f_elements.append(Spacer(1, 6))

                # Summary
                f_elements.append(Paragraph("<b>Observation:</b>", meta_label))
                f_elements.append(Paragraph(finding.summary, body_style))

                # Evidence
                if finding.evidence:
                    f_elements.append(Paragraph("<b>Observed Evidence:</b>", meta_label))
                    clean_evidence = finding.evidence.replace("\n", "<br/>")
                    f_elements.append(Paragraph(clean_evidence, code_style))

                # Impact
                f_elements.append(Paragraph("<b>Security Impact:</b>", meta_label))
                f_elements.append(Paragraph(finding.impact, body_style))

                # Remediation
                f_elements.append(Paragraph("<b>Remediation Guidance:</b>", meta_label))
                clean_remed = finding.remediation.replace("\n", "<br/>")
                f_elements.append(Paragraph(clean_remed, body_style))

                # References
                if finding.references:
                    f_elements.append(Paragraph("<b>References:</b>", meta_label))
                    clean_refs = finding.references.replace("\n", "<br/>")
                    f_elements.append(Paragraph(clean_refs, body_style))

                f_elements.append(Spacer(1, 12))
                f_elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=14))

                elements.append(KeepTogether(f_elements))

        # Build document
        doc.build(elements, canvasmaker=NumberedCanvas)
        buffer.seek(0)
        return buffer.getvalue()

    @classmethod
    def _compute_grade(cls, scan: Scan) -> str:
        if scan.critical_count > 0:
            return "F"
        if scan.high_count > 2:
            return "D"
        if scan.high_count > 0 or scan.medium_count > 3:
            return "C"
        if scan.medium_count > 0 or scan.low_count > 2:
            return "B"
        return "A"

    @classmethod
    def _get_severity_color(cls, sev: SeverityLevel) -> colors.HexColor:
        if sev == SeverityLevel.CRITICAL:
            return colors.HexColor("#ef4444")
        if sev == SeverityLevel.HIGH:
            return colors.HexColor("#f97316")
        if sev == SeverityLevel.MEDIUM:
            return colors.HexColor("#eab308")
        if sev == SeverityLevel.LOW:
            return colors.HexColor("#3b82f6")
        return colors.HexColor("#64748b")
