import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

def generate_requirements_pdf():
    output_pdf = "requirements.pdf"

    doc = SimpleDocTemplate(
        output_pdf,
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )

    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    normal.textColor = colors.HexColor("#1f2937")
    normal.fontSize = 9.5
    normal.leading = 13

    title_style = ParagraphStyle(
        "ReqTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        "ReqSubtitle",
        parent=normal,
        fontName="Helvetica-Oblique",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4b5563"),
        spaceAfter=10
    )

    h1_style = ParagraphStyle(
        "H1Style",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e40af"),
        spaceBefore=12,
        spaceAfter=4
    )

    h2_style = ParagraphStyle(
        "H2Style",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=8,
        spaceAfter=4
    )

    bullet_style = ParagraphStyle(
        "BulletStyle",
        parent=normal,
        leftIndent=15,
        spaceAfter=3
    )

    table_header = ParagraphStyle(
        "TableHeader",
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#ffffff")
    )

    table_cell = ParagraphStyle(
        "TableCell",
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#1f2937")
    )

    table_cell_bold = ParagraphStyle(
        "TableCellBold",
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # Title & Header
    story.append(Paragraph("SentinelScan — Software & System Requirements Specification", title_style))
    story.append(Paragraph("Platform Prerequisites, Runtime Dependencies, and Hardware Specifications | Author: Ankita Kala", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=10))

    # Section 1: System & Hardware Specifications
    story.append(Paragraph("1. System & Hardware Specifications", h1_style))
    story.append(Paragraph("&bull; <b>Operating System:</b> Linux (Ubuntu 22.04+ / Debian 12+), macOS 13+, or Windows 11 with WSL2", bullet_style))
    story.append(Paragraph("&bull; <b>CPU Minimum:</b> 2 Cores (4 Cores recommended for parallel scan workers)", bullet_style))
    story.append(Paragraph("&bull; <b>RAM Minimum:</b> 2 GB RAM (4 GB recommended for concurrent backend + frontend dev servers)", bullet_style))
    story.append(Paragraph("&bull; <b>Disk Space:</b> 500 MB free storage for runtimes, logs, SQLite database, and report exports", bullet_style))
    story.append(Paragraph("&bull; <b>Network:</b> Active outbound Internet connectivity for resolving and auditing public HTTPS targets", bullet_style))
    story.append(Spacer(1, 6))

    # Section 2: Runtime Environments
    story.append(Paragraph("2. Required Runtime Environments", h1_style))
    story.append(Paragraph("&bull; <b>Python Runtime:</b> Python 3.11, 3.12, or 3.14 (with venv and pip package managers)", bullet_style))
    story.append(Paragraph("&bull; <b>Node.js Runtime:</b> Node.js 20.x or 22.x LTS, npm 10.x", bullet_style))
    story.append(Paragraph("&bull; <b>Docker Engine (Optional):</b> Docker 24.0+ and Docker Compose v2 for containerized deployment", bullet_style))
    story.append(Spacer(1, 6))

    # Section 3: Python Backend Dependencies
    story.append(Paragraph("3. Python Backend & Security Engine Dependencies", h1_style))
    py_deps = [
        [Paragraph("Package", table_header), Paragraph("Version Constraint", table_header), Paragraph("Functional Purpose in SentinelScan", table_header)],
        [Paragraph("fastapi", table_cell_bold), Paragraph(">=0.110.0", table_cell), Paragraph("Asynchronous ASGI web application framework", table_cell)],
        [Paragraph("uvicorn[standard]", table_cell_bold), Paragraph(">=0.28.0", table_cell), Paragraph("High-performance ASGI production server with uvloop", table_cell)],
        [Paragraph("pydantic", table_cell_bold), Paragraph(">=2.6.0", table_cell), Paragraph("Schema validation, typing models, and payload sanitization", table_cell)],
        [Paragraph("pydantic-settings", table_cell_bold), Paragraph(">=2.2.0", table_cell), Paragraph("Defensive environment variable and config management", table_cell)],
        [Paragraph("sqlalchemy", table_cell_bold), Paragraph(">=2.0.28", table_cell), Paragraph("SQLAlchemy 2.0 ORM engine for scans and findings persistence", table_cell)],
        [Paragraph("alembic", table_cell_bold), Paragraph(">=1.13.0", table_cell), Paragraph("Database schema versioning and deterministic migrations", table_cell)],
        [Paragraph("httpx", table_cell_bold), Paragraph(">=0.27.0", table_cell), Paragraph("Asynchronous HTTP client with connection sandbox & 2MB limit", table_cell)],
        [Paragraph("cryptography", table_cell_bold), Paragraph(">=42.0.0", table_cell), Paragraph("X.509 certificate parsing, SAN extraction, and TLS trust checks", table_cell)],
        [Paragraph("reportlab", table_cell_bold), Paragraph(">=4.1.0", table_cell), Paragraph("Executive & technical vector PDF report generation engine", table_cell)],
        [Paragraph("pillow", table_cell_bold), Paragraph(">=10.2.0", table_cell), Paragraph("Image rasterization and badge rendering in PDF reports", table_cell)],
        [Paragraph("pytest / pytest-asyncio", table_cell_bold), Paragraph(">=8.0.0", table_cell), Paragraph("Automated unit and integration test runner (100% pass rate)", table_cell)],
        [Paragraph("ruff", table_cell_bold), Paragraph(">=0.3.0", table_cell), Paragraph("Static code analysis, security auditing, and AST linting", table_cell)],
    ]
    t_py = Table(py_deps, colWidths=[120, 100, 310])
    t_py.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8fafc'), colors.HexColor('#ffffff')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_py)
    story.append(Spacer(1, 8))

    # Section 4: Frontend Dependencies
    story.append(Paragraph("4. Frontend UI & Dashboard Dependencies", h1_style))
    fe_deps = [
        [Paragraph("Package", table_header), Paragraph("Version Constraint", table_header), Paragraph("Role in SentinelScan UI", table_header)],
        [Paragraph("react / react-dom", table_cell_bold), Paragraph("^19.0.0", table_cell), Paragraph("Modern reactive UI library with concurrent rendering", table_cell)],
        [Paragraph("typescript", table_cell_bold), Paragraph("~5.8.0", table_cell), Paragraph("Strict static typing across all 9 security workspaces", table_cell)],
        [Paragraph("vite", table_cell_bold), Paragraph("^6.2.0", table_cell), Paragraph("Next-generation lightning-fast frontend build bundler", table_cell)],
        [Paragraph("tailwindcss", table_cell_bold), Paragraph("^4.0.0", table_cell), Paragraph("Tailwind CSS v4 utility design system and dark theme tokens", table_cell)],
        [Paragraph("lucide-react", table_cell_bold), Paragraph("^1.16.0", table_cell), Paragraph("Defensive cybersecurity and telemetry icon set", table_cell)],
        [Paragraph("recharts", table_cell_bold), Paragraph("^2.15.0", table_cell), Paragraph("Interactive risk score charts, grade distributions, and dials", table_cell)],
        [Paragraph("axios", table_cell_bold), Paragraph("^1.8.0", table_cell), Paragraph("Promise-based HTTP client with global error interception", table_cell)],
    ]
    t_fe = Table(fe_deps, colWidths=[120, 100, 310])
    t_fe.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f766e')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f0fdfa'), colors.HexColor('#ffffff')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#ccfbf1')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_fe)
    story.append(Spacer(1, 8))

    # Section 5: Verification & Installation Command
    story.append(Paragraph("5. Installation & Verification Protocol", h1_style))
    story.append(Paragraph("To install and verify all project requirements on a clean environment:", normal))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<font name=\"Courier\">cd backend &amp;&amp; python3 -m venv venv &amp;&amp; source venv/bin/activate</font>", normal))
    story.append(Paragraph("<font name=\"Courier\">pip install -r requirements.txt</font>", normal))
    story.append(Paragraph("<font name=\"Courier\">pytest -v  # Expected: 23 passed in &lt;1.0s (100% pass rate)</font>", normal))
    story.append(Paragraph("<font name=\"Courier\">cd ../frontend &amp;&amp; npm install --legacy-peer-deps &amp;&amp; npm run build</font>", normal))
    story.append(Spacer(1, 8))

    # Footer attribution
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=6))
    story.append(Paragraph("Repository: https://github.com/koyel2004/webscan | License: MIT", subtitle_style))

    doc.build(story)
    size_kb = os.path.getsize(output_pdf) / 1024
    print(f"Successfully generated {output_pdf} ({size_kb:.1f} KB)")

if __name__ == "__main__":
    generate_requirements_pdf()
