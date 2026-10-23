import os
import re
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable

def generate_pdf():
    readme_path = "README.md"
    output_pdf = "README.pdf"

    with open(readme_path, "r", encoding="utf-8") as f:
        text = f.read()

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
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
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
        spaceAfter=3
    )

    bullet_style = ParagraphStyle(
        "BulletStyle",
        parent=normal,
        leftIndent=15,
        spaceAfter=3
    )

    code_style = ParagraphStyle(
        "CodeStyle",
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderPadding=4,
        spaceBefore=4,
        spaceAfter=4
    )

    quote_style = ParagraphStyle(
        "QuoteStyle",
        parent=normal,
        fontName="Helvetica-Oblique",
        textColor=colors.HexColor("#475569"),
        leftIndent=15,
        spaceAfter=4
    )

    def clean_md(s):
        # Escape HTML entities
        s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        # Handle triple asterisk
        s = s.replace("***REDACTED***", "[REDACTED]")
        s = re.sub(r'\*\*\*(.*?)\*\*\*', r'<b><i>\1</i></b>', s)
        # Convert **bold**
        s = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', s)
        # Convert `code`
        s = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', s)
        # Remove markdown links [text](url) -> text
        s = re.sub(r'\[(.*?)\]\((.*?)\)', r'<b>\1</b> (\2)', s)
        # Remove badges/images ![alt](url)
        s = re.sub(r'!\[.*?\]\(.*?\)', '', s)
        # Replace inline dollar formulas
        s = s.replace("$0 - 100$", "0 - 100").replace("$\\to$", "->")
        s = re.sub(r'\$(.*?)\$', r'\1', s)
        return s.strip()

    story = []
    lines = text.split("\n")
    in_code = False
    code_block = []

    for line in lines:
        if line.startswith("```"):
            if in_code:
                raw_code = "<br/>".join([c.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") for c in code_block])
                if raw_code.strip():
                    story.append(Paragraph(raw_code, code_style))
                code_block = []
                in_code = False
            else:
                in_code = True
            continue

        if in_code:
            code_block.append(line)
            continue

        line_stripped = line.strip()
        if not line_stripped:
            story.append(Spacer(1, 3))
            continue

        # Skip raw badge lines
        if line_stripped.startswith("[![") or line_stripped.startswith("!["):
            continue

        if line.startswith("# "):
            story.append(Paragraph(clean_md(line[2:]), title_style))
            story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=6))
        elif line.startswith("## "):
            story.append(Paragraph(clean_md(line[3:]), h1_style))
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=4))
        elif line.startswith("### "):
            story.append(Paragraph(clean_md(line[4:]), h2_style))
        elif line.startswith("* ") or line.startswith("- "):
            story.append(Paragraph(f"&bull; {clean_md(line_stripped[2:])}", bullet_style))
        elif line.startswith("> "):
            story.append(Paragraph(clean_md(line_stripped[2:]), quote_style))
        elif line.startswith("|") and not line.startswith("|:--"):
            cells = [clean_md(c) for c in line.strip("|").split("|")]
            story.append(Paragraph(" | ".join([c for c in cells if c]), normal))
        elif line.startswith("---"):
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceAfter=4))
        else:
            cleaned = clean_md(line_stripped)
            if cleaned:
                story.append(Paragraph(cleaned, normal))

    doc.build(story)
    size_kb = os.path.getsize(output_pdf) / 1024
    print(f"Successfully generated {output_pdf} ({size_kb:.1f} KB)")

if __name__ == "__main__":
    generate_pdf()
