# utils/pdf_exporter.py
import re
from typing import List
from fpdf import FPDF


def _sanitize_latin1(text: str) -> str:
    """Replaces smart Unicode punctuation with clean Latin-1 equivalents for PDF core fonts."""
    replacements = {
        "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "--",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2022": "*", "\u2026": "...", "\u00a0": " ", "\u202f": " ", "\u200b": "",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    # Clean Markdown links [label](url) -> label
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    # Strip markdown bold/code/italic markers
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\*([^*]+)\*", r"\1", text)
    return text.encode("latin-1", "replace").decode("latin-1")


class BFSIReportPDF(FPDF):
    def __init__(self, target_domain: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.target_domain = _sanitize_latin1(target_domain)
        self.set_margins(left=12, top=20, right=12)
        self.set_auto_page_break(auto=True, margin=16)

    def header(self):
        self.set_fill_color(15, 23, 42)  # Executive Slate Navy
        self.rect(0, 0, 210, 14, "F")
        self.set_xy(12, 4)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(248, 250, 252)
        self.cell(
            self.epw, 6,
            f"FINRECON-SWARM  |  BFSI AUTONOMOUS RISK REPORT  |  TARGET: {self.target_domain.upper()}",
            align="L", new_x="LMARGIN", new_y="NEXT"
        )
        self.set_xy(self.l_margin, 18)

    def footer(self):
        self.set_y(-12)
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 116, 139)
        self.cell(
            self.epw, 8,
            f"100% Passive Ethical OSINT Assessment  |  Confidential  |  Page {self.page_no()}",
            align="C"
        )


def _render_table(pdf: BFSIReportPDF, table_lines: List[str]):
    """Renders a Markdown pipe-delimited table cleanly with automatic font scaling."""
    rows: List[List[str]] = []
    for line in table_lines:
        stripped = line.strip().strip("|")
        cells = [_sanitize_latin1(c.strip()) for c in stripped.split("|")]
        if all(re.fullmatch(r"[:\-\s]*", c) for c in cells):
            continue
        rows.append(cells)

    if not rows:
        return

    num_cols = max(len(r) for r in rows)
    normalized = [r + [""] * (num_cols - len(r)) for r in rows]

    # Scale font down cleanly for wide 6+ column tables
    font_size = 7.0 if num_cols >= 6 else 8.0
    line_h = 4.4 if num_cols >= 6 else 5.0

    pdf.ln(2)
    pdf.set_x(pdf.l_margin)
    pdf.set_text_color(30, 41, 59)

    with pdf.table(
        width=int(pdf.epw),
        borders_layout="HORIZONTAL_LINES",
        cell_fill_color=(248, 250, 252),
        cell_fill_mode="ROWS",
        line_height=line_h,
        padding=1.5,
        text_align="LEFT",
    ) as table:
        for r_idx, row_data in enumerate(normalized):
            row = table.row()
            pdf.set_font("Helvetica", "B" if r_idx == 0 else "", font_size)
            for cell_text in row_data:
                row.cell(cell_text)

    pdf.set_x(pdf.l_margin)
    pdf.ln(3)


def markdown_to_pdf_bytes(markdown_text: str, target_domain: str) -> bytes:
    """Converts a synthesized BFSI Markdown report into styled PDF bytes."""
    pdf = BFSIReportPDF(target_domain=target_domain)
    pdf.add_page()

    lines = markdown_text.splitlines()
    i = 0
    while i < len(lines):
        raw_line = lines[i].rstrip()
        stripped = raw_line.strip()

        if not stripped:
            pdf.ln(2.5)
            i += 1
            continue

        # Markdown table block
        if stripped.startswith("|") and "|" in stripped[1:]:
            table_block = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_block.append(lines[i])
                i += 1
            _render_table(pdf, table_block)
            continue

        # Horizontal rule
        if stripped in ("---", "***", "___"):
            pdf.set_draw_color(203, 213, 225)
            y = pdf.get_y() + 1.5
            pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
            pdf.ln(4)
            pdf.set_x(pdf.l_margin)
            i += 1
            continue

        clean = _sanitize_latin1(stripped)
        pdf.set_x(pdf.l_margin)

        if clean.startswith("# "):
            pdf.set_font("Helvetica", "B", 14.5)
            pdf.set_text_color(15, 23, 42)
            pdf.multi_cell(pdf.epw, 7.2, clean[2:].strip(), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1.5)
        elif clean.startswith("## "):
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 11.5)
            pdf.set_text_color(30, 58, 138)
            pdf.multi_cell(pdf.epw, 6.2, clean[3:].strip(), new_x="LMARGIN", new_y="NEXT")
            pdf.set_draw_color(30, 58, 138)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(2.5)
        elif clean.startswith("### "):
            pdf.set_font("Helvetica", "B", 10.2)
            pdf.set_text_color(51, 65, 85)
            pdf.multi_cell(pdf.epw, 5.8, clean[4:].strip(), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)
        elif clean.startswith(("- ", "* ")):
            pdf.set_font("Helvetica", "", 9.2)
            pdf.set_text_color(30, 41, 59)
            pdf.set_x(pdf.l_margin + 4)
            pdf.multi_cell(pdf.epw - 4, 5.0, f"- {clean[2:].strip()}", new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.set_font("Helvetica", "", 9.2)
            pdf.set_text_color(30, 41, 59)
            pdf.multi_cell(pdf.epw, 5.0, clean, new_x="LMARGIN", new_y="NEXT")

        i += 1

    return bytes(pdf.output())
