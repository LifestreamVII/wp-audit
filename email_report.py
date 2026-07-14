"""
email_report.py — Summary email with PDF report attachments for wp_audit.
"""

import html
import re
import smtplib
import ssl
import time
from datetime import datetime, timezone, timedelta
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from markdown_pdf import MarkdownPdf, Section

from config import (
    DEFAULT_OUTPUT_DIR,
    EMAIL_RECIPIENT,
    EMAIL_SENDER,
    EMAIL_SUBJECT_PREFIX,
    SEVERITY_ORDER,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USER,
    log,
)
from state import DiffResult, Issue


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

JST = timezone(timedelta(hours=9))

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "none":     "🟢",
    "unknown":  "⚪",
}

# ---------------------------------------------------------------------------
# Shared inline-style constants (email clients need everything inline)
# ---------------------------------------------------------------------------

_FONT_STACK = (
    'Avenir, "Avenir Next LT Pro", Montserrat, Corbel, '
    '"URW Gothic", source-sans-pro, sans-serif'
)
_TEXT_COLOR = "#03124A"
_BG_COLOR = "#FFFFFF"
_DIVIDER_COLOR = "#EEEEEE"
_TH_STYLE = (
    "text-align:left;padding:8px 12px;"
    f"border-bottom:2px solid {_DIVIDER_COLOR};"
    "font-size:13px;color:#6b7280;"
)
_TD_STYLE = (
    "padding:8px 12px;"
    "border-bottom:1px solid #F3F4F6;"
    "font-size:14px;vertical-align:top;"
)
_TD_STYLE_ZEBRA = _TD_STYLE + "background-color:#FAFAFA;"
_TABLE_STYLE = "width:100%;border-collapse:collapse;"


# ---------------------------------------------------------------------------
# Markdown → PDF conversion
# ---------------------------------------------------------------------------

def _md_to_pdf(md_path: Path) -> Path:
    """Convert a Markdown report to PDF and return the PDF path."""
    md_text = md_path.read_text(encoding="utf-8")
    pdf_path = md_path.with_suffix(".pdf")

    pdf = MarkdownPdf(toc_level=2)
    pdf.add_section(Section(md_text))
    pdf.save(str(pdf_path))

    log.info("  📄 PDF generated: %s", pdf_path.name)
    return pdf_path


# ---------------------------------------------------------------------------
# HTML helper functions
# ---------------------------------------------------------------------------

def _extract_cve_from_issue(issue: Issue) -> str:
    """Extract CVE identifier from issue ID or detail field."""
    m = _CVE_RE.search(issue.id)
    if m:
        return m.group(0).upper()
    m = _CVE_RE.search(issue.detail)
    if m:
        return m.group(0).upper()
    return "—"


def _esc(text: str) -> str:
    """Shorthand for html.escape."""
    return html.escape(str(text), quote=True)


def _html_divider() -> str:
    """HR divider matching the template styling."""
    return (
        '<div style="padding:16px 24px 16px 24px">'
        f'<hr style="width:100%;border:none;border-top:1px solid {_DIVIDER_COLOR};margin:0"/>'
        '</div>'
    )


def _html_issue_table(items: list[tuple[str, Issue]]) -> str:
    """Build an issue table with columns: Site, Component, CVE, Issue, Severity, Recommendation."""
    if not items:
        return ""

    # Table header
    header_cells = "".join(
        f'<th style="{_TH_STYLE}">{col}</th>'
        for col in ("Site", "Component", "CVE", "Issue", "Severity", "Recommendation")
    )
    rows_html = f"<thead><tr>{header_cells}</tr></thead>"

    # Table body
    body_rows: list[str] = []
    for idx, (site, iss) in enumerate(items):
        td_style = _TD_STYLE_ZEBRA if idx % 2 == 1 else _TD_STYLE
        sev_emoji = SEVERITY_EMOJI.get(iss.severity, "⚪")
        cve = _extract_cve_from_issue(iss)

        cells = (
            f'<td style="{td_style}"><strong>{_esc(site)}</strong></td>'
            f'<td style="{td_style}"><strong>{_esc(iss.component)}</strong></td>'
            f'<td style="{td_style}">{_esc(cve)}</td>'
            f'<td style="{td_style}">{_esc(iss.detail)}</td>'
            f'<td style="{td_style}">{sev_emoji} {_esc(iss.severity.capitalize())}</td>'
            f'<td style="{td_style}">{_esc(iss.action)}</td>'
        )
        body_rows.append(f"<tr>{cells}</tr>")

    tbody = "<tbody>" + "".join(body_rows) + "</tbody>"
    return (
        f'<div style="font-size:16px;padding:16px 24px 16px 24px">'
        f'<table style="{_TABLE_STYLE}">{rows_html}{tbody}</table>'
        f'</div>'
    )


def _html_errored_table(items: list[tuple[str, str]]) -> str:
    """Build the errored/unreachable sites table: Site, Error, Since."""
    if not items:
        return ""

    header_cells = "".join(
        f'<th style="{_TH_STYLE}">{col}</th>'
        for col in ("Site", "Error", "Since")
    )
    rows_html = f"<thead><tr>{header_cells}</tr></thead>"

    body_rows: list[str] = []
    for idx, (site, error_msg) in enumerate(items):
        td_style = _TD_STYLE_ZEBRA if idx % 2 == 1 else _TD_STYLE
        body_rows.append(
            f'<tr>'
            f'<td style="{td_style}"><strong>{_esc(site)}</strong></td>'
            f'<td style="{td_style}color:#c0392b;">{_esc(error_msg)}</td>'
            f'<td style="{td_style}">—</td>'
            f'</tr>'
        )

    tbody = "<tbody>" + "".join(body_rows) + "</tbody>"
    return (
        f'<div style="font-size:16px;padding:16px 24px 16px 24px">'
        f'<table style="{_TABLE_STYLE}">{rows_html}{tbody}</table>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Email body builder
# ---------------------------------------------------------------------------

def _build_summary_body(
    diff: DiffResult,
    analysis_dt: datetime,
    total_sites: int,
    start_time: float,
) -> str:
    """Build the full HTML email body matching the revised template."""

    date_str = analysis_dt.strftime("%Y-%m-%d")

    elapsed = time.time() - start_time
    mins, secs = divmod(int(elapsed), 60)
    duration = f"{mins:02d}:{secs:02d}"

    sections: list[str] = []

    # ── Header ────────────────────────────────────────────────────────────
    sections.append(
        f'<h1 style="font-weight:bold;text-align:left;margin:0;'
        f'font-size:32px;padding:16px 0px 0px 0px">'
        f'WordPress Security Audit · {date_str}</h1>'
    )
    sections.append(
        f'<div style="font-size:12px;font-weight:normal;'
        f'padding:0px 24px 12px 0px">'
        f'{total_sites} sites audited · finished in {duration}</div>'
    )
    sections.append(
        '<div style="font-size:16px;font-weight:normal;text-align:left;'
        'padding:16px 24px 16px 24px">'
        'This is the report for WordPress sites listed in sites.yaml. '
        'Full report available as attachment.</div>'
    )

    # ── 🚨 NEW issues (highlighted background) ───────────────────────────
    if diff.new:
        sorted_new = sorted(diff.new, key=lambda p: SEVERITY_ORDER.get(p[1].severity, 99))
        inner = (
            f'<h2 style="font-weight:bold;margin:0;font-size:24px;'
            f'padding:16px 24px 16px 24px">'
            f'🚨 {len(sorted_new)} New issues detected</h2>'
            + _html_issue_table(sorted_new)
        )
        sections.append(
            f'<div style="border-radius:8px;padding:0px 0px 0px 0px">'
            f'<div style="background-color:#fdeed7;border-radius:16px;'
            f'padding:16px 24px 16px 24px">'
            f'{inner}</div></div>'
        )
        sections.append(_html_divider())

    # ── ⏸ EXISTING (previously reported, not resolved) ────────────────────
    if diff.existing:
        sorted_existing = sorted(diff.existing, key=lambda p: SEVERITY_ORDER.get(p[1].severity, 99))
        sections.append(
            f'<h2 style="font-weight:bold;margin:0;font-size:24px;'
            f'padding:16px 24px 16px 24px">'
            f'⏸ {len(sorted_existing)} Previous issues (not resolved)</h2>'
        )
        sections.append(_html_issue_table(sorted_existing))
        sections.append(_html_divider())

    # ── ✅ RESOLVED ───────────────────────────────────────────────────────
    if diff.resolved:
        sections.append(
            f'<h2 style="font-weight:bold;margin:0;font-size:24px;'
            f'padding:16px 24px 16px 24px">'
            f'✅ {len(diff.resolved)} Resolved (fixed since last run)</h2>'
        )
        sections.append(_html_issue_table(diff.resolved))
        sections.append(_html_divider())

    # ── ⚠ UNREACHABLE / ERRORS ───────────────────────────────────────────
    if diff.errored:
        sections.append(
            f'<h2 style="font-weight:bold;margin:0;font-size:24px;'
            f'padding:16px 24px 16px 24px">'
            f'⚠ Unreachable</h2>'
        )
        sections.append(_html_errored_table(diff.errored))
        sections.append(_html_divider())

    # ── Other (unchanged sites) ───────────────────────────────────────────
    if diff.unchanged:
        sections.append(
            '<h2 style="font-weight:bold;margin:0;font-size:24px;'
            'padding:16px 24px 16px 24px">Other</h2>'
        )
        sections.append(
            f'<div style="padding:8px 24px 8px 24px">'
            f'<div style="font-size:16px;font-weight:normal;text-align:left;'
            f'padding:0px 0px 16px 0px">'
            f'{len(diff.unchanged)} sites presented no changes since last audit.</div></div>'
        )
        sections.append(_html_divider())

    # ── Footer ────────────────────────────────────────────────────────────
    sections.append(
        '<div style="font-size:16px;padding:16px 24px 16px 24px">'
        '<p style="margin:0 0 4px 0;">Generated by wp-audit</p>'
        '<p style="margin:0;font-size:11px;">'
        'This is an automated security audit. Do not reply to this email.'
        '</p></div>'
    )

    # ── Wrap in outer layout ──────────────────────────────────────────────
    inner_html = "\n".join(sections)
    return f"""\
<!doctype html>
<html>
  <body>
    <div style='background-color:{_BG_COLOR};color:{_TEXT_COLOR};font-family:{_FONT_STACK};font-size:16px;font-weight:400;letter-spacing:0.15008px;line-height:1.5;margin:0;padding:32px 0;min-height:100%;width:100%'>
      <table align="center" width="100%" style="margin:0 auto;background-color:{_BG_COLOR}" role="presentation" cellspacing="0" cellpadding="0" border="0">
        <tbody>
          <tr style="width:100%">
            <td>
{inner_html}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </body>
</html>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_digest_email(
    diff: DiffResult,
    total_sites: int,
    start_time: float,
    generated_reports: list[Path],
    output_dir: Optional[Path] = None,
    unverified_context: bool = False
) -> None:
    """
    Build a rich HTML summary email from the DiffResult, convert qualifying
    Markdown reports to PDF, attach them, and send.

    Parameters
    ----------
    diff : DiffResult
        The diff output from ``Diff.finalize()``.
    total_sites : int
        Total number of sites in the config (including skipped ones).
    errored_sites : int
        Number of sites that errored / were unreachable.
    start_time : float
        ``time.time()`` captured at the start of the audit run.
    generated_reports : list[Path]
        Paths to the Markdown report files produced during the current run.
    output_dir : Path, optional
        Directory where reports live (default: config.DEFAULT_OUTPUT_DIR).
    """
    if output_dir is None:
        output_dir = Path(DEFAULT_OUTPUT_DIR)

    analysis_dt = datetime.now(tz=JST)

    # ── Build HTML body from DiffResult ───────────────────────────────────
    body = _build_summary_body(
        diff=diff,
        analysis_dt=analysis_dt,
        total_sites=total_sites,
        start_time=start_time,
    )

    msg = MIMEMultipart()
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECIPIENT
    msg["Subject"] = f"{EMAIL_SUBJECT_PREFIX} {analysis_dt.strftime('%d-%m-%Y')} ({len(diff.new)} new issues, {len(diff.existing)} existing)"
    msg.attach(MIMEText(body, "html"))

    # ── Convert reports to PDF & attach ───────────────────────────────────
    log.info("📧 Preparing summary email (%d report(s))…", len(generated_reports))

    for md_path in generated_reports:
        pdf_path = _md_to_pdf(md_path)
        att_name = pdf_path.name
        with pdf_path.open("rb") as f:
            part = MIMEBase("application", "pdf")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{att_name}"')
        msg.attach(part)

    # ── Send ──────────────────────────────────────────────────────────────
    log.info("📧 Sending email to %s via %s:%s…", EMAIL_RECIPIENT, SMTP_HOST, SMTP_PORT)
    if unverified_context:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context()
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENT, msg.as_string())
        log.info("📧 ✅ Summary email sent successfully.")
    except smtplib.SMTPException:
        log.exception("📧 ❌ Failed to send summary email.")
