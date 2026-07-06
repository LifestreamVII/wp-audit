"""
email_report.py — Summary email with PDF report attachments for wp_audit.
"""

import re
import smtplib
import ssl
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


# ---------------------------------------------------------------------------
# Severity threshold — only reports at this severity or above are attached
# ---------------------------------------------------------------------------
_QUALIFYING_SEVERITIES = {"critical", "high", "medium", "low"}

# Report filename pattern produced by reporter.py:
#   [severity]_audit_sitename_YYYYMMDD.md
_REPORT_RE = re.compile(
    r"^\[(?P<severity>[a-z]+)\]_audit_(?P<site>.+)_(?P<date>\d{8})\.md$",
    re.IGNORECASE,
)

JST = timezone(timedelta(hours=9))


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
# Report scanning helpers
# ---------------------------------------------------------------------------

def _parse_report_filename(filename: str) -> Optional[dict]:
    """
    Parse a report filename into its components.

    Returns a dict with keys 'severity', 'site', 'date' or None if the
    filename doesn't match the expected pattern.
    """
    m = _REPORT_RE.match(filename)
    if not m:
        return None
    return {
        "severity": m.group("severity").lower(),
        "site": m.group("site").replace("_", " ").title(),
        "date": m.group("date"),
    }


def _build_pdf_attachment_name(severity: str, site: str, date_str: str) -> str:
    """Build the attachment filename: SEVERITY-SiteName-YYYYMMDD.pdf"""
    safe_site = re.sub(r"\s+", "", site)  # Remove spaces for attachment name
    return f"{severity.upper()}-{safe_site}-{date_str}.pdf"


# ---------------------------------------------------------------------------
# Email body builder
# ---------------------------------------------------------------------------

def _build_summary_body(
    analysis_dt: datetime,
    total_sites: int,
    errored_sites: int,
    no_severity_sites: int,
    report_sites: list[str],
    attachment_names: list[str],
) -> str:
    """Build the plain-text email body."""
    date_str = analysis_dt.strftime("%d-%m-%Y %H:%M JST")
    return f"""\
    <html>
    <body style="font-family: Arial, sans-serif; color: #333;">
      <h2 style="color: #2980b9;">Backup Integrity Summary Report</h2>
      <p><strong>Date of analysis:</strong> {date_str}</p>
      <p><strong>Sites analysed:</strong> {total_sites}</p>
      <p><strong>Sites skipped (errored):</strong> {errored_sites}</p>
      <p><strong>Sites skipped (no severity):</strong> {no_severity_sites}</p>
      <p><strong>Reports available for:</strong> {', '.join(report_sites)}</p>
      <hr>
      <p style="font-size: 0.85em; color: #888;">
        This summary email was generated automatically by the wp-audit script.
      </p>
    </body>
    </html>"""

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_summary_email(
    generated_reports: list[Path],
    total_sites: int,
    errored_sites: int,
    output_dir: Optional[Path] = None,
) -> None:
    """
    Scan *generated_reports* for qualifying reports (severity ≥ low),
    convert them to PDF, and send a recap email with those PDFs attached.

    Parameters
    ----------
    generated_reports : list[Path]
        Paths to the Markdown report files produced during the current run.
    total_sites : int
        Total number of sites in the config (including skipped ones).
    errored_sites : int
        Number of sites that errored / were unreachable.
    output_dir : Path, optional
        Directory where reports live (default: config.DEFAULT_OUTPUT_DIR).
    """
    if output_dir is None:
        output_dir = Path(DEFAULT_OUTPUT_DIR)

    analysis_dt = datetime.now(tz=JST)

    qualifying: list[tuple[Path, dict]] = []     # (md_path, parsed_info)
    no_severity_count = 0

    for report_path in generated_reports:
        info = _parse_report_filename(report_path.name)
        if info is None:
            # Filename didn't match pattern — treat as no-severity
            log.warning("  ⚠ Could not parse severity from: %s", report_path.name)
            no_severity_count += 1
            continue
        if info["severity"] not in _QUALIFYING_SEVERITIES:
            # e.g. "none" or "unknown"
            log.info("  ⏭ Skipped (severity=%s): %s", info["severity"], report_path.name)
            no_severity_count += 1
            continue
        qualifying.append((report_path, info))

    if not qualifying:
        log.info("📧 No reports meet the severity threshold — skipping email.")
        return

    # ── Convert to PDF & build attachment list ────────────────────────────
    log.info("📧 Preparing summary email (%d qualifying report(s))…", len(qualifying))

    pdf_paths: list[Path] = []
    attachment_names: list[str] = []
    report_site_names: list[str] = []

    for md_path, info in qualifying:
        pdf_path = _md_to_pdf(md_path)
        att_name = _build_pdf_attachment_name(info["severity"], info["site"], info["date"])
        pdf_paths.append(pdf_path)
        attachment_names.append(att_name)
        report_site_names.append(info["site"])

    # ── Compose email ─────────────────────────────────────────────────────
    body = _build_summary_body(
        analysis_dt=analysis_dt,
        total_sites=total_sites,
        errored_sites=errored_sites,
        no_severity_sites=no_severity_count,
        report_sites=report_site_names,
        attachment_names=attachment_names,
    )

    msg = MIMEMultipart()
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECIPIENT
    msg["Subject"] = f"{EMAIL_SUBJECT_PREFIX} {analysis_dt.strftime('%d-%m-%Y')}"
    msg.attach(MIMEText(body, "html"))

    for pdf_path, att_name in zip(pdf_paths, attachment_names):
        with pdf_path.open("rb") as f:
            part = MIMEBase("application", "pdf")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{att_name}"')
        msg.attach(part)

    # ── Send ──────────────────────────────────────────────────────────────
    log.info("📧 Sending email to %s via %s:%s…", EMAIL_RECIPIENT, SMTP_HOST, SMTP_PORT)
    context = ssl._create_unverified_context()
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
