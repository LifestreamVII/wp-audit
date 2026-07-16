"""
reporter.py — Markdown digest report generation for wp_audit.

Generates a single digest report from a DiffResult, grouping issues
by status (NEW → EXISTING → RESOLVED → UNCHANGED → ERRORS).
"""

import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import SEVERITY_ORDER, log
from state import DiffResult, Issue


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "none":     "🟢",
    "unknown":  "⚪",
}

def _severity_sort_key(pair: tuple[str, Issue]) -> int:
    """Sort (site, issue) pairs by severity (critical first)."""
    return SEVERITY_ORDER.get(pair[1].severity, 99)


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _extract_cve(issue: Issue) -> str:
    """Extract CVE identifier from issue ID or detail, return '—' if none."""
    m = _CVE_RE.search(issue.id)
    if m:
        return m.group(0).upper()
    m = _CVE_RE.search(issue.detail)
    if m:
        return m.group(0).upper()
    return "—"


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _header(
    total_sites: int,
    diff: DiffResult,
    start_time: float,
) -> list[str]:
    """Title line + status badge bar."""
    elapsed = time.time() - start_time
    mins, secs = divmod(int(elapsed), 60)
    duration = f"{mins}m {secs:02d}s" if mins else f"{secs}s"

    lines = [
        "# 🛡 WordPress Security Audit Digest",
        f"*{datetime.today().strftime('%Y-%m-%d')} — "
        f"{total_sites} sites audited in {duration}*",
        "",
    ]

    # Badge bar — only show categories that have entries
    badges: list[str] = []
    if diff.new:
        badges.append(f"**[ 🔴 {len(diff.new)} new ]**")
    if diff.existing:
        badges.append(f"**[ 🟠 {len(diff.existing)} existing ]**")
    if diff.resolved:
        badges.append(f"**[ 🟢 {len(diff.resolved)} resolved ]**")
    if diff.errored:
        badges.append(f"**[ ⚫ {len(diff.errored)} errored ]**")
    if badges:
        lines.append(" | ".join(badges))
        lines.append("")

    lines += ["---", ""]
    return lines


def _section_new(diff: DiffResult) -> list[str]:
    """🚨 NEW — Critical & High issues discovered this run."""
    if not diff.new:
        return []

    items = sorted(diff.new, key=_severity_sort_key)
    lines = [
        f"## 🚨 NEW — {len(items)} New issues detected",
        "",
        "| Site | Component | CVE | Issue | Severity | Recommended Action |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for site, iss in items:
        sev = SEVERITY_EMOJI.get(iss.severity, "⚪")
        cve = _extract_cve(iss)
        lines.append(
            f"| **{site}** "
            f"| **{iss.component}** "
            f"| {f'[{cve}]({iss.link})' if iss.link else cve} "
            f"| {iss.detail} "
            f"| {sev} **{iss.severity.capitalize()}** "
            f"| {iss.action} |"
        )
    lines += [
        "",
        "---",
        "",
    ]
    return lines


def _section_existing(diff: DiffResult) -> list[str]:
    """⏸ EXISTING — Previously reported, still open."""
    if not diff.existing:
        return []

    items = sorted(diff.existing, key=_severity_sort_key)
    lines = [
        f"## ⏸ {len(items)} Previous issues (not resolved)",
        "",
        "| Site | Component | CVE | Issue | Severity | Recommended Action |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for site, iss in items:
        sev = SEVERITY_EMOJI.get(iss.severity, "⚪")
        cve = _extract_cve(iss)
        first_seen = iss.first_seen[:10] if iss.first_seen else "—"
        lines.append(
            f"| **{site}** "
            f"| **{iss.component}** "
            f"| {f'[{cve}]({iss.link})' if iss.link else cve} "
            f"| {iss.detail} *(since {first_seen})* "
            f"| {sev} **{iss.severity.capitalize()}** "
            f"| {iss.action} |"
        )
    lines += ["", "---", ""]
    return lines


def _section_unchanged(diff: DiffResult) -> list[str]:
    """Compact list of sites with no changes."""
    if not diff.unchanged:
        return []

    names = sorted(diff.unchanged)
    lines = [
        f"**Unchanged sites ({len(names)}):**",
        " · ".join(names),
        "",
        "---",
        "",
    ]
    return lines


def _section_resolved(diff: DiffResult) -> list[str]:
    """✅ RESOLVED — Fixed since last run."""
    if not diff.resolved:
        return []

    lines = [
        f"## ✅ {len(diff.resolved)} Resolved (fixed since last run)",
        "",
        "| Site | Component | CVE | Issue | Severity | Resolution |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for site, iss in diff.resolved:
        sev = SEVERITY_EMOJI.get(iss.severity, "⚪")
        cve = _extract_cve(iss)
        lines.append(
            f"| **{site}** "
            f"| ~~{iss.component}~~ "
            f"| {f'[{cve}]({iss.link})' if iss.link else cve} "
            f"| ~~{iss.detail}~~ "
            f"| {sev} {iss.severity.capitalize()} "
            f"| {iss.action} |"
        )
    lines += ["", "---", ""]
    return lines


def _section_errored(diff: DiffResult) -> list[str]:
    """⚠ UNREACHABLE / ERRORS."""
    if not diff.errored:
        return []

    lines = [
        f"## ⚠ UNREACHABLE / ERRORS *({len(diff.errored)} sites)*",
        "",
        "| Site | Error |",
        "| :--- | :--- |",
    ]
    for site, error_msg in diff.errored:
        lines.append(f"| **{site}** | {error_msg} |")
    lines += ["", "---", ""]
    return lines


def _footer() -> list[str]:
    """Footer with generation notice."""
    return [
        f"Generated by wp-audit.",
        "",
        "*This is an automated security audit. Do not reply to this email.*",
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(
    diff: DiffResult,
    output_dir: Path,
    total_sites: int,
    start_time: float,
) -> Path:
    """Generate a single digest Markdown report from a DiffResult.

    Parameters
    ----------
    diff : DiffResult
        The diff output from ``Diff.finalize()``.
    output_dir : Path
        Directory to write the report into.
    total_sites : int
        Total number of sites in the config.
    start_time : float
        ``time.time()`` captured at the start of the run.

    Returns
    -------
    Path
        Path to the written Markdown file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = output_dir / f"Wordpress_Security_Audit_{datetime.now().strftime('%Y%m%d')}.md"

    lines: list[str] = []
    lines += _header(total_sites, diff, start_time)
    lines += _section_new(diff)
    lines += _section_existing(diff)
    lines += _section_unchanged(diff)
    lines += _section_resolved(diff)
    lines += _section_errored(diff)
    lines += _footer()

    report_text = "\n".join(lines)
    filename.write_text(report_text, encoding="utf-8")
    log.info("  📄 Digest report saved: %s", filename)
    return filename
