"""
reporter.py — Markdown report generation for wp_audit.
"""

import re
from datetime import datetime
from pathlib import Path

from config import SEVERITY_ORDER
from models import SiteAuditResult, Vulnerability


# ---------------------------------------------------------------------------
# Markdown report generator
# ---------------------------------------------------------------------------

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "none": "🟢",
    "unknown": "⚪",
}


def severity_badge(s: str) -> str:
    emoji = SEVERITY_EMOJI.get(s.lower(), "⚪")
    return f"{emoji} {s.capitalize()}"


def _vuln_table(vulns: list[Vulnerability]) -> str:
    if not vulns:
        return ""
    lines = [
        "| CVSSv3 | Severity | Vulnerability | Affected Versions | CVE / ID |",
        "|--------|----------|---------------|-------------------|----------|",
    ]
    for v in sorted(vulns, key=lambda x: SEVERITY_ORDER.get(x.severity_label, 99)):
        score = f"`{v.cvss_score}`" if v.cvss_score else "N/A"
        sev = severity_badge(v.severity_label)
        name = v.name
        version_range = ""
        if v.min_version and v.max_version:
            version_range = f"≥ {v.min_version} and < {v.max_version}"
        elif v.max_version:
            version_range = f"< {v.max_version}"
        elif v.unfixed:
            version_range = "⚠ Unfixed"
        else:
            version_range = "All versions"
        # Pick first CVE reference if available
        cve_links = []
        for src in v.sources[:2]:
            ref_id = src.get("id", "")
            ref_link = src.get("link", "")
            if ref_link:
                cve_links.append(f"[{ref_id}]({ref_link})")
            elif ref_id:
                cve_links.append(ref_id)
        ref_str = ", ".join(cve_links) if cve_links else "—"
        lines.append(f"| {score} | {sev} | {name} | `{version_range}` | {ref_str} |")
    return "\n".join(lines)


def generate_report(result: SiteAuditResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^\w\-]", "_", result.name.lower())
    filename = output_dir / f"[{result.highest_severity}]_audit_{safe_name}_{datetime.now().strftime('%Y%m%d')}.md"

    severity_color = {
        "critical": "🔴", "high": "🟠", "medium": "🟡",
        "low": "🔵", "none": "🟢", "unknown": "⚪",
    }

    lines: list[str] = []

    # ── Title ─────────────────────────────────────────────────────────────
    lines += [
        f"# WordPress Security Audit: {result.name}",
        "",
        f"> **URL:** {result.url}  ",
        f"> **Audited at:** {result.audited_at}  ",
        f"> **Tool:** wp_audit.py (WPVulnerability.net API)",
        "",
        "---",
        "",
    ]

    if not result.reachable:
        lines += [
            "## ❌ Site Unreachable",
            "",
            f"**Error:** {result.error}",
            "",
        ]
        report_text = "\n".join(lines)
        filename.write_text(report_text, encoding="utf-8")
        return filename

    # ── Executive Summary ─────────────────────────────────────────────────
    total = len(result.components)
    vuln_count = len(result.vulnerable_components)
    total_vulns = result.total_vulnerabilities
    hs = result.highest_severity
    hs_emoji = severity_color.get(hs, "⚪")

    # Severity counts
    sev_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for comp in result.vulnerable_components:
        for vuln in comp.vulnerabilities:
            sev_counts[vuln.severity_label] = sev_counts.get(vuln.severity_label, 0) + 1

    lines += [
        "## 📋 Executive Summary",
        "",
        f"| Item | Value |",
        f"|------|-------|",
        f"| WordPress Version | `{result.wp_version or 'Not detected'}` |",
        f"| Components Detected | {total} |",
        f"| Vulnerable Components | **{vuln_count}** |",
        f"| Total Vulnerabilities | **{total_vulns}** |",
        f"| Highest Severity | {hs_emoji} **{hs.capitalize()}** |",
        f"| Log Analysis | {('See below' if result.log_analysis else 'No analysis')} |",
        "",
    ]

    if sev_counts and total_vulns > 0:
        lines += [
            "### Vulnerability Severity Breakdown",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev, cnt in sorted(sev_counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99)):
            if cnt > 0:
                lines.append(f"| {severity_badge(sev)} | {cnt} |")
        lines.append("")

    lines += ["---", ""]

    # ── WordPress Core ────────────────────────────────────────────────────
    lines += ["## 🖥 WordPress Core", ""]
    core_comps = [c for c in result.components if c.kind == "core"]
    if core_comps:
        core = core_comps[0]
        lines += [
            f"**Installed Version:** `{core.version}`  ",
            "",
        ]
        if core.vulnerabilities:
            lines += [
                f"### ⚠ Core Vulnerabilities ({len(core.vulnerabilities)})",
                "",
                _vuln_table(core.vulnerabilities),
                "",
            ]
        else:
            lines += ["✅ No known vulnerabilities found for this core version.", ""]
    else:
        lines += ["Version not detected — vulnerability check skipped.", ""]

    lines += ["---", ""]

    # ── Plugins ───────────────────────────────────────────────────────────
    plugin_comps = [c for c in result.components if c.kind == "plugin"]
    lines += [f"## 🔌 Plugins ({len(plugin_comps)} detected)", ""]

    if not plugin_comps:
        lines += ["No plugins detected.", ""]
    else:
        # Sort: vulnerable first, then by name
        plugin_comps_sorted = sorted(
            plugin_comps,
            key=lambda c: (not c.has_vulnerabilities, SEVERITY_ORDER.get(c.highest_severity, 99), c.name),
        )
        for comp in plugin_comps_sorted:
            vuln_badge = (
                f" — {severity_badge(comp.highest_severity)} ({len(comp.vulnerabilities)} vuln)"
                if comp.has_vulnerabilities else " — ✅ No known vulnerabilities"
            )
            lines += [
                f"### {comp.name}{vuln_badge}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Slug | `{comp.slug}` |",
                "",
            ]
            if comp.latest_version and comp.latest_version[0] != comp.version:
                lines += [
                    f"⚠️ [Outdated] Installed: `{comp.version}`",
                    "",
                    f"Lastest Version: `{comp.latest_version[0]}` (avail. since: {comp.latest_version[1]})",
                    "",
                ]
            else:
                lines += [
                    f"Installed Version: `{comp.version or 'Unknown'}`",
                    ""
                ]
            if comp.vulnerabilities:
                lines += [
                    _vuln_table(comp.vulnerabilities),
                    "",
                ]

    lines += ["---", ""]

    # ── Themes ────────────────────────────────────────────────────────────
    theme_comps = [c for c in result.components if c.kind == "theme"]
    lines += [f"## 🎨 Themes ({len(theme_comps)} detected)", ""]

    if not theme_comps:
        lines += ["No themes detected.", ""]
    else:
        for comp in theme_comps:
            vuln_badge = (
                f" — {severity_badge(comp.highest_severity)} ({len(comp.vulnerabilities)} vuln)"
                if comp.has_vulnerabilities else " — ✅ No known vulnerabilities"
            )
            lines += [
                f"### {comp.name}{vuln_badge}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Slug | `{comp.slug}` |",
                "",
            ]
            if comp.latest_version and comp.latest_version[0] != comp.version:
                lines += [
                    f"⚠️ [Outdated] Installed: `{comp.version}`",
                    "",
                    f"Lastest Version: `{comp.latest_version[0]}` (avail. since: {comp.latest_version[1]})",
                    "",
                ]
            else:
                lines += [
                    f"Installed Version: `{comp.version or 'Unknown'}`",
                    ""
                ]
            if comp.vulnerabilities:
                lines += [
                    _vuln_table(comp.vulnerabilities),
                    "",
                ]

    lines += ["---", ""]

    # ── Log Analysis ────────────────────────────────────────────────────
    lines += ["## 📜 Log Analysis", ""]
    if result.log_analysis:
        lines += [
            f"**Analysis Summary:** {result.log_analysis}",
            "",
        ]
    else:
        lines += [
            "No log analysis available.",
            "",
        ]

    lines += ["---", ""]

    report_text = "\n".join(lines)
    filename.write_text(report_text, encoding="utf-8")
    return filename
