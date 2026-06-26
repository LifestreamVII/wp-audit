#!/usr/bin/env python3
"""
wp_audit.py — Automated WordPress Security Audit Tool
------------------------------------------------------
Audits multiple WordPress sites using SSH access to the site directory
  - WP core version
  - Installed themes & plugins
  - Vulnerability lookups via wpvulnerability.net API

Generates one Markdown report per site in ./reports/

Usage:
    python wp_audit.py [--config sites.yaml] [--output-dir reports]
"""

import argparse
import json
import paramiko
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
import yaml

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = "sites.yaml"
DEFAULT_OUTPUT_DIR = "reports"
REQUEST_TIMEOUT = 15          # seconds per HTTP request
CONNECTION_RETRIES = 2        # number of retries for transient errors
RATE_LIMIT_DELAY = 0.5        # seconds between requests to wpvulnerability.net
USER_AGENT = (
    "Mozilla/5.0 (compatible; wp_audit/1.0; +) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)
WPVULN_API_BASE = "https://www.wpvulnerability.net"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "unknown": 5}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("wp_audit")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    name: str
    description: Optional[str]
    max_version: Optional[str]
    min_version: Optional[str]
    unfixed: bool
    sources: list[dict]
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    cwe: list[str]

    @property
    def severity_label(self) -> str:
        s = self.cvss_severity or "unknown"
        return s.lower()


@dataclass
class Component:
    """A WordPress component (core, plugin, or theme)."""
    kind: str             # "core" | "plugin" | "theme"
    slug: str
    name: str
    version: Optional[str]
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    version_source: str = "unknown"  # how the version was detected

    @property
    def highest_severity(self) -> str:
        if not self.vulnerabilities:
            return "none"
        min_v = 4
        for v in self.vulnerabilities:
            sev = SEVERITY_ORDER.get(v.severity_label, 99)
            if sev < min_v:
                min_v = sev
        return list(SEVERITY_ORDER.keys())[min_v]

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0


@dataclass
class SiteAuditResult:
    name: str
    url: str
    audited_at: str
    reachable: bool
    error: Optional[str]
    wp_version: Optional[str]
    wp_version_source: str
    components: list[Component] = field(default_factory=list)

    @property
    def vulnerable_components(self) -> list[Component]:
        return [c for c in self.components if c.has_vulnerabilities]

    @property
    def highest_severity(self) -> str:
        if not self.vulnerable_components:
            return "none"
        min_v = 4
        for v in self.vulnerable_components:
            sev = SEVERITY_ORDER.get(v.severity_label, 99)
            if sev < min_v:
                min_v = sev
        return list(SEVERITY_ORDER.keys())[min_v]

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(c.vulnerabilities) for c in self.components)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

class HTTP:
    session: requests.Session

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def get(self, url: str, *, silent: bool = False, **kwargs) -> Optional[requests.Response]:
        try:
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
            return resp
        except requests.exceptions.SSLError as e:
            if not silent:
                log.warning("SSL error for %s: %s", url, e)
        except requests.exceptions.ConnectionError as e:
            if not silent:
                log.warning("Connection error for %s: %s", url, e)
        except requests.exceptions.Timeout:
            if not silent:
                log.warning("Timeout for %s", url)
        except requests.exceptions.RequestException as e:
            if not silent:
                log.warning("Request error for %s: %s", url, e)
        return None


http = HTTP()


# ---------------------------------------------------------------------------
# WordPress detection helpers
# ---------------------------------------------------------------------------

def client_connect(host: str, user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, password=password, timeout=10, port=3211)
    return client

def establish_connection(host: str, user: str, password: str) -> bool:
    """
    Attempt to establish an SSH connection to the host using provided credentials.
    Returns True if successful, False otherwise.
    """
    success = False
    retries = 0
    while success is False and retries < CONNECTION_RETRIES:
        try:
            client = client_connect(host, user, password)
            client.close()
            success = True
            break
        except paramiko.AuthenticationException:
            log.warning("Authentication failed for %s@%s", user, host)
        except paramiko.SSHException as e:
            log.warning("SSH error for %s@%s: %s", user, host, e)
        except Exception as e:
            log.warning("Connection error for %s@%s: %s", user, host, e)
        success = False
        retries += 1
    return success

def run_ssh_command(client: paramiko.SSHClient, command: str) -> Optional[str]:
    """
    Execute a command on the SSH client and return its output as a string.
    Returns None if the command fails or produces no output.
    """
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode("utf-8").strip()
        error = stderr.read().decode("utf-8").strip()
        if error:
            log.warning("SSH command error: %s", error)
            return None
        return output if output else None
    except Exception as e:
        log.warning("Failed to execute SSH command '%s': %s", command, e)
        return None

def detect_wp_version(client: paramiko.SSHClient, directory: str) -> tuple[Optional[str], str]:
    """
    Detect the WordPress core version from wp-includes/version.php via SSH.
    Returns a (version_string, source_label) tuple.
    """
    # Primary: parse $wp_version from version.php
    version_file = f"{directory.rstrip('/')}/wp-includes/version.php"
    output = run_ssh_command(
        client,
        f"grep -E \"\\$wp_version\\s*=\" {version_file} 2>/dev/null | head -1",
    )
    if output:
        m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", output)
        if m:
            return m.group(1), "version.php"

    # Fallback: wp-includes/version.php may use a different variable name on some builds
    output2 = run_ssh_command(
        client,
        f"php -r \"include('{version_file}'); echo \$wp_version;\" 2>/dev/null",
    )
    if output2 and re.match(r"^[\d.]+$", output2.strip()):
        return output2.strip(), "version.php (php eval)"

    return None, "not-detected"


def extract_themes(client: paramiko.SSHClient, directory: str) -> Optional[dict]:
    """List installed themes from wp-content/themes/ via SSH.

    Returns a dict mapping slug -> display name (slug is used as name when
    Style.css cannot be read).
    """
    themes_dir = f"{directory.rstrip('/')}/wp-content/themes"
    output = run_ssh_command(client, f"ls -1 {themes_dir} 2>/dev/null")
    if not output:
        return None
    themes: dict[str, str] = {}
    for slug in output.splitlines():
        slug = slug.strip()
        if not slug:
            continue
        # Try to get the Theme Name from style.css
        style_css = f"{themes_dir}/{slug}/style.css"
        name_output = run_ssh_command(
            client,
            f"grep -m1 '^Theme Name' {style_css} 2>/dev/null",
        )
        if name_output:
            m = re.match(r"Theme Name\s*:\s*(.+)", name_output)
            name = m.group(1).strip() if m else slug
        else:
            name = slug
        themes[slug] = name
    return themes or None


def probe_content_version(client: paramiko.SSHClient, directory: str, kind: str, slug: str) -> Optional[str]:
    """
    Probe the readme.txt (or the main plugin PHP file header) of a plugin or
    theme to extract its version string via SSH.
    """
    base = f"{directory.rstrip('/')}/wp-content/{kind}s/{slug}"

    # 1. Try readme.txt "Stable tag" line (plugins & themes)
    for readme in ("readme.txt", "README.txt", "README.md"):
        output = run_ssh_command(
            client,
            f"grep -im1 'stable tag' {base}/{readme} 2>/dev/null",
        )
        if output:
            m = re.search(r"stable tag\s*:\s*([\d.]+)", output, re.IGNORECASE)
            if m:
                return m.group(1).strip()

    # 2. Try "Version:" header in the main plugin PHP file
    if kind == "plugin":
        main_php = run_ssh_command(
            client,
            f"grep -rim1 '^[ \t*]*Version:' {base}/*.php 2>/dev/null | head -1",
        )
        if main_php:
            m = re.search(r"Version:\s*([\d.]+)", main_php, re.IGNORECASE)
            if m:
                return m.group(1).strip()

    return None


def extract_plugins(client: paramiko.SSHClient, directory: str) -> Optional[dict]:
    """List installed plugins from wp-content/plugins/ via SSH.

    Returns a dict mapping slug -> display name.
    """
    plugins_dir = f"{directory.rstrip('/')}/wp-content/plugins"
    output = run_ssh_command(client, f"ls -1 {plugins_dir} 2>/dev/null")
    if not output:
        return None
    plugins: dict[str, str] = {}
    for slug in output.splitlines():
        slug = slug.strip()
        if not slug:
            continue
        # Try to get the Plugin Name from the main PHP header
        name_output = run_ssh_command(
            client,
            f"grep -rim1 '^[ \t*]*Plugin Name' {plugins_dir}/{slug}/*.php 2>/dev/null | head -1",
        )
        if name_output:
            m = re.search(r"Plugin Name\s*:\s*(.+)", name_output, re.IGNORECASE)
            name = m.group(1).strip() if m else slug
        else:
            name = slug
        plugins[slug] = name
    return plugins or None

# ---------------------------------------------------------------------------
# WPVulnerability.net API
# ---------------------------------------------------------------------------

_vuln_cache: dict[str, list[Vulnerability]] = {}


def _parse_vulnerabilities(data: dict | None) -> list[Vulnerability]:
    """Parse vulnerability list from the wpvulnerability.net API response."""
    if not data:
        return []
    vulns = []
    for v in data.get("vulnerability", []) or []:
        op = v.get("operator", {}) or {}
        impact = v.get("impact", {}) or {}
        cvss = impact.get("cvss3") or impact.get("cvss") or {}
        cwe_list = [c["cwe"] for c in impact.get("cwe", []) if c.get("cwe")]
        sources = v.get("source", [])

        vuln = Vulnerability(
            name=v.get("name", "Unknown"),
            description=v.get("description"),
            max_version=op.get("max_version"),
            min_version=op.get("min_version"),
            unfixed=op.get("unfixed", "0") == "1",
            sources=sources,
            cvss_score=float(cvss["score"]) if cvss.get("score") else None,
            cvss_severity=cvss.get("severity"),
            cwe=cwe_list,
        )
        vulns.append(vuln)
    return vulns


def fetch_vulnerabilities(kind: str, slug: str) -> list[Vulnerability]:
    """
    Fetch vulnerabilities for a plugin or theme from wpvulnerability.net.
    kind: "plugin" or "theme" or "core"
    slug: e.g. "woocommerce" or "6.5.0" (for core)
    """
    cache_key = f"{kind}:{slug}"
    if cache_key in _vuln_cache:
        return _vuln_cache[cache_key]

    url = f"{WPVULN_API_BASE}/{kind}/{slug}"
    time.sleep(RATE_LIMIT_DELAY)
    resp = http.get(url)
    if not resp:
        log.warning("  ✗ Could not reach wpvulnerability.net for %s/%s", kind, slug)
        _vuln_cache[cache_key] = []
        return []

    if resp.status_code == 404:
        _vuln_cache[cache_key] = []
        return []

    try:
        data = resp.json()
        if data.get("error") != 0:
            log.debug("  API error for %s/%s: %s", kind, slug, data.get("message"))
            _vuln_cache[cache_key] = []
            return []
        # API returns data: null when the component has no recorded entries
        payload = data.get("data")  # may be None or a dict
        vulns = _parse_vulnerabilities(payload)
        _vuln_cache[cache_key] = vulns
        return vulns
    except (ValueError, KeyError) as e:
        log.warning("  ✗ Failed to parse vulnerability data for %s/%s: %s", kind, slug, e)
        _vuln_cache[cache_key] = []
        return []


def filter_vulns_for_version(
    vulns: list[Vulnerability], version: Optional[str]
) -> list[Vulnerability]:
    """
    Filter vulnerabilities that apply to the given installed version.
    Uses simple semver-style comparison matching the API's operator semantics.
    If version is None, return all (assume worst-case).
    """
    if version is None:
        return vulns

    def version_tuple(v: str):
        """Convert version string to comparable tuple, ignoring non-numeric parts."""
        parts = []
        for p in re.split(r"[.\-]", v):
            try:
                parts.append(int(p))
            except ValueError:
                pass
        return tuple(parts) or (0,)

    try:
        installed = version_tuple(version)
    except Exception:
        return vulns

    applicable = []
    for vuln in vulns:
        # Evaluate max_version constraint
        max_ok = True
        if vuln.max_version:
            try:
                max_v = version_tuple(vuln.max_version)
                op = "lt"  # default from API docs
                # We derive the operator from the vulnerability name as fallback;
                # the actual operator field is in the raw data — we stored it indirectly
                # in the Vulnerability object via max_version presence.
                # For simplicity, assume max_operator is "lt" (most common in the API).
                max_ok = installed < max_v
            except Exception:
                max_ok = True

        # Evaluate min_version constraint
        min_ok = True
        if vuln.min_version:
            try:
                min_v = version_tuple(vuln.min_version)
                min_ok = installed >= min_v
            except Exception:
                min_ok = True

        if max_ok and min_ok:
            applicable.append(vuln)

    return applicable


# ---------------------------------------------------------------------------
# Site auditor
# ---------------------------------------------------------------------------

def audit_site(name: str, host: str, username: str, password: str, directory: str, url: str) -> SiteAuditResult:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    log.info("━━━━ Auditing: %s (%s)", name, host)

    result = SiteAuditResult(
        name=name,
        url=url,
        audited_at=now,
        reachable=False,
        error=None,
        wp_version=None,
        wp_version_source="not-detected",
    )

    # ── 1. Establish SSH connection ──────────────────────────────────────────
    log.info("  🔌 Connecting to %s@%s …", username, host)
    connected = establish_connection(host, username, password)
    if not connected:
        result.error = f"Could not establish SSH connection to {username}@{host}"
        log.error("  ✗ %s", result.error)
        return result

    result.reachable = True
    client = client_connect(host, username, password)

    try:
        # ── 2. Detect WP version ─────────────────────────────────────────────
        log.info("  🔎 Detecting WordPress version…")
        wp_version, wp_version_source = detect_wp_version(client, directory)
        result.wp_version = wp_version
        result.wp_version_source = wp_version_source
        if wp_version:
            log.info("  ✓ WordPress version: %s (via %s)", wp_version, wp_version_source)
        else:
            log.warning("  ✗ Could not detect WordPress version")

        # ── 3. Discover plugins ───────────────────────────────────────────────
        log.info("  🔎 Discovering plugins…")
        plugin_map = extract_plugins(client, directory) or {}
        log.info("  ✓ %d plugin(s) found", len(plugin_map))

        # ── 4. Plugin version probing ─────────────────────────────────────────
        plugin_versions: dict[str, Optional[str]] = {}
        for slug in plugin_map:
            plugin_versions[slug] = probe_content_version(client, directory, "plugin", slug)

        # ── 5. Discover themes ────────────────────────────────────────────────
        log.info("  🔎 Discovering themes…")
        theme_map = extract_themes(client, directory) or {}
        log.info("  ✓ %d theme(s) found", len(theme_map))

        # Theme version probing
        theme_versions: dict[str, Optional[str]] = {}
        for slug in theme_map:
            theme_versions[slug] = probe_content_version(client, directory, "theme", slug)

    finally:
        client.close()

    # ── 6. Build component list ────────────────────────────────────────────
    components: list[Component] = []

    # WP Core
    if wp_version:
        components.append(Component(
            kind="core",
            slug=wp_version,
            name="WordPress Core",
            version=wp_version,
            version_source=wp_version_source,
        ))

    # Plugins
    for slug, display_name in plugin_map.items():
        components.append(Component(
            kind="plugin",
            slug=slug,
            name=display_name,
            version=plugin_versions.get(slug),
            version_source="readme.txt" if plugin_versions.get(slug) else "not-detected",
        ))

    # Themes
    for slug, display_name in theme_map.items():
        components.append(Component(
            kind="theme",
            slug=slug,
            name=display_name,
            version=theme_versions.get(slug),
            version_source="style.css" if theme_versions.get(slug) else "not-detected",
        ))

    # ── 7. Vulnerability lookups ───────────────────────────────────────────
    log.info("  🔍 Looking up vulnerabilities for %d component(s)…", len(components))
    for comp in components:
        if comp.kind == "core":
            all_vulns = fetch_vulnerabilities("core", comp.slug)
        elif comp.kind == "plugin":
            all_vulns = fetch_vulnerabilities("plugin", comp.slug)
        elif comp.kind == "theme":
            all_vulns = fetch_vulnerabilities("theme", comp.slug)
        else:
            all_vulns = []

        comp.vulnerabilities = filter_vulns_for_version(all_vulns, comp.version)

        if comp.vulnerabilities:
            log.info(
                "  ⚠  %s (%s): %d vulnerability/ies found",
                comp.name, comp.version or "?", len(comp.vulnerabilities),
            )

    result.components = components
    log.info(
        "  ✓ Done — %d component(s), %d vulnerable, %d total vulns",
        len(components),
        len(result.vulnerable_components),
        result.total_vulnerabilities,
    )
    return result


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
    filename = output_dir / f"audit_{safe_name}_{datetime.now().strftime('%Y%m%d')}.md"

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
        f"| WordPress Version | `{result.wp_version or 'Not detected'}` (via {result.wp_version_source}) |",
        f"| Components Detected | {total} |",
        f"| Vulnerable Components | **{vuln_count}** |",
        f"| Total Vulnerabilities | **{total_vulns}** |",
        f"| Highest Severity | {hs_emoji} **{hs.capitalize()}** |",
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
                f"| Installed Version | `{comp.version or 'Unknown'}` |",
                "",
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
                f"| Installed Version | `{comp.version or 'Unknown'}` |",
                "",
            ]
            if comp.vulnerabilities:
                lines += [
                    _vuln_table(comp.vulnerabilities),
                    "",
                ]

    lines += ["---", ""]

    report_text = "\n".join(lines)
    filename.write_text(report_text, encoding="utf-8")
    return filename


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def load_config(path: str) -> list[dict]:
    config_path = Path(path)
    if not config_path.exists():
        log.error("Config file not found: %s", path)
        sys.exit(1)
    with config_path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    sites = data.get("sites", [])
    if not sites:
        log.error("No sites defined in %s", path)
        sys.exit(1)
    return sites


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated WordPress Security Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wp_audit.py
  python wp_audit.py --config my_clients.yaml --output-dir ./results
        """,
    )
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG,
        help=f"Path to YAML config file (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--output-dir", default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for reports (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable debug-level logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sites = load_config(args.config)
    output_dir = Path(args.output_dir)

    log.info("WordPress Audit — %d site(s) to audit", len(sites))
    log.info("Reports will be saved to: %s/", output_dir)
    log.info("")

    generated_reports: list[Path] = []
    for site in sites:
        name = site.get("name", site.get("host", "Unknown"))
        host = site.get("host", "")
        username = site.get("username", "")
        password = site.get("password", "")
        directory = site.get("directory", "/var/www/html")
        url = site.get("url", f"https://{host}")
        if not host:
            log.warning("Skipping site with no host: %s", name)
            continue
        result = audit_site(name, host, username, password, directory, url)
        report_path = generate_report(result, output_dir)
        generated_reports.append(report_path)
        log.info("  📄 Report saved: %s", report_path)
        log.info("")

    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("Audit complete. %d report(s) generated:", len(generated_reports))
    for p in generated_reports:
        log.info("  • %s", p)


if __name__ == "__main__":
    main()
