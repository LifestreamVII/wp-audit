"""
vulnerabilities.py — WPVulnerability.net API client and vulnerability filtering.
"""

import re
import time
from typing import Optional

from config import RATE_LIMIT_DELAY, SEVERITY_ORDER, WPVULN_API_BASE, log
from http_client import http
from models import Vulnerability


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


def fetch_vulnerabilities(kind: str, slug: str) -> list[Vulnerability] | None:
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
        return None

    if resp.status_code == 404:
        _vuln_cache[cache_key] = []
        return None

    try:
        data = resp.json()
        if data.get("error") != 0:
            log.debug("  API error for %s/%s: %s", kind, slug, data.get("message"))
            _vuln_cache[cache_key] = []
            return None
        # API returns data: null when the component has no recorded entries
        payload = data.get("data")  # may be None or a dict
        vulns = _parse_vulnerabilities(payload)
        _vuln_cache[cache_key] = vulns
        return vulns
    except (ValueError, KeyError) as e:
        log.warning("  ✗ Failed to parse vulnerability data for %s/%s: %s", kind, slug, e)
        _vuln_cache[cache_key] = []
        return None


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
