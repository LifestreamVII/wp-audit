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
# Version comparison helpers
# ---------------------------------------------------------------------------


def _parse_version(v: str) -> tuple:
    """Parse a version string into a comparable tuple.

    Handles common WordPress version formats including pre-release
    suffixes (alpha, beta, rc).  Pre-release versions sort before
    their corresponding release version.
    """
    v = v.strip().lstrip("vV")

    # Split into numeric parts and optional pre-release suffix.
    # Examples:
    #   "6.5.0"          -> ("6.5.0", None)
    #   "6.5.0-beta2"    -> ("6.5.0", "beta2")
    #   "6.5.0-rc1"      -> ("6.5.0", "rc1")
    match = re.match(
        r"^(\d+(?:\.\d+)*)(?:[-.]?(alpha|beta|rc|a|b)\d*)?",
        v,
        re.IGNORECASE,
    )
    if not match:
        return (0,)

    num_part = match.group(1)
    pre_part = match.group(2)

    nums = tuple(int(p) for p in num_part.split("."))

    if not pre_part:
        # Release version — pad with a large sentinel so it sorts
        # after any pre-release for the same numeric base.
        return nums + (9999,)
    else:
        # Pre-release version — a small number keeps it before the release.
        pre_lower = pre_part.lower()
        if pre_lower in ("alpha", "a"):
            pre_order = 1
        elif pre_lower in ("beta", "b"):
            pre_order = 2
        elif pre_lower == "rc":
            pre_order = 3
        else:
            pre_order = 0
        return nums + (pre_order,)


def _operator_match(installed: tuple, constraint: tuple, operator: str) -> bool:
    """Return True if *installed* satisfies ``installed <operator> constraint``."""
    if operator == "lt":
        return installed < constraint
    elif operator == "le":
        return installed <= constraint
    elif operator == "eq":
        return installed == constraint
    elif operator == "gt":
        return installed > constraint
    elif operator == "ge":
        return installed >= constraint
    else:
        # Unknown operator — be permissive and assume the constraint passes.
        return True


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
            max_operator=op.get("max_operator", "lt"),
            min_version=op.get("min_version"),
            min_operator=op.get("min_operator", "ge"),
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

    Uses the operator fields returned by the API (``max_operator`` /
    ``min_operator``) to correctly decide whether *version* falls
    within the vulnerable range.  If *version* is None, return all
    vulnerabilities (assume worst-case).
    """
    if version is None:
        return vulns

    try:
        installed = _parse_version(version)
    except Exception:
        return vulns

    applicable = []
    for vuln in vulns:
        # Evaluate max_version constraint
        max_ok = True
        if vuln.max_version:
            try:
                max_v = _parse_version(vuln.max_version)
                max_ok = _operator_match(installed, max_v, vuln.max_operator)
            except Exception:
                max_ok = True

        # Evaluate min_version constraint
        min_ok = True
        if vuln.min_version:
            try:
                min_v = _parse_version(vuln.min_version)
                min_ok = _operator_match(installed, min_v, vuln.min_operator)
            except Exception:
                min_ok = True

        if max_ok and min_ok:
            applicable.append(vuln)

    return applicable
