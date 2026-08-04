"""Unit tests for models.py — severity aggregation logic."""

from models import Component, SiteAuditResult, Vulnerability


def _vuln(severity: str, score: float | None = 5.0, name: str = "V"):
    return Vulnerability(
        name=name, description=None,
        max_version="9.0", min_version=None,
        cvss_score=score, cvss_severity=severity,
        sources=[], cwe=[], unfixed=False,
    )


# ---------------------------------------------------------------------------
# Component.highest_severity / has_vulnerabilities
# ---------------------------------------------------------------------------
def test_component_no_vulns():
    c = Component(kind="plugin", slug="x", name="X", version="1.0")
    assert c.highest_severity == "none"
    assert not c.has_vulnerabilities


def test_component_highest_severity_wins():
    c = Component(kind="plugin", slug="x", name="X", version="1.0")
    c.vulnerabilities = [_vuln("low"), _vuln("critical"), _vuln("high")]
    assert c.highest_severity == "critical"


def test_component_unknown_severity_treated_lowest_priority():
    c = Component(kind="plugin", slug="x", name="X", version="1.0")
    c.vulnerabilities = [_vuln("unknown"), _vuln("medium")]
    assert c.highest_severity == "medium"


def test_component_all_unknown():
    c = Component(kind="plugin", slug="x", name="X", version="1.0")
    c.vulnerabilities = [_vuln("unknown")]
    assert c.highest_severity == "unknown"


# ---------------------------------------------------------------------------
# SiteAuditResult aggregation
# ---------------------------------------------------------------------------
def _result() -> SiteAuditResult:
    return SiteAuditResult(
        name="site", url="https://x", audited_at="2026-01-01 00:00 UTC",
        reachable=True, error=None, wp_version="6.0", logs=None,
        log_analysis=None, wp_version_source="version.php",
    )


def test_site_total_vulnerabilities():
    r = _result()
    c1 = Component(kind="plugin", slug="a", name="A", version="1")
    c1.vulnerabilities = [_vuln("high"), _vuln("medium")]
    c2 = Component(kind="theme", slug="b", name="B", version="2")
    c2.vulnerabilities = [_vuln("low")]
    r.components = [c1, c2]
    assert r.total_vulnerabilities == 3
    assert len(r.vulnerable_components) == 2


def test_site_highest_severity_aggregates_components():
    r = _result()
    c1 = Component(kind="plugin", slug="a", name="A", version="1")
    c1.vulnerabilities = [_vuln("medium")]
    r.components = [c1]
    assert r.highest_severity == "medium"


def test_site_highest_severity_none_when_clean():
    r = _result()
    r.components = [Component(kind="plugin", slug="a", name="A", version="1")]
    assert r.highest_severity == "none"