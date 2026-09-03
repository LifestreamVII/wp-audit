"""Unit tests for state.py — issue IDs, issue building, fingerprinting, diff."""

from datetime import datetime, timezone

import pytest

from models import Component, SiteAuditResult, Vulnerability
from state import (Diff, Issue, State, build_issues, fingerprint,
                   gen_issueid)


def _vuln(name="CVE-2024-1234 — XSS", severity="high"):
    return Vulnerability(
        name=name, description="bad thing",
        max_version="2.0", min_version=None,
        cvss_score=7.5, cvss_severity=severity,
        sources=[], cwe=[], unfixed=False,
    )


def _comp(kind="plugin", slug="wp-file-manager", version="6.8",
          latest=None, vulns=None):
    c = Component(kind=kind, slug=slug, name=slug, version=version,
                  latest_version=latest, vulnerabilities=vulns or [])
    return c


def _result(name="site", reachable=True, wp_version="6.4.2",
            components=None, error=None, logs=None):
    return SiteAuditResult(
        name=name, url="https://x", audited_at="2026-01-01 00:00 UTC",
        reachable=reachable, error=error, wp_version=wp_version,
        logs=logs, log_analysis=None, wp_version_source="version.php",
        components=components or [],
    )


# ---------------------------------------------------------------------------
# gen_issueid
# ---------------------------------------------------------------------------
def test_issueid_vuln_with_cve():
    iid = gen_issueid("vuln", component=_comp(), vulnerability=_vuln())
    assert iid == "vuln|plugin|wp-file-manager|CVE-2024-1234"


def test_issueid_vuln_without_cve_hashes_name():
    iid = gen_issueid("vuln", component=_comp(slug="foo"),
                      vulnerability=_vuln(name="No CVE here"))
    prefix = "vuln|plugin|foo|"
    assert iid.startswith(prefix)
    assert len(iid) == len(prefix) + 8


def test_issueid_outdated_log_fail_unreachable():
    assert gen_issueid("outdated", component=_comp()) == "outdated|plugin|wp-file-manager"
    assert gen_issueid("log", site_name="my site") == "log|my site"
    assert gen_issueid("fail", component=_comp()) == "fail|plugin|wp-file-manager"
    assert gen_issueid("unreachable", site_name="my site") == "unreachable|my site"


def test_issueid_requires_its_arguments():
    with pytest.raises(ValueError):
        gen_issueid("vuln")  # missing component/vulnerability
    with pytest.raises(ValueError):
        gen_issueid("outdated")  # missing component
    with pytest.raises(ValueError):
        gen_issueid("log")  # missing site_name
    with pytest.raises(ValueError):
        gen_issueid("unreachable")  # missing site_name
    with pytest.raises(ValueError):
        gen_issueid("bogus-type")


# ---------------------------------------------------------------------------
# build_issues
# ---------------------------------------------------------------------------
def test_build_issues_vuln_and_outdated():
    now = "2026-01-01T00:00:00+00:00"
    comp_vuln = _comp(version="6.8", latest=("8.0.4", "2025-01-01"),
                      vulns=[_vuln()])
    comp_clean = _comp(slug="akismet", version="3.0", latest=("4.5", "2025-01-01"))
    issues = build_issues(_result(components=[comp_vuln, comp_clean]), now)

    assert any(i.startswith("vuln|plugin|wp-file-manager|") for i in issues)
    assert issues["outdated|plugin|akismet"].severity == "low"
    assert issues["outdated|plugin|akismet"].action == "Update to 4.5"


def test_build_issues_unreachable_only():
    now = "2026-01-01T00:00:00+00:00"
    issues = build_issues(_result(reachable=False, error="boom"), now)
    assert set(issues.keys()) == {"unreachable|site"}


def test_build_issues_log_finding():
    now = "2026-01-01T00:00:00+00:00"
    issues = build_issues(_result(logs=["[01-Jan-2026 00:00:00 UTC] PHP Warning: x"]), now)
    assert any(k.startswith("log|") for k in issues)


# ---------------------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------------------
def test_fingerprint_deterministic_and_sensitive():
    a = _result(components=[_comp(version="6.8", vulns=[_vuln()])])
    b = _result(components=[_comp(version="6.8", vulns=[_vuln()])])
    assert fingerprint(a) == fingerprint(b)
    c = _result(components=[_comp(version="6.9", vulns=[_vuln()])])
    assert fingerprint(a) != fingerprint(c)
    d = _result(components=[_comp(version="6.8")])  # vuln removed
    assert fingerprint(a) != fingerprint(d)


# ---------------------------------------------------------------------------
# Diff classification
# ---------------------------------------------------------------------------
def _state_with(snapshot_by_name):
    st = State(__import__("pathlib").Path("/nonexistent/state.json"))
    st.sites = snapshot_by_name
    return st


def test_diff_classifies_new_existing_resolved_unchanged():
    now = datetime.now(timezone.utc).isoformat()
    # foo must persist as EXISTING; baz must disappear as RESOLVED
    old_issues = {
        "vuln|plugin|foo|CVE-2024-1234": Issue(
            id="vuln|plugin|foo|CVE-2024-1234", severity="high", component="foo",
            detail="old", action="fix", first_seen="2025-01-01"),
        "vuln|plugin|baz|CVE-2024-5555": Issue(
            id="vuln|plugin|baz|CVE-2024-5555", severity="medium", component="baz",
            detail="gone", action="fix", first_seen="2025-01-01"),
    }
    old_snap = __import__("state", fromlist=["SiteSnapshot"]).SiteSnapshot(
        fingerprint="OLD", last_checked="2025-01-01", issues=old_issues)

    st = _state_with({"site": old_snap})
    d = Diff(st)

    # new run: foo still vulnerable (existing), bar is brand new (new),
    # baz no longer present (resolved)
    comp_foo = _comp(slug="foo", version="1", vulns=[_vuln()])  # CVE-2024-1234
    comp_bar = _comp(slug="bar", version="2", vulns=[_vuln(name="CVE-2024-9999")])
    d.add(_result(components=[comp_foo, comp_bar]))

    dr = d.finalize()
    assert any(i.id == "vuln|plugin|foo|CVE-2024-1234" for _, i in dr.existing)
    assert any(i.id == "vuln|plugin|bar|CVE-2024-9999" for _, i in dr.new)
    assert any(i.id == "vuln|plugin|baz|CVE-2024-5555" for _, i in dr.resolved)
    assert "site" in st.sites


def test_diff_unchanged_when_fingerprint_same():
    # unchanged requires the OLD fingerprint to equal the NEW one exactly
    fp = fingerprint(_result(components=[]))
    old_snap = __import__("state", fromlist=["SiteSnapshot"]).SiteSnapshot(
        fingerprint=fp, last_checked="2025-01-01", issues={})
    st = _state_with({"site": old_snap})
    d = Diff(st)
    d.add(_result(components=[]))
    dr = d.finalize()
    assert "site" in dr.unchanged


def test_diff_errored_when_unreachable():
    st = _state_with({})
    d = Diff(st)
    d.add(_result(reachable=False, error="no route"))
    dr = d.finalize()
    assert dr.errored == [("site", "no route")]


def test_state_roundtrip(tmp_path):
    st = State(tmp_path / "state.json")
    st.sites["site"] = __import__("state", fromlist=["SiteSnapshot"]).SiteSnapshot(
        fingerprint="F", last_checked="2026-01-01",
        issues={"vuln|plugin|foo|CVE-1": Issue(
            id="vuln|plugin|foo|CVE-1", severity="high", component="foo",
            detail="d", action="a", first_seen="2026-01-01")})
    st.save()
    loaded = State(tmp_path / "state.json").load()
    assert loaded.sites["site"].fingerprint == "F"
    assert "vuln|plugin|foo|CVE-1" in loaded.sites["site"].issues