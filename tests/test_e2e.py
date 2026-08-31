"""End-to-end assertions for the dockerized vulnerable-WordPress audit.

This module does NOT orchestrate Docker — scripts/run_ci_locally.sh (and the
GitHub Actions workflow, which calls that script) builds the fixture, runs the
real `wp_audit.py` CLI against it, and then invokes `pytest -m e2e`. This test
checks the artifacts that run produced:

  * ci/run/scenario.json      — what the scenario generator picked
  * ci/run/reports/state.json — audit state (source of truth for issues)
  * ci/run/reports/*.md       — the digest report

Every expected finding type from the scenario must be present in state.json,
so a change in the vulnerable catalog or a regression in the audit tool fails
this suite loudly.
"""

import json
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

E2E_ROOT = Path(os.environ.get("E2E_ROOT", "ci/run"))
SCENARIO = E2E_ROOT / "scenario.json"
REPORTS = E2E_ROOT / "reports"


def _load_scenario() -> dict:
    return json.loads(SCENARIO.read_text(encoding="utf-8"))


def _load_state() -> dict:
    return json.loads((REPORTS / "state.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def state():
    if not SCENARIO.exists():
        pytest.skip("e2e harness not run (missing ci/run/scenario.json)")
    return _load_state()


@pytest.fixture(scope="module")
def scenario():
    return _load_scenario()


def _issues_for(state: dict, site_name: str) -> dict[str, dict]:
    return state["sites"][site_name]["issues"]


def test_state_file_and_container_site_present(state, scenario):
    assert state["sites"], "state.json has no sites"
    assert scenario["site_name"] in state["sites"]
    site = state["sites"][scenario["site_name"]]
    assert site["fingerprint"], "fixture site should have been audited (non-empty fingerprint)"


def test_core_vulnerability_found(state, scenario):
    issues = _issues_for(state, scenario["site_name"])
    core = scenario["core"]
    expected = f"vuln|core|{core['slug']}|"
    if core["expect"] == "vulnerable":
        assert any(iid.startswith(expected) for iid in issues), \
            f"expected a core vuln issue ({expected}*) — got: {sorted(issues)}"
    else:
        assert not any(iid.startswith(expected) for iid in issues)


def test_plugin_vulnerabilities_found(state, scenario):
    issues = _issues_for(state, scenario["site_name"])
    for p in scenario["plugins"]:
        prefix = f"vuln|plugin|{p['slug']}|"
        outdated_prefix = f"outdated|plugin|{p['slug']}|"
        if p["expect"] == "vulnerable":
            assert any(iid.startswith(prefix) for iid in issues), \
                f"expected plugin vuln issue ({prefix}*) — got: {sorted(issues)}"
        elif p["expect"] == "safe":
            assert not any(iid.startswith(prefix) for iid in issues), \
                f"expected no safe plugin issues ({prefix}*) — got: {sorted(issues)}"
        elif p["expect"] == "outdated":
            assert any(iid.startswith(outdated_prefix) for iid in issues), \
                f"expected outdated plugin issue ({outdated_prefix}*) — got: {sorted(issues)}"

def test_theme_vulnerabilities_found(state, scenario):
    issues = _issues_for(state, scenario["site_name"])
    for t in scenario["themes"]:
        prefix = f"vuln|theme|{t['slug']}|"
        if t["expect"] == "vulnerable":
            assert any(iid.startswith(prefix) for iid in issues), \
                f"expected theme vuln issue ({prefix}*) — got: {sorted(issues)}"


def test_outdated_issues_found(state, scenario):
    issues = _issues_for(state, scenario["site_name"])
    outdated = [iid for iid in issues if iid.startswith("outdated|")]
    assert outdated, f"expected at least one 'outdated version' issue — got: {sorted(issues)}"


def test_log_finding_issue_found(state, scenario):
    issues = _issues_for(state, scenario["site_name"])
    assert any(iid.startswith("log|") for iid in issues), \
        "expected a debug.log finding issue — got: %s" % sorted(issues)


def test_severity_distribution_covers_high(state, scenario):
    """At least one of the expected vulns must be high/critical — the whole
    point is to exercise the severity pipeline, not just presence."""
    issues = _issues_for(state, scenario["site_name"])
    sevs = {i["severity"] for i in issues.values()}
    assert sevs & {"critical", "high"}, \
        f"expected a high/critical severity issue — severities were: {sevs}"


def test_unreachable_site_tracked(state, scenario):
    if not scenario["unreachable"]:
        pytest.skip("scenario has no unreachable host")
    name = scenario["unreachable_site_name"]
    assert name in state["sites"], f"unreachable site '{name}' missing from state"
    issues = _issues_for(state, name)
    assert any(iid.startswith("unreachable|") for iid in issues), \
        f"expected an unreachable issue for '{name}' — got: {sorted(issues)}"


def test_digest_report_generated():
    reports = sorted(REPORTS.glob("Wordpress_Security_Audit_*.md"))
    assert reports, f"no digest report generated in {REPORTS}"
    text = reports[-1].read_text(encoding="utf-8")
    assert "WordPress Security Audit Digest" in text