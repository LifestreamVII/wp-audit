"""Unit tests for vulnerabilities.py — API payload parsing and fetching."""

import pytest

import vulnerabilities
from conftest import FakeResponse
from vulnerabilities import _parse_vulnerabilities, fetch_vulnerabilities, _vuln_cache


def _payload():
    return {
        "error": 0,
        "data": {
            "vulnerability": [
                {
                    "name": "CVE-2024-1234 — XSS",
                    "operator": {"max_version": "7.1", "max_operator": "lt",
                                 "unfixed": "0"},
                    "impact": {
                        "cvss3": {"score": "8.1", "severity": "high"},
                        "cwe": [{"cwe": "CWE-79"}, {"cwe": "CWE-89"}],
                    },
                    "source": [
                        {"id": "CVE-2024-1234", "name": "CVE-2024-1234",
                         "link": "https://cve.org/CVE-2024-1234",
                         "description": "Reflected XSS in settings page."},
                    ],
                },
                {
                    # entry with no operator/impact — defaults must not crash
                    "name": "Mystery issue",
                },
            ]
        },
    }


def test_parse_vulnerabilities_full_entry():
    vulns = _parse_vulnerabilities(_payload()["data"])
    assert len(vulns) == 2

    v = vulns[0]
    assert v.name == "CVE-2024-1234 — XSS"
    assert v.max_version == "7.1"
    assert v.max_operator == "lt"
    assert v.min_version is None
    assert v.cvss_score == 8.1
    assert v.cvss_severity == "high"
    assert v.cwe == ["CWE-79", "CWE-89"]
    assert v.link == "https://cve.org/CVE-2024-1234"
    assert v.description == "Reflected XSS in settings page."
    assert v.unfixed is False


def test_parse_vulnerabilities_sparse_entry_defaults():
    vulns = _parse_vulnerabilities(_payload()["data"])
    v = vulns[1]
    assert v.max_version is None
    assert v.cvss_score is None
    assert v.severity_label == "unknown"
    assert v.unfixed is False


def test_parse_vulnerabilities_none():
    assert _parse_vulnerabilities(None) == []
    assert _parse_vulnerabilities({}) == []


@pytest.fixture(autouse=True)
def _clear_cache():
    _vuln_cache.clear()
    yield
    _vuln_cache.clear()


def test_fetch_vulnerabilities_success(monkeypatch):
    monkeypatch.setattr(vulnerabilities.http, "get",
                        lambda url: FakeResponse(200, _payload()))
    monkeypatch.setattr(vulnerabilities.time, "sleep", lambda s: None)

    vulns = fetch_vulnerabilities("plugin", "wp-file-manager")
    assert vulns is not None
    assert len(vulns) == 2
    # cached for the next call
    assert ("plugin:wp-file-manager") in _vuln_cache


def test_fetch_vulnerabilities_404_returns_none(monkeypatch):
    # 404 = unknown component -> the tool reports "could not fetch" (None)
    monkeypatch.setattr(vulnerabilities.http, "get",
                        lambda url: FakeResponse(404, None))
    monkeypatch.setattr(vulnerabilities.time, "sleep", lambda s: None)
    assert fetch_vulnerabilities("plugin", "does-not-exist") is None


def test_fetch_vulnerabilities_network_error_returns_none(monkeypatch):
    monkeypatch.setattr(vulnerabilities.http, "get", lambda url: None)
    monkeypatch.setattr(vulnerabilities.time, "sleep", lambda s: None)
    assert fetch_vulnerabilities("plugin", "wp-file-manager") is None


def test_fetch_vulnerabilities_api_error_payload_returns_none(monkeypatch):
    # "error != 0" responses (e.g. rate limited) also surface as None
    monkeypatch.setattr(
        vulnerabilities.http, "get",
        lambda url: FakeResponse(200, {"error": 1, "message": "rate limited"}))
    monkeypatch.setattr(vulnerabilities.time, "sleep", lambda s: None)
    assert fetch_vulnerabilities("plugin", "wp-file-manager") is None


def test_fetch_vulnerabilities_uses_kind_and_slug_in_url(monkeypatch):
    seen = []
    monkeypatch.setattr(vulnerabilities.http, "get",
                        lambda url: (seen.append(url) or FakeResponse(404, None)))
    monkeypatch.setattr(vulnerabilities.time, "sleep", lambda s: None)
    fetch_vulnerabilities("theme", "astra")
    assert seen[0].endswith("/theme/astra")