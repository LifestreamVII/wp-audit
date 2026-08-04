"""Unit tests for the version comparison / vulnerability-filtering logic."""

from vulnerabilities import _parse_version, _operator_match, filter_vulns_for_version
from models import Vulnerability


# ---------------------------------------------------------------------------
# _parse_version
# ---------------------------------------------------------------------------
def test_parse_version_basic():
    assert _parse_version("6.5.0") == (6, 5, 0, 9999)
    assert _parse_version("1.2") == (1, 2, 9999)


def test_parse_version_strips_prefix():
    assert _parse_version("v6.4.2")[0] == 6
    assert _parse_version("V1.0.0")[0] == 1


def test_parse_version_prerelease_ordering():
    # A pre-release sorts BEFORE its own release (sentinel 9999 vs 1/2/3).
    assert _parse_version("6.5.0-alpha") == (6, 5, 0, 1)
    assert _parse_version("6.5.0-beta") == (6, 5, 0, 2)
    assert _parse_version("6.5.0-rc1") == (6, 5, 0, 3)
    # alpha < beta < rc < release
    assert _parse_version("6.5.0-alpha") < _parse_version("6.5.0-beta")
    assert _parse_version("6.5.0-beta") < _parse_version("6.5.0-rc1")
    assert _parse_version("6.5.0-rc1") < _parse_version("6.5.0")


def test_parse_version_garbage():
    assert _parse_version("not-a-version") == (0,)


# ---------------------------------------------------------------------------
# _operator_match
# ---------------------------------------------------------------------------
def test_operator_match_examples():
    assert _operator_match((5, 1, 9, 9999), (5, 3, 2, 9999), "lt") is True
    assert _operator_match((5, 3, 2, 9999), (5, 3, 2, 9999), "lt") is False
    assert _operator_match((5, 3, 2, 9999), (5, 3, 2, 9999), "le") is True
    assert _operator_match((6, 8, 0, 9999), (7, 9999), "lt") is True


def test_operator_match_pads_shorter_tuple():
    # real parsed versions always carry the release sentinel as the last element;
    # padding aligns the shorter one without changing the comparison outcome
    assert _operator_match((6, 8, 0, 9999), (7, 9999), "lt") is True
    assert _operator_match((8, 0, 0, 9999), (7, 9999), "lt") is False
    assert _operator_match((7, 9999), (6, 8, 0, 9999), "gt") is True


def test_operator_match_unknown_is_permissive():
    assert _operator_match((1, 2, 3, 9999), (9, 9, 9, 9999), "??") is True


# ---------------------------------------------------------------------------
# filter_vulns_for_version
# ---------------------------------------------------------------------------
def _vuln(max_version=None, min_version=None, max_op="lt", min_op="ge"):
    return Vulnerability(
        name="V", description=None,
        max_version=max_version, min_version=min_version,
        cvss_score=9.0, cvss_severity="critical",
        sources=[], cwe=[], unfixed=False,
        max_operator=max_op, min_operator=min_op,
    )


def test_filter_none_version_returns_all():
    vulns = [_vuln(max_version="6.0")]
    assert filter_vulns_for_version(vulns, None) == vulns


def test_filter_max_only():
    vulns = [_vuln(max_version="5.3.2")]
    assert filter_vulns_for_version(vulns, "5.3.1") == vulns
    assert filter_vulns_for_version(vulns, "5.3.2") == []
    assert filter_vulns_for_version(vulns, "6.0.0") == []


def test_filter_min_and_max_range():
    vulns = [_vuln(min_version="4.0", max_version="5.0")]
    assert filter_vulns_for_version(vulns, "4.5") == vulns
    assert filter_vulns_for_version(vulns, "3.9") == []
    assert filter_vulns_for_version(vulns, "5.0") == []


def test_filter_each_vuln_independently():
    v1 = _vuln(max_version="5.0")   # applies to 4.x
    v2 = _vuln(min_version="6.0")   # applies to 7.x
    out = filter_vulns_for_version([v1, v2], "4.0")
    assert v1 in out
    assert v2 not in out