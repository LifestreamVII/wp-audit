"""
state.py — Persistent state + diff logic for wp-audit.

Handles loading/saving the JSON state file, fingerprinting site audit
results, generating deterministic issue IDs, and diffing successive
runs to classify issues as NEW / EXISTING / RESOLVED.
"""

import json
import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from models import Component, SiteAuditResult, Vulnerability

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Data containers (pure data, no logic)
# ---------------------------------------------------------------------------

@dataclass
class Issue:
    """A single tracked issue, as persisted in state.json."""
    id:         str
    severity:   str
    component:  str
    detail:     str
    action:     str
    first_seen: str   # ISO-8601 timestamp
    link:       Optional[str] = None


@dataclass
class SiteSnapshot:
    """Per-site state as persisted in state.json."""
    fingerprint:  str
    last_checked: str
    issues:       dict[str, Issue] = field(default_factory=dict)  # keyed by issue ID


@dataclass
class DiffResult:
    """Output of diff() — feeds directly into the email digest."""
    new:        list[tuple[str, Issue]]          # (site_name, issue)
    existing:   list[tuple[str, Issue]]          # (site_name, issue)
    resolved:   list[tuple[str, Issue]]          # (site_name, issue)
    unchanged:  list[str]                        # site names
    errored:    list[tuple[str, str]]            # (site_name, error_message)


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

class State:
    """Read/write the state.json file."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.last_run: Optional[str] = None
        self.sites: dict[str, SiteSnapshot] = {}

    # -- Persistence -------------------------------------------------------

    def load(self) -> "State":
        """Load from disk.  Returns self for chaining."""
        if self.path.exists():
            raw = json.loads(self.path.read_text())
            self.last_run = raw.get("last_run")
            for name, sdata in raw.get("sites", {}).items():
                issues = {
                    iid: Issue(**ival)
                    for iid, ival in sdata.get("issues", {}).items()
                }
                self.sites[name] = SiteSnapshot(
                    fingerprint=sdata.get("fingerprint", ""),
                    last_checked=sdata.get("last_checked", ""),
                    issues=issues,
                )
        return self

    def save(self) -> None:
        """Write current state to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        blob = {
            "last_run": self.last_run,
            "sites": {
                name: {
                    "fingerprint": snap.fingerprint,
                    "last_checked": snap.last_checked,
                    "issues": {
                        iid: asdict(iss)
                        for iid, iss in snap.issues.items()
                    },
                }
                for name, snap in self.sites.items()
            },
        }
        self.path.write_text(json.dumps(blob, indent=2))


# ---------------------------------------------------------------------------
# Helpers (module-level, pure functions)
# ---------------------------------------------------------------------------

def _extract_cve(vuln: Vulnerability) -> Optional[str]:
    """Try to pull a CVE identifier from a Vulnerability.

    Checks (in order):
    1. The vulnerability name (e.g. "CVE-2024-12345 — XSS in REST API")
    2. The source list (each source dict typically has a "link" or "url" key
       pointing at an NVD / Patchstack / WPScan page whose URL contains the
       CVE)

    Returns the first CVE found (uppercased), or None.
    """
    # 1. Name
    m = _CVE_RE.search(vuln.name)
    if m:
        return m.group(0).upper()

    # 2. Sources — each entry is a dict; look through all string values
    for src in vuln.sources or []:
        if isinstance(src, dict):
            for val in src.values():
                if isinstance(val, str):
                    m = _CVE_RE.search(val)
                    if m:
                        vuln.link = src.get("link") or src.get("url") or vuln.link
                        return m.group(0).upper()
        elif isinstance(src, str):
            m = _CVE_RE.search(src)
            if m:
                return m.group(0).upper()

    return None


def _short_hash(text: str) -> str:
    """Deterministic 8-char hex hash of arbitrary text."""
    return hashlib.sha256(text.encode()).hexdigest()[:8]


def fingerprint(result: SiteAuditResult) -> str:
    """Hash of everything that matters — if this matches, nothing changed."""
    raw = json.dumps({
        "wp": result.wp_version,
        "comps": sorted((c.slug, c.version) for c in result.components),
        "vulns": sorted(
            (c.slug, v.name)
            for c in result.components
            for v in c.vulnerabilities
        ),
        "comp_errors": sorted(result.components_errors),
        "logs": result.logs[0] if result.logs else None,
    }, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Issue ID generation
# ---------------------------------------------------------------------------

def gen_issueid(
    finding_type: str,
    *,
    component: Optional[Component] = None,
    vulnerability: Optional[Vulnerability] = None,
    log_line: Optional[str] = None,
    site_name: Optional[str] = None,
) -> str:
    """Generate a deterministic, stable issue ID for state tracking.

    Patterns (from fixes.md):

        Finding type        ID pattern
        ───────────────     ──────────────────────────────────────
        Vulnerability       vuln|{kind}|{slug}|{CVE-or-hash}
        Outdated component  outdated|{kind}|{slug}
        Log finding         log|{short_hash}
        Unreachable site    unreachable|{site_name}
    """

    if finding_type == "vuln":
        if component is None or vulnerability is None:
            raise ValueError(
                "gen_issueid('vuln') requires both component and vulnerability"
            )
        cve = _extract_cve(vulnerability)
        vuln_id = cve if cve else _short_hash(vulnerability.name)
        return f"vuln|{component.kind}|{component.slug}|{vuln_id}"

    elif finding_type == "outdated":
        if component is None:
            raise ValueError("gen_issueid('outdated') requires component")
        return f"outdated|{component.kind}|{component.slug}"

    elif finding_type == "log":
        if log_line is None:
            raise ValueError("gen_issueid('log') requires log_line")
        return f"log|{_short_hash(log_line)}"
    
    elif finding_type == "fail":
        if component is None:
            raise ValueError("gen_issueid('fail') requires component")
        return f"fail|{component.kind}|{component.slug}"

    elif finding_type == "unreachable":
        if site_name is None:
            raise ValueError("gen_issueid('unreachable') requires site_name")
        return f"unreachable|{site_name}"

    else:
        raise ValueError(f"Unknown finding_type: {finding_type!r}")


# ---------------------------------------------------------------------------
# Building current issues from a SiteAuditResult
# ---------------------------------------------------------------------------

def build_issues(result: SiteAuditResult, now: str) -> dict[str, Issue]:
    """Extract every issue from a SiteAuditResult, keyed by issue ID.

    This is the bridge between audit-time models (Component, Vulnerability)
    and the state layer (Issue).  The `now` timestamp is used as the default
    first_seen; callers (i.e. diff()) may overwrite it with a preserved value.
    """
    issues: dict[str, Issue] = {}

    # ── Unreachable site ──────────────────────────────────────────────
    if not result.reachable:
        iid = gen_issueid("unreachable", site_name=result.name)
        issues[iid] = Issue(
            id=iid,
            severity="unknown",
            component="site",
            detail=result.error or "Unreachable",
            action="Check SSH connectivity",
            first_seen=now,
        )
        return issues  # can't inspect further if unreachable

    for comp in result.components:
        # ── Vulnerabilities ───────────────────────────────────────────
        for vuln in comp.vulnerabilities:
            iid = gen_issueid("vuln", component=comp, vulnerability=vuln)
            if comp.latest_version:
                action = f"Update {comp.name} to {comp.latest_version[0]}"
            else:
                action = "Investigate"
            issues[iid] = Issue(
                id=iid,
                severity=vuln.severity_label,
                component=comp.name,
                detail=vuln.description or vuln.name,
                action=action,
                first_seen=now,
                link=vuln.link,
            )

        # ── Could not fetch vulnerabilities/version ─────────────────────────────
        if comp.slug in result.components_errors:
            iid = gen_issueid("fail", component=comp)
            issues[iid] = Issue(
                id=iid,
                severity="unknown",
                component=comp.name,
                detail=result.components_errors[comp.slug],
                action="Investigate audit script or server connectivity",
                first_seen=now,
            )

        # ── Outdated (no vuln, but behind on version) ─────────────────
        if comp.latest_version and not comp.vulnerabilities:
            latest_ver, _ = comp.latest_version
            if comp.version and comp.version != latest_ver:
                iid = gen_issueid("outdated", component=comp)
                issues[iid] = Issue(
                    id=iid,
                    severity="low",
                    component=comp.name,
                    detail=f"{comp.version} installed, {latest_ver} available",
                    action=f"Update to {latest_ver}",
                    first_seen=now,
                )

    # ── Log findings ──────────────────────────────────────────────────
    if result.logs and len(result.logs) > 0:
        log_line = result.logs[0] or None
        if log_line is not None:
            iid = gen_issueid("log", log_line=log_line)
            detail = result.log_analysis or "Review log entry"
            issues[iid] = Issue(
                id=iid,
                severity="unknown",
                component="debug.log",
                detail=detail,
                action="Review log entry",
                first_seen=now,
            )

    return issues


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

class Diff:
    """Incremental diff engine — compare one site at a time against old state.

    Usage::

        state = State(path).load()
        d = Diff(state)

        for site in sites:
            result = audit_site(...)
            d.add(result)

        dr = d.finalize()   # → DiffResult, also updates state for .save()
        state.save()

    Calling ``add(result)`` diffs that single site's result against whatever
    the previous state had for it.  ``finalize()`` packages everything into
    a DiffResult and updates the State in-place.
    """

    def __init__(self, state: State):
        self._state = state
        self._now = datetime.now(timezone.utc).isoformat()

        # Accumulate across add() calls
        self._new:       list[tuple[str, Issue]] = []
        self._existing:  list[tuple[str, Issue]] = []
        self._resolved:  list[tuple[str, Issue]] = []
        self._unchanged: list[str]               = []
        self._errored:   list[tuple[str, str]]   = []

        # Build the new state incrementally
        self._new_sites: dict[str, SiteSnapshot] = {}

    # -- Per-site entry point ----------------------------------------------

    def add(self, result: SiteAuditResult) -> None:
        """Diff a single site result against its previous state."""
        site = result.name
        old_snap = self._state.sites.get(site)

        if not result.reachable:
            self._add_errored(site, result, old_snap)
        elif old_snap and old_snap.fingerprint == fingerprint(result):
            self._add_unchanged(site, old_snap)
        else:
            self._add_changed(site, result, old_snap)
        
    # -- Internal handlers (one per classification) ------------------------

    def _add_errored(
        self, site: str, result: SiteAuditResult, old_snap: Optional[SiteSnapshot]
    ) -> None:
        error_msg = result.error or "Unreachable"
        self._errored.append((site, error_msg))

        current = build_issues(result, self._now)
        if old_snap:
            for iid, iss in current.items():
                if iid in old_snap.issues:
                    iss.first_seen = old_snap.issues[iid].first_seen

        self._new_sites[site] = SiteSnapshot(
            fingerprint="",
            last_checked=self._now,
            issues={iid: iss for iid, iss in current.items() if not iid.startswith("fail|")},
        )

    def _add_unchanged(self, site: str, old_snap: SiteSnapshot) -> None:
        self._unchanged.append(site)
        self._new_sites[site] = SiteSnapshot(
            fingerprint=old_snap.fingerprint,
            last_checked=self._now,
            issues=dict(old_snap.issues),
        )

    def _add_changed(
        self, site: str, result: SiteAuditResult, old_snap: Optional[SiteSnapshot]
    ) -> None:
        fp = fingerprint(result)
        current = build_issues(result, self._now)
        old_issues = old_snap.issues if old_snap else {}

        current_ids = set(current.keys())
        old_ids     = set(old_issues.keys())

        for iid in sorted(current_ids - old_ids):            # NEW
            self._new.append((site, current[iid]))

        for iid in sorted(current_ids & old_ids):            # EXISTING
            issue = current[iid]
            issue.first_seen = old_issues[iid].first_seen    # preserve
            self._existing.append((site, issue))

        for iid in sorted(old_ids - current_ids):            # RESOLVED
            if iid.startswith("log|"):
                # don't report logs as resolved
                continue
            self._resolved.append((site, old_issues[iid]))

        self._new_sites[site] = SiteSnapshot(
            fingerprint=fp,
            last_checked=self._now,
            issues={iid: iss for iid, iss in current.items() if not iid.startswith("fail|")},
        )

    # -- Finalize ----------------------------------------------------------

    def finalize(self) -> DiffResult:
        """Package accumulated diffs and update State in-place for saving."""
        self._state.sites = self._new_sites
        self._state.last_run = self._now

        return DiffResult(
            new=self._new,
            existing=self._existing,
            resolved=self._resolved,
            unchanged=self._unchanged,
            errored=self._errored,
        )
