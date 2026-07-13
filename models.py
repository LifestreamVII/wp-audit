"""
models.py — Data classes for wp_audit.
"""

from dataclasses import dataclass, field
from typing import Optional

from config import SEVERITY_ORDER


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    name: str
    description: Optional[str]
    max_version: Optional[str]
    min_version: Optional[str]
    cvss_score: Optional[float]
    cvss_severity: Optional[str]
    sources: list[dict]
    cwe: list[str]
    unfixed: bool
    max_operator: str = "lt"
    min_operator: str = "ge"
    link: Optional[str] = None

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
    latest_version: Optional[tuple[str, str]] = None  # (version, last_updated)
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
    logs: Optional[list[str]]
    log_analysis: Optional[str]
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
            sev = SEVERITY_ORDER.get(v.highest_severity, 99)
            if sev < min_v:
                min_v = sev
        return list(SEVERITY_ORDER.keys())[min_v]

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(c.vulnerabilities) for c in self.components)
