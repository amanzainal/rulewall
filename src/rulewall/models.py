"""Core data structures shared across rulewall.

These are deliberately plain dataclasses with no third-party deps so the whole
tool stays stdlib-only and trivially serializable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """SARIF-aligned severity levels.

    The string values match SARIF ``level`` so reporting is a direct mapping.
    Ordering (note < warning < error) is used to decide CI exit codes.
    """

    NOTE = "note"
    WARNING = "warning"
    ERROR = "error"

    @property
    def rank(self) -> int:
        return {"note": 0, "warning": 1, "error": 2}[self.value]


@dataclass(frozen=True)
class Package:
    """A dependency that shipped a rule-file.

    ``ecosystem`` is "npm", "pypi", or "vendor". ``name`` / ``version`` are
    best-effort; version may be ``None`` when it cannot be determined.
    """

    ecosystem: str
    name: str
    version: str | None = None

    def coordinate(self) -> str:
        if self.version:
            return f"{self.name}@{self.version}"
        return self.name

    def label(self) -> str:
        return f"{self.ecosystem}:{self.coordinate()}"


@dataclass
class RuleFile:
    """A discovered AI-agent rule-file inside the dependency tree."""

    path: Path
    kind: str  # e.g. "CLAUDE.md", ".cursorrules"
    package: Package


@dataclass
class Finding:
    """A single poisoning signal detected inside a rule-file."""

    rule_id: str
    severity: Severity
    message: str
    rule_file: RuleFile
    line: int = 1
    column: int = 1
    snippet: str = ""

    @property
    def package(self) -> Package:
        return self.rule_file.package


@dataclass
class ScanResult:
    """Aggregate result of a scan."""

    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[RuleFile] = field(default_factory=list)
    roots: list[Path] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.findings

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def findings_by_package(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for f in self.findings:
            grouped.setdefault(f.package.label(), []).append(f)
        return grouped
