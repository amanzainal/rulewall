"""Orchestrate a scan: discover rule-files, run detectors, attribute findings."""

from __future__ import annotations

from pathlib import Path

from rulewall.detectors import run_detectors
from rulewall.discover import discover
from rulewall.models import Finding, RuleFile, ScanResult


def _read_text(path: Path) -> str | None:
    try:
        # errors="surrogatepass" so we never lose bytes that could be a payload;
        # decode permissively because malicious files may be intentionally weird.
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def scan_rule_file(rule_file: RuleFile) -> list[Finding]:
    """Run all detectors over a single discovered rule-file."""
    text = _read_text(rule_file.path)
    if text is None:
        return []
    findings: list[Finding] = []
    for raw in run_detectors(text):
        findings.append(
            Finding(
                rule_id=raw.rule_id,
                severity=raw.severity,
                message=raw.message,
                rule_file=rule_file,
                line=raw.line,
                column=raw.column,
                snippet=raw.snippet,
            )
        )
    return findings


def scan(start: Path) -> ScanResult:
    """Scan dependency trees under ``start`` for poisoned rule-files."""
    start = Path(start)
    rule_files = discover(start)
    findings: list[Finding] = []
    for rf in rule_files:
        findings.extend(scan_rule_file(rf))
    return ScanResult(
        findings=findings,
        scanned_files=rule_files,
        roots=[start.resolve()],
    )
