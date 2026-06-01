"""Emit findings as SARIF 2.1.0 for GitHub code scanning.

The SARIF is intentionally minimal but valid: a single run with a tool driver,
one ``rule`` per detector id, and one ``result`` per finding. Each result's
location points at the offending rule-file with a region (line/column), and the
shipping package is recorded in result ``properties`` so a reviewer can see
which dependency to act on directly inside GitHub's Security tab.
"""

from __future__ import annotations

import json
from pathlib import Path

from rulewall import __version__
from rulewall.models import ScanResult, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)

# Short human-readable rule names + help text for the SARIF rule catalog.
_RULE_NAMES = {
    "invisible-unicode": "Invisible/zero-width unicode in rule-file",
    "bidi-override": "Bidirectional override (Trojan Source) in rule-file",
    "unicode-tag-smuggling": "Unicode tag-character smuggling in rule-file",
    "prompt-injection": "Prompt-injection / jailbreak phrasing in rule-file",
    "remote-code-execution": "Pipe-to-shell / remote code execution in rule-file",
    "credential-exfiltration": "Credential exfiltration instruction in rule-file",
    "run-remote-instruction": "Instruction to run a remote/opaque command",
    "suspicious-base64": "Suspicious high-entropy base64 blob in rule-file",
}


def _severity_to_security_severity(sev: Severity) -> str:
    # GitHub uses a 0.0-10.0 numeric scale for ordering in the Security tab.
    return {"note": "3.0", "warning": "5.5", "error": "8.5"}[sev.value]


def _rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def build_sarif(result: ScanResult, base_dir: Path | None = None) -> dict:
    base = Path(base_dir) if base_dir else Path.cwd()

    used_rule_ids: list[str] = []
    seen: set[str] = set()
    for f in result.findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            used_rule_ids.append(f.rule_id)

    rules = [
        {
            "id": rid,
            "name": "".join(part.capitalize() for part in rid.split("-")),
            "shortDescription": {"text": _RULE_NAMES.get(rid, rid)},
            "fullDescription": {
                "text": _RULE_NAMES.get(rid, rid)
                + " — detected in a rule-file shipped by an installed dependency."
            },
            "defaultConfiguration": {"level": _default_level(result, rid).value},
            "helpUri": "https://github.com/AmanZainal/rulewall#detectors",
        }
        for rid in used_rule_ids
    ]

    results = []
    for f in result.findings:
        pkg = f.package
        message = (
            f"{pkg.label()} ships a poisoned {f.rule_file.kind}: {f.message}"
        )
        results.append(
            {
                "ruleId": f.rule_id,
                "level": f.severity.value,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _rel(f.rule_file.path, base)
                            },
                            "region": {
                                "startLine": max(f.line, 1),
                                "startColumn": max(f.column, 1),
                                "snippet": {"text": f.snippet} if f.snippet else {},
                            },
                        }
                    }
                ],
                "properties": {
                    "security-severity": _severity_to_security_severity(f.severity),
                    "package": pkg.coordinate(),
                    "packageEcosystem": pkg.ecosystem,
                    "ruleFileKind": f.rule_file.kind,
                },
            }
        )

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "rulewall",
                        "informationUri": "https://github.com/AmanZainal/rulewall",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _default_level(result: ScanResult, rule_id: str) -> Severity:
    # Default level = the highest severity observed for that rule.
    sevs = [f.severity for f in result.findings if f.rule_id == rule_id]
    return max(sevs, key=lambda s: s.rank) if sevs else Severity.WARNING


def dumps_sarif(result: ScanResult, base_dir: Path | None = None) -> str:
    return json.dumps(build_sarif(result, base_dir), indent=2)
