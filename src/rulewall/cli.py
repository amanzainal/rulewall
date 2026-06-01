"""Command-line entrypoint for rulewall.

Usage examples::

    rulewall                       # scan ./ for dependency trees
    rulewall ./node_modules        # scan a specific dep tree
    rulewall --sarif out.sarif     # also write SARIF for GitHub code scanning
    rulewall --demo                # scan a synthesized poisoned tree (no deps)
    rulewall --format json         # machine-readable findings on stdout

Exit codes:
    0   no findings at or above the fail threshold
    1   findings at or above the threshold (CI-friendly)
    2   usage / runtime error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from rulewall import __version__
from rulewall.mock import (
    build_mock_tree,
    expected_clean_packages,
    expected_poisoned_packages,
)
from rulewall.models import ScanResult, Severity
from rulewall.report import render
from rulewall.sarif import dumps_sarif
from rulewall.scanner import scan

_FAIL_LEVELS = {"note": Severity.NOTE, "warning": Severity.WARNING, "error": Severity.ERROR}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rulewall",
        description=(
            "Scan your installed dependency tree (node_modules / site-packages / "
            "vendored deps) for poisoned AI-agent rule-files (CLAUDE.md, "
            ".cursorrules, AGENTS.md, .mcp.json, copilot-instructions.md, ...) and "
            "attribute each finding to the dependency that shipped it."
        ),
    )
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory to scan for dependency trees (default: current directory).",
    )
    p.add_argument(
        "--sarif",
        metavar="FILE",
        help="Write SARIF 2.1.0 output to FILE (for GitHub code scanning).",
    )
    p.add_argument(
        "--format",
        choices=("human", "json", "sarif"),
        default="human",
        help="stdout format (default: human). 'sarif'/'json' print to stdout.",
    )
    p.add_argument(
        "--fail-on",
        choices=("note", "warning", "error"),
        default=os.environ.get("RULEWALL_FAIL_ON", "warning"),
        help="Minimum severity that causes a non-zero exit (default: warning).",
    )
    p.add_argument(
        "--demo",
        action="store_true",
        help="Scan a freshly synthesized poisoned dependency tree (no real deps "
        "or network needed). Great for trying rulewall out.",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"rulewall {__version__}",
    )
    return p


def _result_to_json(result: ScanResult, base: Path) -> str:
    payload = {
        "tool": "rulewall",
        "version": __version__,
        "summary": {
            "scanned_files": len(result.scanned_files),
            "findings": len(result.findings),
            "flagged_packages": sorted(result.findings_by_package().keys()),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "package": f.package.label(),
                "ecosystem": f.package.ecosystem,
                "rule_file": _rel(f.rule_file.path, base),
                "rule_file_kind": f.rule_file.kind,
                "line": f.line,
                "column": f.column,
                "snippet": f.snippet,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2)


def _rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path)


def _exceeds_threshold(result: ScanResult, fail_on: Severity) -> bool:
    return any(f.severity.rank >= fail_on.rank for f in result.findings)


def run(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    fail_on = _FAIL_LEVELS[args.fail_on]

    demo_dir: tempfile.TemporaryDirectory | None = None
    if args.demo:
        demo_dir = tempfile.TemporaryDirectory(prefix="rulewall-demo-")
        scan_root = build_mock_tree(Path(demo_dir.name))
        base = scan_root
        if args.format == "human":
            print(
                f"[demo] synthesized a poisoned dependency tree at {scan_root}\n"
                f"[demo] expected-poisoned packages: "
                f"{sorted(expected_poisoned_packages())}\n"
                f"[demo] expected-clean packages: "
                f"{sorted(expected_clean_packages())}\n",
                file=sys.stderr,
            )
    else:
        scan_root = Path(args.path)
        if not scan_root.exists():
            print(f"rulewall: path does not exist: {scan_root}", file=sys.stderr)
            return 2
        base = scan_root if scan_root.is_dir() else scan_root.parent

    try:
        result = scan(scan_root)

        if args.sarif:
            Path(args.sarif).write_text(
                dumps_sarif(result, base), encoding="utf-8"
            )

        if args.format == "human":
            sys.stdout.write(render(result, base))
        elif args.format == "json":
            print(_result_to_json(result, base))
        elif args.format == "sarif":
            print(dumps_sarif(result, base))
    finally:
        if demo_dir is not None:
            demo_dir.cleanup()

    return 1 if _exceeds_threshold(result, fail_on) else 0


def main() -> None:
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
