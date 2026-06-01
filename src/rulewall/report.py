"""Human-readable terminal report, grouped by the dependency that shipped the file."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from rulewall.models import ScanResult, Severity

_SEV_LABEL = {
    Severity.ERROR: "ERROR",
    Severity.WARNING: "WARN",
    Severity.NOTE: "NOTE",
}

_COLORS = {
    Severity.ERROR: "\033[31m",   # red
    Severity.WARNING: "\033[33m",  # yellow
    Severity.NOTE: "\033[36m",     # cyan
}
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _rel(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path)


def render(result: ScanResult, base_dir: Path | None = None, stream=None) -> str:
    base = Path(base_dir) if base_dir else Path.cwd()
    stream = stream or sys.stdout
    color = _use_color(stream)

    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines: list[str] = []
    n_files = len(result.scanned_files)
    n_pkgs = len({rf.package.label() for rf in result.scanned_files})

    lines.append(
        c("rulewall", _BOLD)
        + f" scanned {n_files} rule-file(s) shipped by {n_pkgs} dependenc"
        + ("y" if n_pkgs == 1 else "ies")
        + "."
    )

    if result.clean:
        lines.append(c("No poisoned AI-agent rule-files found.", "\033[32m"))
        return "\n".join(lines) + "\n"

    grouped = result.findings_by_package()
    n_findings = len(result.findings)
    n_bad_pkgs = len(grouped)
    lines.append(
        c(
            f"Found {n_findings} issue(s) across {n_bad_pkgs} dependenc"
            + ("y" if n_bad_pkgs == 1 else "ies")
            + ":",
            _BOLD,
        )
    )
    lines.append("")

    for pkg_label in sorted(grouped):
        findings = grouped[pkg_label]
        rf = findings[0].rule_file
        lines.append(c(f"  {pkg_label}", _BOLD))
        lines.append(
            c(f"    ships {rf.kind}: {_rel(rf.path, base)}", _DIM)
        )
        for f in sorted(findings, key=lambda x: (-x.severity.rank, x.line)):
            sev = c(_SEV_LABEL[f.severity], _COLORS[f.severity])
            loc = c(f"L{f.line}:{f.column}", _DIM)
            lines.append(f"      [{sev}] {loc} {f.rule_id}: {f.message}")
            if f.snippet:
                lines.append(c(f"             > {f.snippet}", _DIM))
        lines.append("")

    worst = result.max_severity()
    if worst is not None:
        lines.append(
            c(
                f"Highest severity: {_SEV_LABEL[worst]}. "
                "Treat these dependencies as compromised: pin, patch, or remove them.",
                _COLORS[worst],
            )
        )
    return "\n".join(lines) + "\n"
