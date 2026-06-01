"""Discover AI-agent rule-files anywhere inside an installed dependency tree.

The differentiator of rulewall is that it does NOT scan your repo's own config.
It walks the *installed dependency tree* — node_modules, Python site-packages,
and vendored dependency directories — and finds rule-files that a dependency
shipped.

Recognized rule-file kinds are matched by basename (case-insensitively for the
markdown ones) so a malicious package can't hide behind ``claude.md`` vs
``CLAUDE.md``.
"""

from __future__ import annotations

import os
from pathlib import Path
from collections.abc import Iterator

from rulewall.attribution import attribute
from rulewall.models import RuleFile

# Exact-basename rule-files (matched case-insensitively).
RULE_FILE_BASENAMES: dict[str, str] = {
    "claude.md": "CLAUDE.md",
    "agents.md": "AGENTS.md",
    "gemini.md": "GEMINI.md",
    ".cursorrules": ".cursorrules",
    ".windsurfrules": ".windsurfrules",
    ".mcp.json": ".mcp.json",
    "copilot-instructions.md": ".github/copilot-instructions.md",
}

# Directories that mark the root of a dependency tree we care about.
DEP_TREE_DIR_NAMES = {"node_modules", "site-packages", "vendor"}

# Directories we never descend into (noise / not dependency payloads).
_SKIP_DIR_NAMES = {".git", ".hg", ".svn", "__pycache__", ".cache"}


def _basename_kind(path: Path) -> str | None:
    """Return the canonical rule-file kind for a path, or None."""
    name = path.name.lower()
    if name in RULE_FILE_BASENAMES:
        # copilot-instructions.md only counts inside a `.github` directory.
        if name == "copilot-instructions.md":
            if path.parent.name.lower() != ".github":
                return None
        return RULE_FILE_BASENAMES[name]
    return None


def is_dep_tree_root(path: Path) -> bool:
    """True if ``path`` looks like the root of a dependency tree."""
    return path.is_dir() and path.name in DEP_TREE_DIR_NAMES


def find_dep_tree_roots(start: Path) -> list[Path]:
    """Find dependency-tree roots under ``start``.

    If ``start`` itself is a dep-tree root (e.g. you point rulewall directly at
    a ``node_modules`` dir) it is returned as-is. Otherwise we look for
    ``node_modules`` / ``site-packages`` / ``vendor`` directories within.
    """
    start = start.resolve()
    if is_dep_tree_root(start):
        return [start]

    roots: list[Path] = []
    for dirpath, dirnames, _ in os.walk(start):
        # prune obvious noise to keep the walk fast
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES]
        for d in list(dirnames):
            if d in DEP_TREE_DIR_NAMES:
                roots.append(Path(dirpath) / d)
        # don't descend *into* a found dep-tree root here; the rule-file walk
        # below handles the inside. Pruning avoids quadratic re-walking.
        dirnames[:] = [d for d in dirnames if d not in DEP_TREE_DIR_NAMES]
    return roots


def iter_rule_files(root: Path) -> Iterator[RuleFile]:
    """Yield every rule-file found under a dependency-tree ``root``.

    Each yielded :class:`RuleFile` is already attributed to the package that
    shipped it.
    """
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES]
        here = Path(dirpath)
        for fn in filenames:
            candidate = here / fn
            kind = _basename_kind(candidate)
            if kind is None:
                continue
            package = attribute(candidate, root)
            yield RuleFile(path=candidate, kind=kind, package=package)


def discover(start: Path) -> list[RuleFile]:
    """Discover all attributed rule-files in dependency trees under ``start``."""
    rule_files: list[RuleFile] = []
    seen: set[Path] = set()
    for root in find_dep_tree_roots(start):
        for rf in iter_rule_files(root):
            resolved = rf.path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            rule_files.append(rf)
    return rule_files
