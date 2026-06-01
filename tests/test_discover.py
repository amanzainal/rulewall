"""Tests for dependency-tree discovery of rule-files."""

from __future__ import annotations

from pathlib import Path

from rulewall.discover import RULE_FILE_BASENAMES, discover, find_dep_tree_roots


def _touch(path: Path, content: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_finds_node_modules_root(tmp_path: Path):
    _touch(tmp_path / "node_modules" / "foo" / "CLAUDE.md")
    roots = find_dep_tree_roots(tmp_path)
    assert (tmp_path / "node_modules").resolve() in [r.resolve() for r in roots]


def test_discovers_rule_files_in_node_modules(tmp_path: Path):
    _touch(tmp_path / "node_modules" / "foo" / "CLAUDE.md")
    _touch(tmp_path / "node_modules" / "bar" / ".cursorrules")
    found = discover(tmp_path)
    kinds = sorted(rf.kind for rf in found)
    assert kinds == [".cursorrules", "CLAUDE.md"]


def test_case_insensitive_basename(tmp_path: Path):
    # a malicious package can't hide behind lowercase claude.md
    _touch(tmp_path / "node_modules" / "foo" / "claude.md")
    found = discover(tmp_path)
    assert len(found) == 1
    assert found[0].kind == "CLAUDE.md"


def test_copilot_instructions_only_in_github_dir(tmp_path: Path):
    # inside .github -> counts
    _touch(tmp_path / "node_modules" / "a" / ".github" / "copilot-instructions.md")
    # outside .github -> ignored
    _touch(tmp_path / "node_modules" / "b" / "copilot-instructions.md")
    found = discover(tmp_path)
    assert len(found) == 1
    assert found[0].kind == ".github/copilot-instructions.md"


def test_does_not_scan_repo_own_config(tmp_path: Path):
    # a CLAUDE.md at the project root (NOT inside a dep tree) is ignored —
    # this is the whole point: rulewall scans deps, not your repo's own config.
    _touch(tmp_path / "CLAUDE.md")
    _touch(tmp_path / ".cursorrules")
    found = discover(tmp_path)
    assert found == []


def test_points_directly_at_node_modules(tmp_path: Path):
    nm = tmp_path / "node_modules"
    _touch(nm / "foo" / "AGENTS.md")
    found = discover(nm)
    assert len(found) == 1
    assert found[0].kind == "AGENTS.md"


def test_all_known_rule_kinds_discoverable(tmp_path: Path):
    # plant one of each recognized basename inside a dep tree
    nm = tmp_path / "node_modules" / "pkg"
    _touch(nm / "CLAUDE.md")
    _touch(nm / "AGENTS.md")
    _touch(nm / "GEMINI.md")
    _touch(nm / ".cursorrules")
    _touch(nm / ".windsurfrules")
    _touch(nm / ".mcp.json")
    _touch(nm / ".github" / "copilot-instructions.md")
    found = discover(tmp_path)
    kinds = {rf.kind for rf in found}
    assert kinds == set(RULE_FILE_BASENAMES.values())
