"""Tests for mapping a rule-file path back to the package that shipped it."""

from __future__ import annotations

import json
from pathlib import Path

from rulewall.attribution import attribute


def test_npm_simple_package(tmp_path: Path):
    pkg = tmp_path / "node_modules" / "left-pad-clone"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "left-pad-clone", "version": "1.3.0"}))
    rf = pkg / "CLAUDE.md"
    rf.write_text("# rules")
    p = attribute(rf, tmp_path / "node_modules")
    assert p.ecosystem == "npm"
    assert p.name == "left-pad-clone"
    assert p.version == "1.3.0"
    assert p.coordinate() == "left-pad-clone@1.3.0"


def test_npm_scoped_package(tmp_path: Path):
    pkg = tmp_path / "node_modules" / "@acme" / "ui"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "@acme/ui", "version": "2.0.0"}))
    rf = pkg / ".cursorrules"
    rf.write_text("rules")
    p = attribute(rf, tmp_path / "node_modules")
    assert p.name == "@acme/ui"
    assert p.version == "2.0.0"


def test_npm_nested_attributes_to_nearest_package(tmp_path: Path):
    inner = tmp_path / "node_modules" / "outer" / "node_modules" / "inner"
    inner.mkdir(parents=True)
    (inner / "package.json").write_text(json.dumps({"name": "inner", "version": "9.9.9"}))
    rf = inner / "AGENTS.md"
    rf.write_text("x")
    p = attribute(rf, tmp_path / "node_modules")
    assert p.name == "inner"
    assert p.version == "9.9.9"


def test_npm_missing_package_json_still_attributes_name(tmp_path: Path):
    pkg = tmp_path / "node_modules" / "noversion"
    pkg.mkdir(parents=True)
    rf = pkg / "CLAUDE.md"
    rf.write_text("x")
    p = attribute(rf, tmp_path / "node_modules")
    assert p.name == "noversion"
    assert p.version is None


def test_pypi_with_dist_info(tmp_path: Path):
    sp = tmp_path / "site-packages"
    imp = sp / "coolparse"
    imp.mkdir(parents=True)
    dist = sp / "cool_parse-0.1.2.dist-info"
    dist.mkdir(parents=True)
    (dist / "top_level.txt").write_text("coolparse\n")
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: cool-parse\nVersion: 0.1.2\n")
    rf = imp / "CLAUDE.md"
    rf.write_text("x")
    p = attribute(rf, sp)
    assert p.ecosystem == "pypi"
    # canonical (hyphenated) name from METADATA wins over the dir name
    assert p.name == "cool-parse"
    assert p.version == "0.1.2"


def test_pypi_without_dist_info_falls_back_to_import_name(tmp_path: Path):
    sp = tmp_path / "site-packages"
    imp = sp / "loneliness"
    imp.mkdir(parents=True)
    rf = imp / ".cursorrules"
    rf.write_text("x")
    p = attribute(rf, sp)
    assert p.ecosystem == "pypi"
    assert p.name == "loneliness"


def test_vendor_attribution(tmp_path: Path):
    v = tmp_path / "vendor" / "grabby"
    v.mkdir(parents=True)
    rf = v / "CLAUDE.md"
    rf.write_text("x")
    p = attribute(rf, tmp_path / "vendor")
    assert p.ecosystem == "vendor"
    assert p.name == "grabby"


def test_unknown_layout_never_raises(tmp_path: Path):
    rf = tmp_path / "weird" / "place" / "CLAUDE.md"
    rf.parent.mkdir(parents=True)
    rf.write_text("x")
    p = attribute(rf, tmp_path)
    assert p.name == "place"  # parent dir name
    assert p.label()  # does not raise
