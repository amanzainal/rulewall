"""Tests for SARIF 2.1.0 output."""

from __future__ import annotations

import json
from pathlib import Path

from rulewall.mock import build_mock_tree
from rulewall.sarif import build_sarif, dumps_sarif
from rulewall.scanner import scan


def _scan(tmp_path: Path):
    root = build_mock_tree(tmp_path / "tree")
    return root, scan(root)


def test_sarif_basic_shape(tmp_path: Path):
    root, result = _scan(tmp_path)
    doc = build_sarif(result, root)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "rulewall"
    assert driver["rules"]
    assert doc["runs"][0]["results"]


def test_sarif_serializes_to_valid_json(tmp_path: Path):
    root, result = _scan(tmp_path)
    text = dumps_sarif(result, root)
    doc = json.loads(text)  # must not raise
    assert doc["runs"][0]["results"]


def test_sarif_result_count_matches_findings(tmp_path: Path):
    root, result = _scan(tmp_path)
    doc = build_sarif(result, root)
    assert len(doc["runs"][0]["results"]) == len(result.findings)


def test_sarif_results_carry_package_attribution(tmp_path: Path):
    root, result = _scan(tmp_path)
    doc = build_sarif(result, root)
    for r in doc["runs"][0]["results"]:
        props = r["properties"]
        assert props["package"]
        assert props["packageEcosystem"] in {"npm", "pypi", "vendor"}
        # the human message names the shipping package
        assert "ships a poisoned" in r["message"]["text"]


def test_sarif_levels_are_valid(tmp_path: Path):
    root, result = _scan(tmp_path)
    doc = build_sarif(result, root)
    for r in doc["runs"][0]["results"]:
        assert r["level"] in {"note", "warning", "error"}


def test_sarif_rules_have_unique_ids(tmp_path: Path):
    root, result = _scan(tmp_path)
    doc = build_sarif(result, root)
    ids = [rule["id"] for rule in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))


def test_sarif_clean_scan_has_no_results(tmp_path: Path):
    nm = tmp_path / "node_modules" / "ok"
    nm.mkdir(parents=True)
    (nm / "CLAUDE.md").write_text("Run pytest. Read config from env vars.")
    result = scan(tmp_path)
    doc = build_sarif(result, tmp_path)
    assert doc["runs"][0]["results"] == []
