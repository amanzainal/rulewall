"""End-to-end scan against the synthesized poisoned dependency tree.

This is the headline test: it builds a fake node_modules + site-packages +
vendor tree with planted poisoned AND clean rule-files, runs a full scan, and
asserts three things the spec demands:

1. every poisoned package is flagged,
2. each finding is attributed to the CORRECT shipping package,
3. ZERO false positives on the clean packages.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rulewall.mock import (
    build_mock_tree,
    catalog,
    expected_clean_packages,
    expected_poisoned_packages,
)
from rulewall.scanner import scan


@pytest.fixture()
def scanned(tmp_path: Path):
    root = build_mock_tree(tmp_path / "tree")
    return root, scan(root)


def flagged_packages(result) -> set[str]:
    return {f.package.coordinate() for f in result.findings}


def test_all_planted_rule_files_discovered(scanned):
    _root, result = scanned
    assert len(result.scanned_files) == len(catalog())


def test_every_poisoned_package_is_flagged(scanned):
    _root, result = scanned
    flagged = flagged_packages(result)
    for pkg in expected_poisoned_packages():
        assert pkg in flagged, f"missed poisoned package: {pkg}"


def test_zero_false_positives_on_clean_packages(scanned):
    _root, result = scanned
    flagged = flagged_packages(result)
    for clean in expected_clean_packages():
        assert clean not in flagged, f"false positive on clean package: {clean}"


def test_findings_attributed_to_correct_package(scanned):
    _root, result = scanned
    # map each poisoned planted file to its expected package/rule and confirm.
    by_path = {}
    for f in result.findings:
        by_path.setdefault(f.rule_file.path.name, []).append(f)

    for pf in catalog():
        if not pf.poisoned:
            continue
        basename = Path(pf.relpath).name
        matches = by_path.get(basename, [])
        # there may be several files with the same basename; filter by package
        relevant = [f for f in matches if f.package.coordinate() == pf.expect_package]
        assert relevant, f"no finding attributed to {pf.expect_package} for {pf.relpath}"
        for f in relevant:
            assert f.package.ecosystem == pf.expect_ecosystem
        if pf.expect_rules:
            got_rules = {f.rule_id for f in relevant}
            assert got_rules & set(pf.expect_rules), (
                f"{pf.expect_package}: expected one of {pf.expect_rules}, got {got_rules}"
            )


def test_result_is_not_clean(scanned):
    _root, result = scanned
    assert not result.clean
    assert result.max_severity() is not None


def test_grouping_by_package(scanned):
    _root, result = scanned
    grouped = result.findings_by_package()
    # every flagged package label should appear as a group key
    assert grouped
    for label in grouped:
        assert all(f.package.label() == label for f in grouped[label])


def test_clean_tree_produces_no_findings(tmp_path: Path):
    # a dep tree with only clean rule-files must yield zero findings.
    nm = tmp_path / "node_modules" / "clean-pkg"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text('{"name": "clean-pkg", "version": "1.0.0"}')
    (nm / "CLAUDE.md").write_text(
        "# CLAUDE.md\nRun `pytest`. Read config from environment variables. "
        "Never hardcode tokens; store the API key in a .env file.\n"
    )
    result = scan(tmp_path)
    assert result.clean
    assert len(result.scanned_files) == 1
