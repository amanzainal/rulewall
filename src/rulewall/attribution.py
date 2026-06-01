"""Correlate a rule-file path back to the dependency that shipped it.

This is the half of rulewall that makes a finding actionable: instead of
"there is a poisoned CLAUDE.md somewhere", you get "package foo@1.2.3 ships a
poisoned CLAUDE.md", so you know exactly which dependency to pin, patch, or
remove.

Attribution strategy by ecosystem:

* **npm** (``node_modules`` layout): the package directory is the first path
  segment after a ``node_modules`` component, honoring ``@scope/name`` scoped
  packages and nested ``node_modules``. Version is read from that package's
  ``package.json``.
* **PyPI** (``site-packages`` layout): find the top-level import directory the
  file lives in, then map it to a distribution via the nearest ``*.dist-info``
  / ``*.egg-info`` metadata (name + version from ``METADATA``/``PKG-INFO`` or
  the directory name).
* **vendor**: best-effort — the first directory segment under ``vendor`` is the
  vendored package name; version is usually unknown.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from rulewall.models import Package

_DISTINFO_RE = re.compile(r"^(?P<name>.+?)-(?P<version>[^-]+)\.(dist-info|egg-info)$")


def _read_package_json_version(pkg_dir: Path) -> str | None:
    pj = pkg_dir / "package.json"
    if not pj.is_file():
        return None
    try:
        data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None
    version = data.get("version")
    return str(version) if version is not None else None


def _attribute_npm(path: Path, parts: list[str]) -> Package | None:
    """Attribute a file living under a ``node_modules`` directory."""
    # Use the LAST node_modules in the path so nested deps attribute to the
    # nearest enclosing package (the actual shipper), not a top-level parent.
    nm_indexes = [i for i, p in enumerate(parts) if p == "node_modules"]
    if not nm_indexes:
        return None
    nm_idx = nm_indexes[-1]
    after = parts[nm_idx + 1 :]
    if not after:
        return None

    if after[0].startswith("@") and len(after) >= 2:
        name = f"{after[0]}/{after[1]}"
        depth = 2
    else:
        name = after[0]
        depth = 1

    pkg_dir = Path(*parts[: nm_idx + 1 + depth])
    version = _read_package_json_version(pkg_dir)
    return Package(ecosystem="npm", name=name, version=version)


def _read_distinfo_metadata(meta_dir: Path) -> tuple[str | None, str | None]:
    """Return (name, version) from a dist-info/egg-info directory."""
    name: str | None = None
    version: str | None = None
    m = _DISTINFO_RE.match(meta_dir.name)
    if m:
        name = m.group("name")
        version = m.group("version")

    for meta_name in ("METADATA", "PKG-INFO"):
        meta_file = meta_dir / meta_name
        if not meta_file.is_file():
            continue
        try:
            text = meta_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if line.startswith("Name:") and not name:
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                version = line.split(":", 1)[1].strip()
        break
    return name, version


def _attribute_pypi(path: Path, root: Path) -> Package | None:
    """Attribute a file living under a ``site-packages`` directory."""
    parts = path.parts
    sp_indexes = [i for i, p in enumerate(parts) if p == "site-packages"]
    if not sp_indexes:
        return None
    sp_idx = sp_indexes[-1]
    after = parts[sp_idx + 1 :]
    if not after:
        return None

    top_level = after[0]  # e.g. the import package directory or a metadata dir

    # If the file itself is inside a *.dist-info / *.egg-info dir, use that.
    if top_level.endswith((".dist-info", ".egg-info")):
        name, version = _read_distinfo_metadata(Path(*parts[: sp_idx + 2]))
        if name:
            return Package(ecosystem="pypi", name=name, version=version)

    site_packages = Path(*parts[: sp_idx + 1])
    import_name = top_level.removesuffix(".py")

    # Look for a matching *.dist-info / *.egg-info to recover the dist name.
    name, version = _match_distinfo(site_packages, import_name)
    if name:
        return Package(ecosystem="pypi", name=name, version=version)

    # Fallback: use the import directory name as the package name.
    return Package(ecosystem="pypi", name=import_name, version=None)


def _match_distinfo(site_packages: Path, import_name: str) -> tuple[str | None, str | None]:
    """Find the dist-info whose RECORD/top_level matches ``import_name``."""
    if not site_packages.is_dir():
        return None, None
    candidates = sorted(
        p
        for p in site_packages.iterdir()
        if p.is_dir() and p.name.endswith((".dist-info", ".egg-info"))
    )
    norm = import_name.replace("-", "_").lower()
    for meta_dir in candidates:
        # top_level.txt lists the importable names this dist installs.
        top_level_file = meta_dir / "top_level.txt"
        if top_level_file.is_file():
            try:
                tops = top_level_file.read_text(
                    encoding="utf-8", errors="replace"
                ).split()
            except OSError:
                tops = []
            if any(t.replace("-", "_").lower() == norm for t in tops):
                return _read_distinfo_metadata(meta_dir)
        # Fall back to matching the dist name prefix against the import name.
        m = _DISTINFO_RE.match(meta_dir.name)
        if m and m.group("name").replace("-", "_").lower() == norm:
            return _read_distinfo_metadata(meta_dir)
    return None, None


def _attribute_vendor(path: Path, parts: list[str]) -> Package | None:
    vendor_indexes = [i for i, p in enumerate(parts) if p == "vendor"]
    if not vendor_indexes:
        return None
    v_idx = vendor_indexes[-1]
    after = parts[v_idx + 1 :]
    if not after:
        return None
    # honor scoped-style vendored names too
    if after[0].startswith("@") and len(after) >= 2:
        name = f"{after[0]}/{after[1]}"
    else:
        name = after[0]
    return Package(ecosystem="vendor", name=name, version=None)


def attribute(path: Path, root: Path) -> Package:
    """Map a rule-file ``path`` to the :class:`Package` that shipped it.

    ``root`` is the dependency-tree root the file was found under. Always
    returns a Package; falls back to an ``unknown`` package rather than raising,
    so a weird layout never aborts a scan.
    """
    path = path.resolve()
    parts = list(path.parts)

    if "node_modules" in parts:
        pkg = _attribute_npm(path, parts)
        if pkg:
            return pkg
    if "site-packages" in parts:
        pkg = _attribute_pypi(path, root)
        if pkg:
            return pkg
    if "vendor" in parts:
        pkg = _attribute_vendor(path, parts)
        if pkg:
            return pkg

    # Unknown layout: name the package after the immediate parent directory.
    parent = path.parent.name or "unknown"
    return Package(ecosystem="vendor", name=parent, version=None)
