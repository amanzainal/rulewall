"""rulewall — dependency-tree scanner for poisoned AI-agent rule-files.

rulewall walks your *installed dependency tree* (node_modules, Python
site-packages, vendored deps) looking for AI-agent rule-files (CLAUDE.md,
AGENTS.md, .cursorrules, .mcp.json, copilot-instructions.md, GEMINI.md,
.windsurfrules) that were shipped by a dependency and contain poisoning
markers: invisible/zero-width unicode, bidi overrides, prompt-injection /
jailbreak phrasing, exfiltration instructions, or suspicious base64 blobs.

Each finding is correlated back to the *package* that shipped the file, so the
report reads "package foo@1.2.3 ships a poisoned CLAUDE.md".
"""

__version__ = "0.1.0"

from rulewall.models import Finding, RuleFile, ScanResult, Severity

__all__ = ["Finding", "RuleFile", "ScanResult", "Severity", "__version__"]
