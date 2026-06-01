"""Heuristic detectors for poisoned AI-agent rule-files.

Each detector takes the text of a rule-file and yields ``RawFinding`` tuples
``(rule_id, severity, message, line, column, snippet)``. The scanner wraps
these into :class:`~rulewall.models.Finding` objects with package attribution.

Design goals:

* **Stdlib only** — ``re`` + ``unicodedata``.
* **Low false positives** — a legitimate CLAUDE.md (project conventions, build
  commands, "run pytest") must produce ZERO findings. The exfiltration and
  injection detectors therefore look for the *combination* of an imperative to
  run/send/exfiltrate AND a sensitive target (secrets/tokens/env) or a
  pipe-to-shell pattern, not either alone.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import NamedTuple

from rulewall.models import Severity


class RawFinding(NamedTuple):
    rule_id: str
    severity: Severity
    message: str
    line: int
    column: int
    snippet: str


# --------------------------------------------------------------------------
# 1. Invisible / zero-width unicode and bidi overrides
# --------------------------------------------------------------------------

# Zero-width and other invisible formatting characters that can smuggle hidden
# instructions past a human reviewer while the model still reads them.
# Built from explicit codepoints so THIS source file contains no invisible
# characters (which would itself look suspicious / trip scanners).
_ZERO_WIDTH = {
    chr(0x200B): "ZERO WIDTH SPACE",
    chr(0x200C): "ZERO WIDTH NON-JOINER",
    chr(0x200D): "ZERO WIDTH JOINER",
    chr(0x2060): "WORD JOINER",
    chr(0xFEFF): "ZERO WIDTH NO-BREAK SPACE / BOM",
    chr(0x00AD): "SOFT HYPHEN",
    chr(0x034F): "COMBINING GRAPHEME JOINER",
    chr(0x180E): "MONGOLIAN VOWEL SEPARATOR",
    chr(0x200E): "LEFT-TO-RIGHT MARK",
    chr(0x200F): "RIGHT-TO-LEFT MARK",
}

# Unicode bidirectional control characters ("Trojan Source" class).
_BIDI = {
    chr(0x202A): "LEFT-TO-RIGHT EMBEDDING",
    chr(0x202B): "RIGHT-TO-LEFT EMBEDDING",
    chr(0x202C): "POP DIRECTIONAL FORMATTING",
    chr(0x202D): "LEFT-TO-RIGHT OVERRIDE",
    chr(0x202E): "RIGHT-TO-LEFT OVERRIDE",
    chr(0x2066): "LEFT-TO-RIGHT ISOLATE",
    chr(0x2067): "RIGHT-TO-LEFT ISOLATE",
    chr(0x2068): "FIRST STRONG ISOLATE",
    chr(0x2069): "POP DIRECTIONAL ISOLATE",
}

# Unicode "tag" characters (E0000-E007F) used for steganographic prompt hiding.
def _is_tag_char(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def _line_col(text: str, index: int) -> tuple[int, int]:
    prefix = text[:index]
    line = prefix.count("\n") + 1
    col = index - (prefix.rfind("\n")) if "\n" in prefix else index + 1
    return line, col


def detect_invisible_unicode(text: str) -> Iterator[RawFinding]:
    for idx, ch in enumerate(text):
        if ch in _ZERO_WIDTH:
            line, col = _line_col(text, idx)
            yield RawFinding(
                "invisible-unicode",
                Severity.ERROR,
                f"Invisible/zero-width character {_ZERO_WIDTH[ch]} (U+{ord(ch):04X}) "
                "can hide instructions from human review while the AI agent still reads them.",
                line,
                col,
                f"U+{ord(ch):04X}",
            )
        elif ch in _BIDI:
            line, col = _line_col(text, idx)
            yield RawFinding(
                "bidi-override",
                Severity.ERROR,
                f"Unicode bidirectional control {_BIDI[ch]} (U+{ord(ch):04X}) can reorder "
                "visible text so a reviewer sees something different from what the agent parses.",
                line,
                col,
                f"U+{ord(ch):04X}",
            )
        elif _is_tag_char(ch):
            line, col = _line_col(text, idx)
            yield RawFinding(
                "unicode-tag-smuggling",
                Severity.ERROR,
                f"Unicode tag character (U+{ord(ch):05X}) — these are invisible and are used to "
                "smuggle hidden instructions to an AI agent.",
                line,
                col,
                f"U+{ord(ch):05X}",
            )


# --------------------------------------------------------------------------
# 2. Prompt-injection / jailbreak phrasing
# --------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore (?:all |any )?(?:your |the )?(?:previous|prior|above|earlier|preceding) (?:instructions|prompts?|rules?|directions?)",
     "Override of prior instructions — classic prompt-injection."),
    (r"disregard (?:all |any )?(?:your |the )?(?:previous|prior|above|safety|system) (?:instructions|prompts?|rules?|guidelines?)",
     "Instruction to disregard prior/safety rules — prompt-injection."),
    (r"forget (?:all |everything )?(?:your |the )?(?:previous|prior|above) (?:instructions|context|rules?)",
     "Instruction to forget prior context — prompt-injection."),
    (r"you are (?:now )?(?:in )?(?:dan|developer mode|jailbroken|unrestricted|do anything now)",
     "Jailbreak persona / 'developer mode' — prompt-injection."),
    (r"do not (?:tell|inform|mention|warn|alert) (?:the )?(?:user|developer|human|anyone)",
     "Instruction to hide activity from the user — covert behavior."),
    (r"without (?:telling|informing|asking|notifying) (?:the )?(?:user|developer|human|anyone)",
     "Instruction to act without informing the user — covert behavior."),
    (r"(?:override|bypass|ignore|disable) (?:your |the )?(?:safety|security|content) (?:guidelines?|filters?|policies|policy|checks?)",
     "Instruction to bypass safety/security controls — jailbreak."),
    (r"this is (?:a |the )?(?:new |updated )?system prompt",
     "Text claiming to be a system prompt — injection attempt."),
    (r"<\s*system\s*>|\[system\]|###\s*system",
     "Fake system-role delimiter embedded in a rule-file — injection attempt."),
]

_INJECTION_COMPILED = [
    (re.compile(p, re.IGNORECASE), msg) for p, msg in _INJECTION_PATTERNS
]


def _scan_patterns(
    text: str, compiled: list[tuple[re.Pattern[str], str]], rule_id: str, severity: Severity
) -> Iterator[RawFinding]:
    for pattern, msg in compiled:
        for m in pattern.finditer(text):
            line, col = _line_col(text, m.start())
            snippet = m.group(0).strip()
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            yield RawFinding(rule_id, severity, msg, line, col, snippet)


def detect_prompt_injection(text: str) -> Iterator[RawFinding]:
    yield from _scan_patterns(text, _INJECTION_COMPILED, "prompt-injection", Severity.ERROR)


# --------------------------------------------------------------------------
# 3. Exfiltration / "run this" instructions
# --------------------------------------------------------------------------

# Pipe-to-shell: curl/wget ... | sh|bash. This alone is high-signal in a
# rule-file because a rule-file should never tell an agent to execute remote code.
_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget|fetch|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh\b",
    re.IGNORECASE,
)

# Sensitive targets that should never be moved off the machine.
_SENSITIVE = (
    r"(?:\$?(?:[A-Z_]*(?:TOKEN|SECRET|API[_-]?KEY|PASSWORD|PASSWD|CREDENTIAL)S?[A-Z_]*)"
    r"|\.env\b|environment variables?|process\.env|os\.environ"
    r"|~/\.ssh|id_rsa|\.aws/credentials|\.npmrc|\.netrc"
    r"|private keys?|access keys?|secret keys?|api keys?)"
)

# Verbs that genuinely MOVE data outward (exfiltration). Deliberately excludes
# inbound verbs like "read"/"load" so legitimate advice such as
# "read secrets from the environment; never hardcode tokens" does NOT match.
_EXFIL_VERB = (
    r"(?:exfiltrate|ex-?filtrate|leak|send|upload|post|transmit|forward|"
    r"email|e-mail|publish|share|copy)"
)

# A remote/attacker destination.
_REMOTE_DEST = (
    r"(?:https?://|ftps?://|webhook|remote (?:server|endpoint|host|machine)|"
    r"attacker|external (?:server|endpoint|url|host)|my server|our server|"
    r"this (?:url|endpoint|server)|paste(?:bin)?|discord\.com/api/webhooks)"
)

# Outbound-verb ... <sensitive>  (e.g. "send the $API_TOKEN", "exfiltrate .env").
_EXFIL_RE = re.compile(
    rf"{_EXFIL_VERB}\b[^\n]{{0,80}}?{_SENSITIVE}",
    re.IGNORECASE,
)
# <sensitive> ... to a remote destination  (e.g. ".env ... to https://...").
_EXFIL_DEST_RE = re.compile(
    rf"{_SENSITIVE}[^\n]{{0,80}}?(?:to|into|at|via)\b[^\n]{{0,40}}?{_REMOTE_DEST}",
    re.IGNORECASE,
)

# "run this (security) scan / script" pointing at a remote/opaque command.
_RUN_REMOTE_RE = re.compile(
    r"(?:run|execute|eval)\b[^\n]{0,60}?(?:https?://|`?(?:curl|wget|iwr)\b|base64\s+-d|the following (?:command|script))",
    re.IGNORECASE,
)


def detect_exfiltration(text: str) -> Iterator[RawFinding]:
    for m in _PIPE_TO_SHELL.finditer(text):
        line, col = _line_col(text, m.start())
        yield RawFinding(
            "remote-code-execution",
            Severity.ERROR,
            "Pipe-to-shell instruction (e.g. `curl ... | sh`) — a rule-file telling an agent "
            "to download and execute remote code is a hallmark of supply-chain poisoning.",
            line,
            col,
            _short(m.group(0)),
        )
    # Collect matches from both exfiltration patterns, then drop any match whose
    # span overlaps an earlier one so a single instruction is reported once.
    matches = sorted(
        (m for regex in (_EXFIL_RE, _EXFIL_DEST_RE) for m in regex.finditer(text)),
        key=lambda m: (m.start(), -(m.end() - m.start())),
    )
    covered_until = -1
    for m in matches:
        if m.start() < covered_until:
            continue
        covered_until = m.end()
        line, col = _line_col(text, m.start())
        yield RawFinding(
            "credential-exfiltration",
            Severity.ERROR,
            "Instruction that moves secrets/tokens/env off the machine — credential "
            "exfiltration. A rule-file should never tell an agent to read and send secrets.",
            line,
            col,
            _short(m.group(0)),
        )
    for m in _RUN_REMOTE_RE.finditer(text):
        line, col = _line_col(text, m.start())
        yield RawFinding(
            "run-remote-instruction",
            Severity.WARNING,
            "Instruction to run/execute a remote or opaque command — often phrased as a fake "
            "'security scan' to trick the agent into executing attacker code.",
            line,
            col,
            _short(m.group(0)),
        )


def _short(s: str) -> str:
    s = " ".join(s.split())
    return s if len(s) <= 120 else s[:117] + "..."


# --------------------------------------------------------------------------
# 4. Suspicious base64 blobs
# --------------------------------------------------------------------------

# A long contiguous base64-looking run. Real prose / code rarely has 80+
# unbroken base64 chars on one token; encoded payloads commonly do.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2

    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def detect_base64_blob(text: str) -> Iterator[RawFinding]:
    for m in _BASE64_RE.finditer(text):
        blob = m.group(0)
        # high entropy filters out things like long hex IDs or repeated chars.
        if _shannon_entropy(blob) < 3.5:
            continue
        line, col = _line_col(text, m.start())
        yield RawFinding(
            "suspicious-base64",
            Severity.WARNING,
            f"High-entropy base64-like blob ({len(blob)} chars) embedded in a rule-file — "
            "may be an encoded payload or hidden instruction. Decode and review.",
            line,
            col,
            blob[:40] + "...",
        )


# --------------------------------------------------------------------------
# Aggregate
# --------------------------------------------------------------------------

ALL_DETECTORS = (
    detect_invisible_unicode,
    detect_prompt_injection,
    detect_exfiltration,
    detect_base64_blob,
)


def run_detectors(text: str) -> list[RawFinding]:
    """Run every detector over ``text`` and return all raw findings."""
    findings: list[RawFinding] = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(text))
    return findings
