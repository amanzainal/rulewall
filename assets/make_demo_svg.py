#!/usr/bin/env python3
"""Render the real `rulewall --demo` output into a terminal-style SVG card.

This produces `assets/demo.svg` straight from the tool's own ANSI output, so the
image in the README is the literal program output, not a mock-up. Regenerate
with::

    python assets/make_demo_svg.py

It shells out to `rulewall --demo` (color forced on) and converts the ANSI
escape sequences into colored <tspan> elements on a dark terminal background.
"""

from __future__ import annotations

import html
import os
import re
import subprocess
import sys
from pathlib import Path

# ANSI SGR code -> SVG fill color (matching report.py's palette).
COLORS = {
    "31": "#ff6b6b",  # red    (ERROR)
    "33": "#ffd166",  # yellow (WARN)
    "36": "#4dd0e1",  # cyan   (NOTE)
    "32": "#6bd968",  # green  (clean)
}
FG = "#d6deeb"        # default foreground
DIM = "#7a8aa0"       # dim
BOLD = "#ffffff"      # bold default

ANSI_RE = re.compile(r"\033\[([0-9;]*)m")
CHAR_W = 7.6          # px per monospace char at 13px
LINE_H = 18.0
PAD_X = 18.0
PAD_TOP = 44.0
PAD_BOTTOM = 16.0


def capture() -> str:
    env = dict(os.environ)
    env.pop("NO_COLOR", None)
    env["FORCE_COLOR"] = "1"
    # Force a tty-like color decision by post-processing: report.py only colors
    # on an isatty stream, so we re-create the ANSI ourselves is overkill —
    # instead we run with a pseudo-tty.
    import pty

    out: list[bytes] = []

    def _read(fd: int) -> bytes:
        data = os.read(fd, 4096)
        out.append(data)
        return data

    pty.spawn(["rulewall", "--demo"], _read)  # type: ignore[arg-type]
    text = b"".join(out).decode("utf-8", "replace")
    # Drop the stderr [demo] banner lines; keep the report body. The report's
    # first line begins with a bold ANSI code, so strip ANSI before matching.
    body = []
    started = False
    for line in text.splitlines():
        plain = ANSI_RE.sub("", line).lstrip()
        if plain.startswith("rulewall scanned"):
            started = True
        if started:
            body.append(line.rstrip("\r"))
    return "\n".join(body)


def tokenize(line: str) -> list[tuple[str, str, bool]]:
    """Split a line into (text, color, bold) runs from its ANSI codes."""
    runs: list[tuple[str, str, bool]] = []
    color = FG
    bold = False
    pos = 0
    for m in ANSI_RE.finditer(line):
        if m.start() > pos:
            runs.append((line[pos : m.start()], color, bold))
        for code in (m.group(1) or "0").split(";"):
            if code in ("", "0"):
                color, bold = FG, False
            elif code == "1":
                bold = True
            elif code == "2":
                color = DIM
            elif code in COLORS:
                color = COLORS[code]
        pos = m.end()
    if pos < len(line):
        runs.append((line[pos:], color, bold))
    return runs


def main() -> int:
    raw = capture()
    lines = raw.split("\n")
    visible_lens = [len(ANSI_RE.sub("", ln)) for ln in lines]
    cols = max(visible_lens) if visible_lens else 80
    width = int(PAD_X * 2 + cols * CHAR_W)
    height = int(PAD_TOP + len(lines) * LINE_H + PAD_BOTTOM)

    svg: list[str] = []
    svg.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="ui-monospace,SFMono-Regular,'
        f'Menlo,Consolas,monospace" font-size="13">'
    )
    svg.append(f'<rect width="{width}" height="{height}" rx="10" fill="#0b1021"/>')
    svg.append(f'<rect width="{width}" height="30" rx="10" fill="#141a32"/>')
    svg.append('<rect y="20" width="100%" height="10" fill="#141a32"/>')
    for i, fill in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        svg.append(f'<circle cx="{18 + i * 18}" cy="15" r="6" fill="{fill}"/>')
    svg.append(
        f'<text x="{width / 2:.0f}" y="19" fill="#7a8aa0" text-anchor="middle" '
        f'font-size="11">rulewall --demo</text>'
    )

    y = PAD_TOP
    for ln in lines:
        x = PAD_X
        for text, color, bold in tokenize(ln):
            if not text:
                continue
            weight = ' font-weight="700"' if bold else ""
            svg.append(
                f'<text x="{x:.1f}" y="{y:.1f}" fill="{color}"{weight} '
                f'xml:space="preserve">{html.escape(text)}</text>'
            )
            x += len(text) * CHAR_W
        y += LINE_H
    svg.append("</svg>")

    out_path = Path(__file__).with_name("demo.svg")
    out_path.write_text("\n".join(svg) + "\n", encoding="utf-8")
    print(f"wrote {out_path} ({width}x{height})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
