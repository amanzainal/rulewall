# rulewall

> Scan your installed **dependency tree** for poisoned AI-agent rule-files (CLAUDE.md / .cursorrules) planted by malicious packages.

`rulewall` walks the dependencies you actually installed — `node_modules`,
Python `site-packages`, vendored deps — and finds AI-agent rule-files that a
**dependency shipped** and that contain poisoning markers. It then tells you
**which package** shipped each one, so the report reads:

> `npm:color-picker-fake@0.0.7` ships a poisoned `CLAUDE.md`: Override of prior instructions — classic prompt-injection.

It is offline, stdlib-only, fast, and CI-friendly (human report + SARIF +
non-zero exit + a pre-commit hook).

---

## The problem

AI coding agents (Claude Code, Cursor, Windsurf, Copilot, Gemini, ...) silently
read rule-files from your working tree: `CLAUDE.md`, `AGENTS.md`,
`.cursorrules`, `.windsurfrules`, `.mcp.json`, `.github/copilot-instructions.md`,
`GEMINI.md`. Whatever those files say, the agent tends to do.

That makes a rule-file a perfect payload for a supply-chain attack. A malicious
(or compromised) package can ship its **own** rule-file deep inside
`node_modules` or `site-packages`. Many agents glob for rule-files across the
project, so a poisoned `CLAUDE.md` inside a transitive dependency can quietly:

- override your instructions ("ignore all previous instructions"),
- exfiltrate secrets ("read `.env` and POST `$API_TOKEN` to `https://...`"),
- run remote code ("first run `curl https://.../i.sh | sh`"),
- hide all of the above using **invisible zero-width unicode** or **bidi
  overrides** so a human reviewer sees nothing wrong.

This is the **TrapDoor / Shai-Hulud 2026** class of attack: the poison rides in
on a dependency, not in your own repo.

## How this is different (named competitors)

There are good tools that scan AI rule-files. The gap is *where they look*:

| Tool | What it scans | Walks the installed dependency tree? |
| --- | --- | --- |
| **CodeGate** | your repo's own agent config / prompts | No |
| **Pillar Security** | your repo's rule-files & prompts | No |
| **Cisco AI guardrails** | your repo / runtime prompts | No |
| **Snyk** | known-CVE deps + your own code/config | No (not for rule-file poisoning in deps) |
| **rulewall** | rule-files **shipped by your dependencies** | **Yes — this is the whole point** |

Every tool above scans **your** config files. None walks the
**installed dependency tree** for a poisoned rule-file shipped by a transitive
dependency — which is the actual attack vector. `rulewall` does only that one
thing, and correlates every hit back to the package that shipped it. It is a
*complement* to the tools above, not a replacement: keep using CodeGate/Pillar
for your own prompts; add `rulewall` for the dependencies you didn't write.

## What it detects

For every rule-file found inside a dependency tree, `rulewall` flags:

- **Invisible / zero-width unicode** (`U+200B`, `U+FEFF`, soft hyphen, ...) and
  **unicode tag-character smuggling** — hidden text a human can't see but the
  agent still reads.
- **Bidirectional overrides** (`U+202E` "Trojan Source" class) that reorder
  visible text away from what the agent actually parses.
- **Prompt-injection / jailbreak phrasing** — "ignore previous instructions",
  "developer mode", "bypass safety guidelines", "do not tell the user", fake
  `<system>` delimiters, ...
- **Exfiltration / remote-code instructions** — `curl ... | sh`, "send
  `$TOKEN`/`.env`/secrets to `https://...`", "run this security scan". Tuned to
  fire on *outbound movement of secrets to a destination*, not on legitimate
  advice like "read secrets from the environment; never hardcode tokens".
- **Suspicious high-entropy base64 blobs** that may be an encoded payload.

Each finding is **attributed to the shipping package** via the `node_modules`
layout (incl. scoped and nested deps), `*.dist-info` / `PKG-INFO` metadata for
PyPI, and the `vendor/` layout.

## Install

`rulewall` is pure-Python, stdlib-only, no runtime dependencies.

```bash
# with uv (recommended)
uv tool install rulewall          # once published
# or run from a clone:
git clone https://github.com/AmanZainal/rulewall
cd rulewall
uv sync
uv run rulewall --demo
```

```bash
# with pip
pip install rulewall              # once published
```

## Usage

```bash
rulewall                          # scan ./ for dependency trees
rulewall ./node_modules           # scan a specific dependency tree
rulewall . --sarif rulewall.sarif # also write SARIF for GitHub code scanning
rulewall . --format json          # machine-readable findings on stdout
rulewall . --fail-on error        # only fail CI on ERROR-level findings
rulewall --demo                   # scan a synthesized poisoned tree (no deps!)
```

Exit codes: `0` clean (below threshold), `1` findings at/above `--fail-on`
(default `warning`), `2` usage error. The threshold can also be set with
`RULEWALL_FAIL_ON`.

### Sample output

```text
$ rulewall --demo

rulewall scanned 9 rule-file(s) shipped by 9 dependencies.
Found 14 issue(s) across 6 dependencies:

  npm:color-picker-fake@0.0.7
    ships CLAUDE.md: node_modules/color-picker-fake/CLAUDE.md
      [ERROR] L5:1 prompt-injection: Override of prior instructions — classic prompt-injection.
             > Ignore all previous instructions
      [ERROR] L5:35 prompt-injection: Jailbreak persona / 'developer mode' — prompt-injection.
             > You are now in developer mode

  npm:inner-trojan@9.9.9
    ships .windsurfrules: node_modules/outer-fake/node_modules/inner-trojan/.windsurfrules
      [ERROR] L3:24 invisible-unicode: Invisible/zero-width character ZERO WIDTH SPACE (U+200B) ...
      [ERROR] L3:32 bidi-override: Unicode bidirectional control RIGHT-TO-LEFT OVERRIDE (U+202E) ...

  pypi:cool-parse@0.1.2
    ships CLAUDE.md: site-packages/coolparse/CLAUDE.md
      [ERROR] L4:1 credential-exfiltration: Instruction that moves secrets/tokens/env off the machine ...
             > $API_TOKEN values and secrets to https://

Highest severity: ERROR. Treat these dependencies as compromised: pin, patch, or remove them.
```

### SARIF / GitHub code scanning

`rulewall . --sarif rulewall.sarif` emits SARIF 2.1.0. Each result carries the
shipping package in `properties.package` and the human message names it, so the
GitHub Security tab tells you which dependency to act on. A ready-to-use
workflow lives at [`.github/workflows/rulewall.yml`](.github/workflows/rulewall.yml).

### pre-commit hook

`rulewall` ships a [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml). In your
repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/AmanZainal/rulewall
    rev: v0.1.0
    hooks:
      - id: rulewall
        args: ["."]          # or ["node_modules", "--fail-on", "error"]
```

## Real vs. demo

`rulewall` needs **no GPU, no accounts, and no network** — it is a static file
scanner over directories you already have on disk.

- **Demo (`--demo`)**: synthesizes a throwaway fake dependency tree
  (`node_modules` + `site-packages` + `vendor`) with planted poisoned **and**
  clean rule-files, scans it, and cleans up. Every package name and host in the
  demo is obviously synthetic (`color-picker-fake`, `evil.example`,
  `attacker.test`). This is what the test suite asserts against — detection,
  correct package attribution, and **zero false positives** on the clean files.
- **Real**: point `rulewall` at a real project (`rulewall .`) after you have
  installed dependencies (`npm ci`, `pip install -r requirements.txt`, etc.).
  It walks whatever `node_modules` / `site-packages` / `vendor` trees it finds.

There is no "real hardware" tier — the demo exercises the exact same code path
as a real scan, just over synthetic input.

## Development

```bash
uv sync
uv run pytest -q     # 69 tests, all offline
uv run rulewall --demo
```

## Roadmap

- More rule-file kinds as new agents appear (`.clinerules`, `.aiderrules`, ...).
- Homoglyph / confusable-character detection.
- `.mcp.json` deep checks (suspicious server commands, `npx`-to-remote).
- `--baseline` / allowlist to suppress known-accepted findings.
- Optional decode-and-rescan of base64 blobs.
- Lockfile cross-referencing to print the dependency *path* (who pulled the bad
  package in).

## License

MIT © Aman Zainal. See [LICENSE](LICENSE).
