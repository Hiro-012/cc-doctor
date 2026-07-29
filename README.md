# cc-doctor

[![npm version](https://img.shields.io/npm/v/cc-doctor.svg)](https://www.npmjs.com/package/cc-doctor)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A diagnostic CLI for repositories that use [Claude Code](https://claude.com/claude-code). It scans your project's Claude Code configuration and flags common misconfigurations before they cause a security or usability problem.

## What it checks

- **`.claude/settings.json` / `.claude/settings.local.json`** — invalid JSON, unrestricted `Bash(*)` permission grants with no deny rules, other high-risk allowlisted command patterns, hooks that point at scripts which don't exist on disk, and `settings.local.json` being committed to git (by convention it's a personal, machine-local file and belongs in `.gitignore`).
- **`.mcp.json`** — invalid JSON, and `env` values or remote-server `headers` (e.g. an `Authorization: Bearer …` token on an `http`/`sse` server) that look like a hardcoded secret instead of an env-var reference.
- **`CLAUDE.md`** — missing or empty file, a file large enough to eat into every session's context budget, and accidental credentials pasted into it.
- **Git-tracked files** — a lightweight regex scan for common secret formats (AWS keys, GitHub tokens, Slack tokens, private key blocks, generic `api_key = "..."`-style assignments) so they don't slip into a commit.

This is a linter, not a security guarantee — it catches common, specific mistakes. It does not replace a real secret scanner or a security review for anything that actually matters.

## Accuracy

Measured against a 44-fixture corpus (`test/accuracy.test.js`, run via `npm test`) of known-vulnerable and known-clean repo configurations:

- **Recall: 96.4%** (27/28 known-bad fixtures detected)
- **False positive rate: 0.0%** (0/16 known-clean fixtures wrongly flagged)

Known limitation: the generic `password = "..."` / `token = "..."` catch-all only matches values made up of `[a-zA-Z0-9_-/+=]`. Real secrets containing other punctuation (e.g. `!`) won't be caught by that specific pattern — the format-specific patterns (AWS, GitHub, Slack, Anthropic/OpenAI-style, private key blocks) are unaffected.

## Usage

```bash
npx cc-doctor            # scan the current directory
npx cc-doctor path/to/repo
```

Exit code is non-zero if any `error`-level finding is present, so it's safe to drop into CI:

```yaml
- run: npx cc-doctor
```

## Install

```bash
npm install -g cc-doctor
```

## Development

```bash
npm test
```

## License

MIT

## Support

`cc-doctor` is built and maintained independently under the **HiroCheck** name —
free under the MIT license, run locally with `npx`, no account, no telemetry, and
no paid tier gating any check.

If it flagged a real misconfiguration for you, a one-off contribution helps fund
continued maintenance and new checks:

**→ https://buy.stripe.com/bJeeVe2te0U16Ln1yudMI00**

Prefer not to pay? Starring the repo or filing an issue for a false positive or a
missed case is just as valuable, and free.
