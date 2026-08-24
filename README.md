# 🛡️ AI Code Guard

A GitHub-native security gate for AI-generated code. Runs on every pull request, catches obvious problems deterministically, and adds evidence-grounded AI review on top — all reported directly in the PR, no dashboard required.

## Install

Add this to `.github/workflows/ai-code-guard.yml` in the repo you want protected:

```yaml
name: AI Code Guard

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: YOURNAME/ai-code-guard@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }} # optional
          fail-on: critical
```

Free tier runs deterministic checks with no API key needed. Add `anthropic-api-key` to unlock AI-based review of logic-level issues (broken auth, business-logic flaws, context-dependent injection risks).

## What it checks

**Deterministic (no AI, no API cost):**
- Hardcoded secrets — AWS/GitHub/Slack/Stripe/Google/Anthropic/OpenAI keys, private key blocks, JWTs, generic password/token assignments
- Dangerous commands — curl-pipe-to-shell, `rm -rf`, `eval()`, `shell=True`, unsafe `exec`/`execSync`, disabled TLS verification, unsafe deserialization
- Workflow permissions — `write-all`, risky `pull_request_target` + checkout-head combos, self-hosted runners on untrusted triggers
- Dependencies — non-registry sources (git/file URLs), unpinned wildcard versions
- Injection patterns — string-built SQL, raw `innerHTML`/`dangerouslySetInnerHTML`, concatenated shell commands

**AI-assisted (requires `anthropic-api-key`):**
- Context-dependent issues that need understanding intent: broken authorization, missing validation on a path that reaches a sink, insecure defaults, business-logic flaws

Every AI finding must cite an exact snippet from the diff as evidence — findings whose "evidence" isn't a real substring of the code sent to the model are dropped before you ever see them. **No evidence, no report.**

## Design principles

- **Scoped to the diff.** Only changed files (and their patches) are ever sent to the model — not the whole repo.
- **False positives are the enemy.** A tool that cries wolf gets uninstalled. See `tests/fixtures/safe/` for the false-positive regression suite.
- **Structured findings only.** Every finding follows Finding → Evidence → Explanation → Recommendation, with a confidence score.

## Local development

```bash
npm install
npm test          # runs deterministic checks against tests/fixtures/{vulnerable,safe}
npm run build      # bundles src/ -> dist/index.js (this is what actually ships)
```

`dist/` is committed (standard practice for JS-based GitHub Actions, since Actions don't run a build step for you). CI verifies `dist/` is in sync with `src/` on every push.

## Status

Early MVP. Deterministic checks are solid; AI review is functional but young. See `tests/fixtures/` for what's currently covered — contributions of new vulnerable/safe test cases are the highest-leverage way to help.

## License

MIT
