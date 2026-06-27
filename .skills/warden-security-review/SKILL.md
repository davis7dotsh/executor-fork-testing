---
name: warden-security-review
description: Run Warden security scans in this repo using Sentry's warden-skills. Use when asked to audit security, scan with Warden, investigate authz/data-exfil/code-execution/GitHub Actions risks, or triage Warden findings.
---

# Warden security review runbook

Use Warden as a first-pass scanner, then manually verify every finding against the code. A clean Warden run means "no findings from that skill/pass", not "the codebase is secure."

## Setup

Warden uses Claude Code auth locally. For Claude Max usage:

```bash
claude login
```

Run Warden through npm so the package version does not need to be committed:

```bash
npm exec --yes --package=@sentry/warden -- warden --help
```

The repo has a `warden.toml` that uses remote skills from `getsentry/warden-skills`.

Before scanning, verify that every configured target resolves to at least one
non-ignored file:

```bash
bun run lint:warden-targets
```

Reference skills are mirrored under `.reference/warden-skills` when needed. `.reference/` is gitignored.

## Local Outputs

Write run artifacts under `.warden-runs/`. Do not commit `.warden/` or `.warden-runs/`.

Use JSONL output for later triage:

```bash
mkdir -p .warden-runs
npm exec --yes --package=@sentry/warden -- \
  warden <targets...> --skill <skill> --fail-on off --report-on low --min-confidence low \
  --parallel 2 --log -o .warden-runs/<name>.jsonl
```

Warden may not treat bare directories as recursive targets. Prefer explicit quoted globs or a target file list.

## Recommended Scans

Authz on the active Rust API and OAuth surfaces plus archived opt-in API
surfaces:

```bash
npm exec --yes --package=@sentry/warden -- \
  warden "src/api.rs" "src/api/**/*.rs" "src/oauth/**/*.rs" \
  "legacy/cloud/src/auth/**/*.ts" "legacy/cloud/src/api/**/*.ts" \
  "legacy/cloud/src/routes/**/*.tsx" "packages/core/api/src/**/*.ts" \
  --skill wrdn-authz --fail-on off --report-on low --min-confidence low \
  --parallel 2 --log -o .warden-runs/authz.jsonl
```

Code execution on sink-bearing runtime/plugin files:

The archived local runtime remains in scope because explicit legacy development
and test commands can still execute it. No release workflow publishes it. Its
server code lives directly under `legacy/local/src`, not a `src/server`
subdirectory.

```bash
rg -l "\b(exec|spawn|execFile|fork|subprocess|Deno\.Command|new Function|eval\(|vm\.|QuickJS|quickjs|Worker\(|import\(|compile|instantiate|runIn|shell|command|child_process)\b" \
  src legacy/local/src legacy/cli/src packages/core/execution/src packages/core/sdk/src packages/kernel packages/plugins \
  -g "*.rs" -g "*.ts" -g "*.tsx" -g "!*.test.ts" -g "!*.spec.ts" -g "!*.e2e.ts" -g "!**/dist/**" -g "!**/node_modules/**" \
  > .warden-runs/code-execution-targets.txt

npm exec --yes --package=@sentry/warden -- \
  warden $(tr '\n' ' ' < .warden-runs/code-execution-targets.txt) \
  --skill wrdn-code-execution --fail-on off --report-on low --min-confidence low \
  --parallel 2 --log -o .warden-runs/code-execution.jsonl
```

Data exfiltration on backend/API/storage/plugin SDK surfaces:

```bash
find src/api src/catalog src/invocation src/mcp src/oauth src/protocols src/runtime \
  src/api.rs src/database.rs src/outbound.rs src/request_logs.rs \
  legacy/cloud/src/api legacy/cloud/src/auth legacy/cloud/src/routes legacy/local/src \
  packages/core/api/src packages/plugins packages/react/src/api \
  -type f \( -name "*.rs" -o -name "*.ts" -o -name "*.tsx" \) |
  rg -v '(\.test\.|\.spec\.|\.e2e\.|dist/|node_modules/|embedded-migrations\.gen\.ts)' \
  > .warden-runs/exfil-targets-focused.txt

npm exec --yes --package=@sentry/warden -- \
  warden $(tr '\n' ' ' < .warden-runs/exfil-targets-focused.txt) \
  --skill wrdn-data-exfil --fail-on off --report-on low --min-confidence low \
  --parallel 2 --log -o .warden-runs/data-exfil.jsonl
```

GitHub Actions workflow risks:

```bash
find .github -type f \( -name "*.yml" -o -name "*.yaml" \) > .warden-runs/gha-targets.txt

npm exec --yes --package=@sentry/warden -- \
  warden $(tr '\n' ' ' < .warden-runs/gha-targets.txt) \
  --skill wrdn-gha-workflows --fail-on off --report-on low --min-confidence low \
  --parallel 2 --log -o .warden-runs/gha-workflows.jsonl
```

## How to Triage

Deduplicate findings by root cause. Warden often reports the same bug at the low-level sink, wrapper, API handler, and plugin-tool entrypoint.

For each candidate:

- Trace whether input is user-controlled.
- Identify the exact sink.
- Check whether auth, scope, host allowlists, private-IP blocks, redirects, and DNS rebinding defenses exist.
- Determine what data returns to the caller: raw body, parsed fields, typed error message, timing/status oracle, or no observable data.
- State confidence and deployment caveats.

## Result freshness

Do not carry old findings or clean claims forward without rerunning the current
targets. Report the exact commit, skill, target list, confidence threshold, and
output artifact for every result. A clean scoped pass is not evidence that the
whole codebase is secure.
