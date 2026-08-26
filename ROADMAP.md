# lockkeeper — Roadmap

`lockkeeper` turns the capability router from a personal inventory tool into the
**package manager and trust layer for agent capabilities**: skills, MCP
servers, plugins, tools, agents, and commands across every major coding-agent
runtime (Claude Code, Codex, Cursor, OpenCode, Hermes, Jcode).

Positioning in one line: *npm for your agent's context — with a built-in
prompt-injection firewall.*

## Why now

- Agents drown in installed capabilities; context windows fill before work starts.
- Skills/MCPs are copied from random repos with zero safety screening.
- No existing tool indexes capabilities across runtimes and routes tasks to a
  bounded portfolio (verified against the ecosystem in Aug 2026).

## v1.0 — Public foundation (current work)

- [x] De-personalized core: no hardcoded users, projects, or pinned paths.
- [x] `lockkeeper` CLI name (`capability-registry` kept as an alias).
- [x] Project policy is config-driven (any `config/<name>.toml`).
- [x] Bundle lane heuristics read optional declarative **policy packs**
      (`policies/<project>.json`) instead of hardcoded capability names.
- [x] MIT license, CI on Python 3.11–3.14, real README.
- Deferred to v1.1: pyproject.toml packaging (needs the single-module import
  layout refactored into a package first).

## v1.0.x — Platform hardening

- [x] Windows-blocking import (fcntl) made portable; per-OS venv paths,
      shutil.which CLI resolution, UTF-8 subprocess decoding.
- [x] Native Windows story: symlink privilege docs vs junction fallback,
      sys.platform-guarded integration tests, windows-latest CI job.

## v1.1 — Audit firewall (`lockkeeper audit`) — SHIPPED

Static, stdlib-only analysis of any skill/plugin/MCP definition:

- Rule families: instruction override, exfiltration (network calls touching
  secrets/env/ssh), obfuscation (base64/eval/homoglyphs/zero-width chars),
  destructive commands, hidden directive text.
- Severity-weighted verdicts: `clean` / `suspect` (warn) / `hostile` (block).
- JSON + human output; non-zero exit under `--strict` for CI and install gates.
- Optional LLM second-pass behind a provider plug-in interface (offline first).

## Competitive upgrades (from the Aug 2026 landscape scan)

Closest neighbors: Tencent AI-Infra-Guard `skill-scan` (LLM-assisted, T01-T09
taxonomy, SkillTrustBench), Cisco `mcp-scanner` (YARA+LLM engines, CVE +
binary scanning), `pipelock` (egress firewall, signed action receipts),
`parry-guard` (ML runtime-hook scanner), `SkillRouter` (body-aware retrieve-
and-rerank at ~80K skills). None combines cross-runtime routing with a
local, dependency-free install-time firewall -- that gap is lockkeeper's niche.

- [x] Taxonomy mapping: tag `lockkeeper audit` findings with T01-T09 categories so
      results are comparable with SkillTrustBench-class tools.
- [x] Non-text payloads: `.pyc`/binaries inside an audited directory get
      hashed and floored to `suspect` instead of being ignored silently.
- [x] `lockkeeper hook`: Claude Code / Codex hook mode scanning live tool payloads
      (PreToolUse-style stdin/stdout contract), extending the firewall from
      files to runtime traffic.
- [x] Optional LLM deep-scan tier: `--llm-scan` with an OpenAI-compatible
      provider via env config; off by default, failures degrade to info.
- [x] Dependency CVE gate: check skill-declared dependencies against
      osv.dev (keyless, cached) during `lockkeeper audit`.
- [x] Signed audit receipts: locally-verifiable scan reports for CI evidence.
- [x] Reranking study: body-aware second-stage ranking -- tested as a
      post-hoc rescore over live registries (14 known-answer queries,
      weights 10/25/45): Hit@1 unchanged, MRR slightly worse. Description-
      level ranking is already saturated at personal-registry scale;
      revisit only above ~50K overlapping skills or with a learned encoder.

## v1.2 — Install & lock (`lockkeeper install`, `cap.lock`)

- Sources: git URL, tarball, local path.
- Pipeline: fetch → audit gate → verify hash → place into selected runtime
  skill roots → rebuild index.
- `cap.lock` pins origin commit + content hash + audit verdict per capability.
- Runtime targets: `claude`, `codex`, `cursor`, `opencode`, `jcode`, `hermes`.

## v1.3 — Remote discovery

- `lockkeeper search <query> --remote`: GitHub API aggregator over topic-indexed skill
  repos (no central server to operate).
- Audit-on-search: remote results show cached/static verdicts before install.

## v2.x — Context-budget optimizer

- Live per-capability token-cost accounting.
- Auto-loading only the top-k relevant capabilities per task (router-driven),
  instead of everything at startup.

## Non-goals

- Running a hosted registry service.
- Replacing MCP server management apps (complementary, not competing).
- Telemetry of any kind.
