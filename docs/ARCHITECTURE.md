# Architecture

## Current engine (v0.x, single module)

`scripts/capability_registry.py` is a deliberate standard-library-only
monolith with these internal seams:

```
config (router_config.py)
  └── discovery ──► registry ──► search/bundle ──► emit
   skills, plugins,   jsonl shards,  lexical score,
   mcps, tools        manifest +    optional semantic
   (runtime snaps)    fingerprint   sidecar, lane select
```

- **Discovery** walks skill roots and plugin caches per runtime, parses
  SKILL.md frontmatter, imports MCP/plugin/tool snapshots.
- **Registry** writes `registry.jsonl`, `registrations.jsonl`, category
  shards, and a content fingerprint; queries self-heal staleness once.
- **Search** is lexical scoring with alias/intent damping; an embedder
  sidecar adds cosine re-ranking when available.
- **Bundle** selects a bounded portfolio across lanes: context, primary,
  integration, execution, verification, output.

## v1 upgrade seams

1. **Config-driven projects.** Any `config/<name>.toml` is a valid project;
   the CLI validates against files on disk instead of a hardcoded allowlist.
2. **Policy packs** (`policies/<project>.json`, selected with `--project`):

```json
{
  "deny": [{"types": ["mcp"], "names": ["some-server"]}],
  "require_context": [
    {"choose": [{"tool": "mcp__myproject__search_decisions"}, {"mcp": "myproject"}],
     "why": "Load prior decisions before acting.", "required": false}
  ],
  "prefer": [{"match": "\\b(library|sdk)\\b", "choose": [{"mcp": "context7"}],
              "lane": "context", "why": "Prefer live docs."}],
  "enable_routes": ["harness", "browser", "software"],
  "output_lane": {"choose": [{"skill": "your-output-polisher"}], "why": "..."}
}
```

- `deny` is absolute: denied capabilities never enter bundles, even for
  required lanes. Rule shapes are validated and fail loudly.
- `require_context` resolves each choice with its own type, in order.
- `prefer` adds matching capabilities to a lane with a score boost.
- `enable_routes` opts into the built-in demo routes (off by default).
- `output_lane` fires only on external-facing task keywords.

3. **Audit subsystem** (`scripts/cap_audit.py`): pure functions over file bytes
   → findings → verdict (`clean`/`suspect`/`hostile`). No network, no model by
   default. Used standalone (`lockkeeper audit`) and as the gate for future installs.
   Suppression markers are always surfaced as findings themselves.
4. **Installer** (planned, see ROADMAP): fetch → audit → hash-pin → place →
   rebuild. Not implemented in this version; `lockkeeper install` does not exist yet.
5. **Packaging**: install.sh symlinks `cap`; pyproject packaging is deferred
   until the single-module layout becomes an importable package.

## Invariants kept from v0.x

- Standard library only in the core path; semantic sidecar stays optional.
- Invalid startup configuration blocks public operations instead of falling back.
- Generated catalogs never load wholesale; routing returns bounded portfolios.
- Descriptions and registry metadata are treated as untrusted input everywhere.
