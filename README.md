# cap

**The package manager and trust layer for your AI agent's capabilities.**

`cap` indexes every skill, MCP server, plugin, tool, agent, and command installed
across your coding agents (Claude Code, Codex, Cursor, OpenCode, Hermes, Jcode),
routes any task to a **bounded portfolio** of the right capabilities, and audits
everything it touches with a built-in **prompt-injection firewall**.

> Your agent doesn't need all 500 capabilities in context.
> It needs the right 8, verified safe, for this task.

```bash
$ cap route --runtime claude --stdin <<'TASK'
migrate the auth module to the new token API
TASK
```

```
status: success
summary: selected 6 complementary capabilities across 4 lanes
[context] mcp: context7
[primary] skill: api-migration
[integration] tool: mcp__context7__query_docs
[execution] tool: exec_command
[verification] agent: code-reviewer
[support] skill: python-patterns
```

(Exact entries depend on what you have installed; lanes and bounded portfolio
size are what `cap` guarantees.)

- Zero dependencies: pure Python 3.11+ standard library. The optional semantic
  sidecar is the only extra.
- Cross-runtime: one index over every harness you use; bundles are filtered to
  what each runtime can actually execute.
- Self-healing: queries refresh stale registries automatically; invalid config
  fails loudly instead of guessing.

## Why

Agent capability directories are exploding. Three MCP servers can eat 140k
tokens before real work starts; copied skills ship hidden instructions nobody
reads. Existing tools manage *servers*; none route *tasks* across *all* your
installed capabilities, and none screen what you install.

`cap` is the missing layer:

| Layer | Command | Status |
|---|---|---|
| Index & inventory | `cap rebuild`, `cap check` | ✅ shipped |
| Task routing | `cap search`, `cap bundle` / `route` | ✅ shipped |
| Prompt-injection firewall | `cap audit` | ✅ shipped (static) |
| Install & lock | `cap install`, `cap.lock` | 🔜 roadmap |
| Remote discovery | `cap search --remote` | 🔜 roadmap |

See [ROADMAP.md](ROADMAP.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Install

### Way 1 — no terminal skills required (one paste)

Copy the prompt in [PROMPT.md](PROMPT.md) and paste it into any AI coding agent
you already have. It installs cap, binds it to every harness it finds on your
machine, builds the index, and reports back in plain language.

### Way 2 — terminal, zero manual wiring

```sh
git clone https://github.com/<you>/capability-router.git
cd capability-router
./install.sh        # symlinks `cap`, then auto-detects and binds every harness on this machine
cap snapshot-runtimes
cap rebuild
cap doctor          # shows each bound harness and its skill count
```

`./install.sh` scans for Claude Code, Codex, Cursor, Jcode, Hermes, OpenCode,
Gemini, Copilot, Windsurf, Cline — **plus anything unknown** that looks like an
agent harness under your home directory. Bindings are written to
`config/local.toml` (git-ignored, machine-local).

Selective binding:

```sh
CAP_RUNTIMES=claude,codex ./install.sh   # bind only these two
CAP_NO_INIT=1 ./install.sh               # install without auto-binding
```

### Route and audit

```sh
# Route a task to a bounded portfolio from any bound harness's perspective
cap route --runtime claude --stdin --max 8 <<'CAPABILITY_QUERY'
audit our payment webhook for race conditions
CAPABILITY_QUERY

# Audit any skill folder before installing it
cap audit ~/Downloads/some-skill --recursive --strict
```

### Auditing skills (the firewall)

`cap audit` scans SKILL.md files, plugin manifests, and MCP configs for:

- instruction-override phrasing ("ignore previous instructions…") <!-- cap-audit-suppress -->
- exfiltration pipelines (secrets/ssh/env → curl/wget/nc)
- credential-store access (`~/.ssh`, keychain, `.aws`, `.env`) <!-- cap-audit-suppress -->
- obfuscated execution (`base64 -d | sh`, eval'd fetches) <!-- cap-audit-suppress -->
- destructive commands (`rm -rf ~`, force-push to main)
- hidden directive comments and invisible/homoglyph Unicode

Verdicts: `clean` / `suspect` / `hostile`. With `--strict`, exit codes gate
installs and CI: 0 / 1 / 2. A missing or non-auditable target under `--strict`
also fails the gate. First-party docs that quote attack patterns can carry a
`cap-audit-suppress` marker on a line; every marker usage is itself reported
as a high finding, so a suppressed file can never audit clean.

## Configuration

Structural paths come from `config/default.toml`; add per-project overlays as
`config/<name>.toml` and select them with `--project <name>`. Project-specific
routing policy (deny lists, required-context lanes) lives in declarative
**policy packs**: `policies/<project>.json`. See
[policies/example.json](policies/example.json).

The optional semantic sidecar (`embedder/`) adds embedding re-ranking on top of
lexical scoring; everything works without it.

## Development

```sh
HOME="$(mktemp -d)" python3.11 -m unittest \
  tests.test_router_config tests.test_router_integration tests.test_cap_audit
```

Requirements: Python 3.11+. No third-party dependencies in the core path.
Platforms: Linux and macOS are first-class today. Windows works under WSL;
native Windows support (Developer Mode symlinks or junctions) is on the
roadmap — see ROADMAP.md.

## License

MIT — see [LICENSE](LICENSE).
