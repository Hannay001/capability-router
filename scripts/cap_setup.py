#!/usr/bin/env python3
"""System binding for cap: discover installed agent harnesses, bind, report.

`lockkeeper init`  — scan the machine, write config/local.toml bindings.
`lockkeeper doctor` — show what was found and whether routing is healthy.

Harness detection is deliberately generic so future runtimes work without a
cap release: anything under $HOME that looks like an agent harness (a dot-dir
containing skills/, or plugins/cache) is picked up by the generic scanner,
in addition to the well-known names below. Standard-library only.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

HOME = Path.home()

# (name, home dot-dirs relative to $HOME, CLI binary, notes)
KNOWN_HARNESS_SPECS = [
    ("claude", [".claude"], "claude"),
    ("codex", [".codex"], "codex"),
    ("jcode", [".jcode"], "jcode"),
    ("hermes", [".hermes"], "hermes"),
    ("cursor", [".cursor"], "cursor-agent"),
    ("opencode", [".opencode", ".config/opencode"], "opencode"),
    ("gemini", [".gemini"], "gemini"),
    ("cline", [".cline", ".config/cline"], None),
    ("windsurf", [".windsurf", ".codeium/windsurf"], None),
    ("copilot", [".copilot"], "copilot"),
]

GENERIC_SKILL_DIR_MARKERS = ("skills",)
SKIP_HOME_DIRS = {
    ".Trash", ".cache", ".cargo", ".config", ".docker", ".dropbox",
    ".git", ".gnupg", ".local", ".npm", ".nvm", ".pyenv", ".rustup",
    ".ssh", ".ssl", ".vscode", ".zsh", ".oh-my-zsh", ".keras", ".matplotlib",
}


@dataclass
class Harness:
    name: str
    home_dir: Path
    binary: Optional[str]
    known: bool
    skill_roots: list[Path] = field(default_factory=list)
    plugin_caches: list[Path] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return self.home_dir.is_dir() or bool(self.skill_roots) or bool(self.plugin_caches)


def _which(binary: str) -> Optional[str]:
    import shutil

    return shutil.which(binary)


def _skills_roots_under(harness_home: Path) -> list[Path]:
    roots = []
    direct = harness_home / "skills"
    if direct.is_dir():
        roots.append(direct)
    # nested layouts like .codeium/windsurf/skills or <home>/plugins/*/skills
    for marker in GENERIC_SKILL_DIR_MARKERS:
        for found in harness_home.glob(f"*/{marker}"):
            if found.is_dir() and found not in roots:
                roots.append(found)
    return roots


def _plugin_caches_under(harness_home: Path) -> list[Path]:
    caches = []
    for pattern in ("plugins/cache", "plugins"):
        candidate = harness_home / pattern
        if candidate.is_dir():
            caches.append(candidate)
    return caches


def _detect_known(spec) -> Harness:
    name, dot_dirs, binary = spec
    for dot_dir in dot_dirs:
        harness_home = HOME / dot_dir
        if harness_home.exists():
            resolved_binary = _which(binary) if binary else None
            return Harness(
                name=name,
                home_dir=harness_home,
                binary=resolved_binary,
                known=True,
                skill_roots=_skills_roots_under(harness_home),
                plugin_caches=_plugin_caches_under(harness_home),
            )
    return Harness(name=name, home_dir=HOME / dot_dirs[0], binary=binary, known=False)


def detect_harnesses() -> list[Harness]:
    """All known harnesses plus any unknown ones the generic scanner finds."""
    harnesses: dict[str, Harness] = {}
    seen_homes: set[Path] = set()
    for spec in KNOWN_HARNESS_SPECS:
        harness = _detect_known(spec)
        harnesses[harness.name] = harness
        if harness.present:
            seen_homes.add(harness.home_dir.resolve(strict=False))
            for root in (*harness.skill_roots, *harness.plugin_caches):
                seen_homes.add(root.resolve(strict=False))

    already_named = {h.name for h in harnesses.values()}
    for entry in HOME.iterdir():
        if not entry.is_dir() or entry.name.startswith(".") is False and entry.name not in {".config"}:
            if not entry.name.startswith("."):
                continue
        if entry.name in SKIP_HOME_DIRS or entry.resolve(strict=False) in seen_homes:
            continue
        if entry.name.lstrip(".").split("-")[0] in already_named:
            continue
        skill_roots = _skills_roots_under(entry)
        plugin_caches = _plugin_caches_under(entry)
        if not skill_roots and not plugin_caches:
            continue
        alias = entry.name.lstrip(".")
        harnesses[f"{alias} (auto-detected)"] = Harness(
            name=alias,
            home_dir=entry,
            binary=None,
            known=False,
            skill_roots=[root for root in skill_roots],
            plugin_caches=plugin_caches,
        )
    return list(harnesses.values())


def selected_skill_roots(selection: Optional[set[str]]) -> list[str]:
    """Portable skill-root strings for the chosen harnesses (all if selection is None)."""
    roots: list[str] = []
    for harness in detect_harnesses():
        if not harness.present:
            continue
        if selection is not None and harness.name.lower() not in selection:
            continue
        for root in harness.skill_roots:
            text = str(root)
            if text not in roots:
                roots.append(text)
    return roots


def cmd_init(args: argparse.Namespace) -> int:
    harnesses = detect_harnesses()
    present = [h for h in harnesses if h.present]
    if args.runtimes:
        selection = {name.strip().lower() for name in args.runtimes.split(",") if name.strip()}
        unknown = sorted(
            name for name in selection if name not in {h.name.lower() for h in present}
        )
        if unknown and not args.force:
            print(
                "status: error\nsummary: requested runtime(s) not detected on this machine: "
                + ", ".join(unknown)
            )
            return 1
    else:
        selection = None  # bind everything found

    roots = selected_skill_roots(selection)
    local_path = _repo_root() / "config" / "local.toml"
    lines = [
        "# Written by `lockkeeper init` — machine-local bindings; safe to delete.",
        "# This file is git-ignored and never leaves this machine.",
        f"[project]\nsurface_roots = [{', '.join(_toml_str(p) for p in _surface_candidates())}]",
        "",
        "[extensions]",
        "extra_skill_roots = [" + ", ".join(_toml_str(r) for r in roots) + "]",
    ]
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("status: success")
    print(f"bound skill roots ({len(roots)}):")
    for root in roots:
        print(f"  - {root}")
    print(f"bindings written: {local_path}")
    print("next: lockkeeper rebuild && lockkeeper doctor")
    return 0


def _surface_candidates() -> list[str]:
    candidates = []
    for harness in detect_harnesses():
        if harness.present:
            candidates.append(str(harness.home_dir))
    return candidates


def _toml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def cmd_doctor(args: argparse.Namespace) -> int:
    harnesses = detect_harnesses()
    print("lockkeeper doctor")
    print(f"python: {sys.version.split()[0]} (requires >= 3.11)")
    print("")
    print("harnesses:")
    any_present = False
    for harness in harnesses:
        if harness.present:
            any_present = True
            cli = harness.binary or "not on PATH"
            skills = sum(1 for root in harness.skill_roots for _ in root.glob("*/SKILL.md"))
            label = harness.name
            print(f"  [x] {label:<12} {str(harness.home_dir):<40} skills={skills:<4} cli={cli}")
        else:
            print(f"  [ ] {harness.name:<12} not detected")
    if not any_present:
        print("  (no harnesses found — cap still works standalone with `lockkeeper audit`)")

    registry_manifest = Path.home() / ".agents" / "capabilities" / "manifest.json"
    if registry_manifest.is_file():
        try:
            data = json.loads(registry_manifest.read_text(encoding="utf-8"))
            counts = data.get("counts", {})
            print("")
            print("registry:")
            print(f"  capabilities: {counts.get('capabilities', 0):,}")
            print(f"  rebuilt at:   {data.get('generated_at', 'unknown')}")
            print(f"  fingerprint:  {data.get('fingerprint', '')[:16]}")
        except (OSError, json.JSONDecodeError):
            pass
    else:
        print("")
        print("registry: not built yet — run `lockkeeper snapshot-runtimes && lockkeeper rebuild`")

    local_config = _repo_root() / "config" / "local.toml"
    print("")
    if local_config.is_file():
        print("binding: config/local.toml present (machine-local)")
    else:
        print("binding: none yet — run `lockkeeper init` to bind detected harnesses")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cap-setup", description="Bind cap to this machine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Detect harnesses and write local bindings")
    init_parser.add_argument(
        "--runtimes",
        help="Comma-separated subset to bind (default: everything detected)",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Write bindings even when a requested runtime was not detected",
    )

    subparsers.add_parser("doctor", help="Show detected harnesses and routing health")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "doctor":
        return cmd_doctor(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
