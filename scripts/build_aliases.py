#!/usr/bin/env python3
"""Build ~/.agents/capabilities/aliases.json -- the router's synonym side-car.

Two sources, merged:

1. DETERMINISTIC (this script, no LLM): the `keywords` array in every plugin.json.
   Those are the exact domain terms a user types, authored by the plugin's own maintainer.
   Free, high precision, and it is what makes exact domain-term queries reach the right entrypoint.

2. SEMANTIC (the community-detection pass, separate pass): community detection over the cleaned corpus supplies
   cross-vocabulary synonyms for the English surface -- "who else is doing this commercially"
   -> competitive-analysis. Merged in under the same schema; this script never clobbers
   external community-detection pass synonyms, it only adds its own.

The file is advisory: the router degrades to alias-free scoring if it is missing or stale.
It is deliberately NOT a registry field -- see load_aliases() for why.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from collections import Counter
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import capability_registry as registry  # noqa: E402

MAX_SYNONYMS_PER_CAPABILITY = 24

# A synonym that is merely a generic verb misroutes queries rather than helping them --
# it matches everything. These are already damped as SOFT terms on the query side; letting
# them in as aliases would reintroduce the exact bug that made "review" decisive.
BANNED_SYNONYMS = {
    "analyze", "analyse", "audit", "build", "check", "create", "debug", "draft", "edit",
    "find", "fix", "generate", "help", "implement", "list", "make", "plan", "prepare",
    "research", "review", "run", "search", "show", "summarize", "test", "verify", "write",
}


def llm_synonyms(synonym_dir: Path) -> dict[str, list[str]]:
    """Ingest the Haiku batch output. Missing or malformed batches are simply skipped."""
    harvested: dict[str, list[str]] = {}
    if not synonym_dir.is_dir():
        return harvested
    for batch in sorted(synonym_dir.glob("batch_*.json")):
        data = registry.load_json(batch)
        for entry in data.get("capabilities") or []:
            if not isinstance(entry, dict):
                continue
            capability_id = registry.clean_text(entry.get("id") or "")
            if not capability_id:
                continue
            words = []
            for word in entry.get("synonyms") or []:
                word = registry.clean_text(word).lower().strip()
                if not word or word in BANNED_SYNONYMS:
                    continue
                if len(word.split()) > registry.MAX_ALIAS_WORDS:
                    continue
                words.append(word)
            if words:
                harvested.setdefault(capability_id, []).extend(words)
    return harvested


def plugin_manifest_for(source_path: str) -> dict[str, Any]:
    """An entrypoint's source is <plugin_dir>/<name><suffix>.md; the manifest sits beside it."""
    plugin_dir = Path(source_path).parent
    for marker in (".claude-plugin", ".codex-plugin"):
        manifest = plugin_dir / marker / "plugin.json"
        if manifest.is_file():
            return registry.load_json(manifest)
    return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build deterministic and semantic alias side-car data.")
    parser.parse_args(argv)
    registry.ensure_router_config_valid()
    output = registry.ROUTER_CONFIG.output_dir
    synonym_dir = output / "audit" / "synonyms"
    records = registry.load_registry(output)
    existing = registry.load_json(output / "aliases.json")
    previous = existing.get("aliases") or {}

    harvested = llm_synonyms(synonym_dir)
    live_by_id = {record["id"]: record for record in records}

    aliases: dict[str, dict[str, Any]] = {}
    llm_applied = 0
    echoed_dropped = 0
    for capability_id, words in harvested.items():
        # An id the model altered or invented cannot be matched -- drop it rather than
        # guess. This is the main failure mode of LLM-authored ids.
        record = live_by_id.get(capability_id)
        if record is None:
            continue
        # A synonym that already appears in the name/description is worse than useless: the
        # router matches it lexically anyway, so as an alias it just double-scores the same
        # word (+18 on the name AND +6 on the alias). Drop it.
        blob = f"{record['name']} {record['description']}".lower()
        kept = []
        for word in dict.fromkeys(words):
            if word in blob:
                echoed_dropped += 1
                continue
            kept.append(word)
        kept = kept[:MAX_SYNONYMS_PER_CAPABILITY]
        if kept:
            aliases[capability_id] = {"synonyms": kept}
            llm_applied += 1

    # CONSENSUS GATE across duplicate records.
    # The same capability is often registered many times (14 records named "market-research").
    # Each was synonymized independently, so an agent that drifted its id->synonym pairing
    # produces one outlier among many agreeing siblings -- exactly what happened: 13 of the 14
    # market-research records got "market sizing analysis", one got LinkedIn synonyms.
    # Identical name+description => identical correct synonyms, so take the modal set and
    # overwrite the outliers. Deterministic, no LLM, and it repairs pairing drift for free.
    by_identity: dict[tuple[str, str], list[str]] = {}
    for capability_id in aliases:
        record = live_by_id[capability_id]
        by_identity.setdefault((record["type"], record["name"].lower()), []).append(capability_id)

    repaired = 0
    for _identity, sibling_ids in by_identity.items():
        if len(sibling_ids) < 3:
            continue  # need a real majority to trust a consensus
        tally = Counter(
            tuple(aliases[cid]["synonyms"]) for cid in sibling_ids
        )
        winner, votes = tally.most_common(1)[0]
        if votes * 2 <= len(sibling_ids):
            continue  # no majority -- leave every sibling alone rather than guess
        for cid in sibling_ids:
            if tuple(aliases[cid]["synonyms"]) != winner:
                aliases[cid] = {"synonyms": list(winner)}
                repaired += 1

    seeded = 0
    for record in records:
        if record["type"] != "entrypoint":
            continue
        manifest = plugin_manifest_for(record["source_path"])
        keywords = [
            registry.clean_text(word).lower()
            for word in (manifest.get("keywords") or [])
            if registry.clean_text(word) and len(registry.clean_text(word).split()) <= registry.MAX_ALIAS_WORDS
        ]
        if not keywords:
            continue
        # Union of three sources, in priority order: LLM-authored synonyms (this run),
        # anything already in the file, then the maintainer's own plugin.json keywords.
        # Do not let the keyword seed CLOBBER the LLM synonyms -- both are wanted.
        prior = previous.get(record["id"], {})
        from_llm = aliases.get(record["id"], {}).get("synonyms") or []
        merged = list(dict.fromkeys([*from_llm, *(prior.get("synonyms") or []), *keywords]))
        entry: dict[str, Any] = {"synonyms": merged[:MAX_SYNONYMS_PER_CAPABILITY]}
        for carried in ("cluster", "duplicate_group"):
            if prior.get(carried):
                entry[carried] = prior[carried]
        aliases[record["id"]] = entry
        seeded += 1

    # Carry forward every community-detection-authored entry we did not regenerate.
    live_ids = {record["id"] for record in records}
    carried = 0
    for capability_id, entry in previous.items():
        if capability_id in aliases or capability_id not in live_ids:
            continue
        aliases[capability_id] = entry
        carried += 1

    payload = {
        "schema_version": 1,
        "generated_at": registry.utc_now(),
        "source": "plugin.json keywords (deterministic) + the community-detection pass (semantic)",
        "aliases": dict(sorted(aliases.items())),
    }
    destination = output / "aliases.json"
    destination.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
    total_synonyms = sum(len(entry["synonyms"]) for entry in aliases.values())
    print(
        f"status: success\n"
        f"summary: {llm_applied:,} capabilities from LLM synonym pass, "
        f"{seeded} entrypoints seeded from plugin.json keywords, "
        f"{carried} carried forward, {echoed_dropped:,} echoed dropped, {repaired:,} drift-repaired by consensus, "
        f"{total_synonyms:,} synonyms across {len(aliases):,} capabilities\n"
        f"artifacts: {destination}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
