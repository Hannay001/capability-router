#!/usr/bin/env python3
"""Materialize the CLEANED capability surface as a folder of files for graphify.

Deliberately built from registry *records*, not from the raw skill directories:

- The raw dirs contain very large leaf corpora. They would
  dominate community detection and burn the entire LLM extraction budget on Prussian
  legal history. record_is_rankable() is exactly the predicate that excludes them.
- The record metadata (name + description + category) IS the surface the router scores
  against. Graphing anything else would map a corpus the router never sees.

Output: one small markdown file per capability, which graphify ingests to produce
communities, semantic-duplicate edges, and the synonyms that feed aliases.json.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import capability_registry as registry  # noqa: E402


def safe_stem(record: dict) -> str:
    """Filename must be stable and collision-free: capability id is both."""
    return record["id"].replace(":", "_")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize the routable capability corpus for graph analysis.")
    parser.parse_args(argv)
    registry.ensure_router_config_valid()
    corpus_dir = registry.ROUTER_CONFIG.output_dir / "audit" / "corpus"
    records = registry.load_registry(registry.ROUTER_CONFIG.output_dir)
    surface = [record for record in records if registry.record_is_rankable(record)]

    if corpus_dir.exists():
        shutil.rmtree(corpus_dir)
    corpus_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for record in surface:
        category = registry.CATEGORY_BY_SLUG.get(record["category"], {}).get("title", record["category"])
        body = "\n".join(
            [
                "---",
                f"id: {record['id']}",
                f"name: {record['name']}",
                f"type: {record['type']}",
                f"category: {record['category']}",
                f"runtimes: {', '.join(record['runtimes'])}",
                "---",
                "",
                f"# {record['name']}",
                "",
                f"**Type:** {record['type']}  ",
                f"**Domain:** {category}",
                "",
                record["description"] or "(no description)",
                "",
            ]
        )
        (corpus_dir / f"{safe_stem(record)}.md").write_text(body, encoding="utf-8")
        written += 1

    excluded = len(records) - len(surface)
    print(
        f"status: success\n"
        f"summary: wrote {written:,} capability files; excluded {excluded:,} "
        f"non-routable leaf skills (not router candidates)\n"
        f"artifacts: {corpus_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
