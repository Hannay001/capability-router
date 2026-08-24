#!/usr/bin/env python3
"""Batch the routable capability surface into files for inline synonym extraction.

The pilot burned 85k tokens on 12 records because the agent Read each file separately --
13 tool calls for ~500 tokens of actual content. The whole corpus is only ~220k tokens of
text; the cost was almost entirely tool-call overhead. So: pre-batch the records INLINE
into a handful of files, and each agent does exactly one Read.

Excludes records the router marks non-rankable -- they already carry
maintainer-authored keywords from plugin.json via build_aliases.py, and they are not
router candidates anyway.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import capability_registry as registry  # noqa: E402
BATCH_SIZE = 200


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch routable capabilities for synonym extraction.")
    parser.parse_args(argv)
    registry.ensure_router_config_valid()
    batch_dir = registry.ROUTER_CONFIG.output_dir / "audit" / "batches"
    records = [r for r in registry.load_registry(registry.ROUTER_CONFIG.output_dir) if registry.record_is_rankable(r)]
    records.sort(key=lambda r: (r["category"], r["type"], r["name"].lower()))

    if batch_dir.exists():
        shutil.rmtree(batch_dir)
    batch_dir.mkdir(parents=True, exist_ok=True)

    batches = [records[i : i + BATCH_SIZE] for i in range(0, len(records), BATCH_SIZE)]
    for index, batch in enumerate(batches):
        lines = [
            f"# Capability batch {index:03d} ({len(batch)} records)",
            "",
            "Each line: ID <TAB> TYPE <TAB> NAME <TAB> DESCRIPTION",
            "",
        ]
        for record in batch:
            description = " ".join((record["description"] or "").split())[:280]
            lines.append(
                f"{record['id']}\t{record['type']}\t{record['name']}\t{description}"
            )
        (batch_dir / f"batch_{index:03d}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    total_chars = sum(len(p.read_text(encoding="utf-8")) for p in batch_dir.glob("*.md"))
    print(
        f"status: success\n"
        f"summary: {len(records):,} routable capabilities -> {len(batches)} batches "
        f"of <={BATCH_SIZE} (~{total_chars // 4:,} tokens of content total)\n"
        f"artifacts: {batch_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
