#!/usr/bin/env python3
from __future__ import annotations

import argparse

import capability_registry as registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rebuild the registry and export its configured skill catalog.")
    parser.parse_args(argv)
    registry.ensure_router_config_valid()
    output = registry.ROUTER_CONFIG.output_dir
    registry.rebuild(output, quiet=True)
    registry.export_skill_csv(output, registry.ROUTER_CONFIG.skill_catalog_csv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
