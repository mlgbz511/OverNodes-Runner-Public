#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI 壳：调用 src/node_artifact.py 校验 node artifacts。

用法与退出码保持不变：
  python tools/validate_node_artifact.py tests/fixtures/schema/valid/*
  python tools/validate_node_artifact.py artifacts/<run_id>/nodes.jsonl --json
退出码：0 全部通过；1 存在错误。
"""
import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from node_artifact import (  # noqa: E402
    DEFAULT_SCHEMA_PATH,
    HAVE_JSONSCHEMA,
    load_schema,
    secret_errors,
    validate,
    validate_file,
)

# 兼容旧调用方（tests 直接 import 本文件后使用 DEFAULT_SCHEMA）。
DEFAULT_SCHEMA = DEFAULT_SCHEMA_PATH


def main(argv=None):
    ap = argparse.ArgumentParser(description="Validate OverNodes node artifacts")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--schema", default=str(DEFAULT_SCHEMA_PATH))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    schema = load_schema(args.schema)
    all_errors = {}
    for path in args.paths:
        errs = validate_file(path, schema)
        if errs:
            all_errors[path] = errs
    backend = "jsonschema" if HAVE_JSONSCHEMA else "builtin"
    if args.json:
        print(json.dumps({"ok": not all_errors, "errors": all_errors, "backend": backend},
                         ensure_ascii=False, indent=2))
    else:
        if all_errors:
            for path, errs in all_errors.items():
                print(f"FAIL {path}")
                for e in errs[:20]:
                    print(f"  - {e}")
        else:
            print(f"OK ({len(args.paths)} file(s), backend={backend})")
    return 0 if not all_errors else 1


if __name__ == "__main__":
    sys.exit(main())