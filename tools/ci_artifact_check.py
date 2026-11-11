#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CI artifact 隐私与边界检查（零依赖，fail-closed）。

边界规则：
- artifacts 根下只允许 `<run_id>/run.json` 与 `<run_id>/nodes.jsonl`；
- 任何 `private/` 目录（如 `private/chain-auth.json`）或其他文件名都算违规；
- 至少存在一个 run 目录，且 run.json / nodes.jsonl 同时存在。

秘密规则（逐行扫描，输出 `file:line`）：
- 明文凭据字段 `username` / `password`；
- `socks5://user:pass@host` 形状的 URL；
- token 形状：`gh*_` / `glpat-` / `cfut_` / `sk-`。

用法：
  python tools/ci_artifact_check.py artifacts
  python tools/ci_artifact_check.py artifacts/<run_id>/nodes.jsonl
退出码：0 通过；1 违规或用法错误。
"""
import argparse
import re
import sys
from pathlib import Path

ALLOWED_FILES = ("run.json", "nodes.jsonl")
REQUIRED_FILES = ("run.json", "nodes.jsonl")
FORBIDDEN_DIRS = ("private",)

SECRET_URL = re.compile(r"socks5://[^/\s:@]+:[^/\s@]+@", re.I)
TOKEN_SHAPE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}"
    r"|cfut_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\b"
)
CRED_KEY = re.compile(r'"(?:username|password)"\s*:', re.I)


def _scan_file(path, errors):
    """逐行扫描单个 artifact 文件，返回违规行数（错误追加到 errors）。"""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        errors.append(f"{path}:0: not valid UTF-8 text")
        return 0
    except OSError as exc:
        errors.append(f"{path}:0: unreadable: {exc}")
        return 0
    hits = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        if CRED_KEY.search(line):
            errors.append(f"{path}:{lineno}: plaintext credential field (username/password) is forbidden")
            hits += 1
        if SECRET_URL.search(line):
            errors.append(f"{path}:{lineno}: plaintext socks5 user:pass URL is forbidden")
            hits += 1
        if TOKEN_SHAPE.search(line):
            errors.append(f"{path}:{lineno}: token-shaped value is forbidden")
            hits += 1
    return hits


def _check_file(path, errors):
    """校验单个文件：文件名白名单 + 内容扫描。"""
    if path.name not in ALLOWED_FILES:
        errors.append(f"{path}:0: unexpected artifact file (only {'/'.join(ALLOWED_FILES)} allowed)")
        return 0
    return _scan_file(path, errors)


def _check_run_dir(run_dir, errors):
    """校验一个 run 目录：结构白名单 + 必需文件 + 内容扫描。"""
    files = 0
    for child in sorted(run_dir.iterdir()):
        if child.is_dir():
            if child.name.lower() in FORBIDDEN_DIRS:
                errors.append(f"{child}:0: private/ directory must never be part of CI artifacts")
            else:
                errors.append(f"{child}:0: unexpected subdirectory in run dir")
            continue
        if child.name not in ALLOWED_FILES:
            errors.append(f"{child}:0: unexpected artifact file (only {'/'.join(ALLOWED_FILES)} allowed)")
            continue
        _scan_file(child, errors)
        files += 1
    for name in REQUIRED_FILES:
        if not (run_dir / name).is_file():
            errors.append(f"{run_dir / name}:0: missing required artifact file")
    return files


def check_paths(paths):
    """检查若干目录/文件，返回 `file:line: message` 错误列表（不抛异常）。"""
    errors = []
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            errors.append(f"{p}:0: path does not exist")
            continue
        if p.is_file():
            if p.name not in ALLOWED_FILES:
                errors.append(f"{p}:0: unexpected artifact file (only {'/'.join(ALLOWED_FILES)} allowed)")
            else:
                _scan_file(p, errors)
            continue
        if (p / "nodes.jsonl").is_file() or (p / "run.json").is_file():
            _check_run_dir(p, errors)
            continue
        runs = [c for c in sorted(p.iterdir()) if c.is_dir()]
        if not runs:
            errors.append(f"{p}:0: no artifact run directory found (fail-closed)")
            continue
        for child in sorted(p.iterdir()):
            if child.is_file():
                errors.append(f"{child}:0: unexpected file at artifact root")
            elif child.is_dir():
                _check_run_dir(child, errors)
    return errors


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check CI artifact privacy and layout (fail-closed)")
    ap.add_argument("paths", nargs="*", default=["artifacts"],
                    help="artifact root dir, run dir, or artifact file (default: artifacts)")
    args = ap.parse_args(argv)
    errors = check_paths(args.paths)
    if errors:
        for line in errors:
            print(line)
        print(f"FAIL ({len(errors)} violation(s))")
        return 1
    print(f"OK ({len(args.paths)} path(s) checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())