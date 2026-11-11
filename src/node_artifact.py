#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Node Artifact Schema v1.0 唯一权威核心：加载、校验、产物目录读取、旧文本视图适配。

- `validate*`：零依赖 JSON-Schema 子集校验（Draft 2020-12 中用到的关键字）+ 秘密断言。
- `validate_artifact_dir` / `latest_run` / `load_records`：读取 `artifacts/<run_id>/`。
- `records_to_lines`：把 `nodes.jsonl` 记录渲染为旧订阅文本（actions/local/download），
  与 `src/cf_overscan.py` 的 `rotate_and_save_nodes` / `save_download_nodes` 现存输出逐字节一致。

`tools/validate_node_artifact.py` 只是本模块的 CLI 壳，避免双份校验实现。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA_VERSION = "1.0"
DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "specs" / "node-artifact.schema.json"
LEGACY_VIEWS: Tuple[str, ...] = ("actions", "local", "download")

DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
SECRET_URL = re.compile(r"socks5://[^/\s:@]+:[^/\s@]+@", re.I)
TOKEN_SHAPE = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_\-]{20,}|cfut_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\b")

try:  # 可选后端，仅用于 CLI 的 backend 标识；没有也完全可用。
    import jsonschema  # type: ignore  # noqa: F401

    HAVE_JSONSCHEMA = True
except Exception:  # pragma: no cover - depends on environment
    HAVE_JSONSCHEMA = False


# ---------------------------------------------------------------------------
# Schema 校验核心（原 tools/validate_node_artifact.py 迁移）
# ---------------------------------------------------------------------------
def load_schema(path: Optional[str] = None) -> Dict[str, Any]:
    """加载 JSON Schema；`path` 为空时使用 `DEFAULT_SCHEMA_PATH`。"""
    return json.loads(Path(path or DEFAULT_SCHEMA_PATH).read_text(encoding="utf-8"))


def _resolve(schema: Dict[str, Any], root: Dict[str, Any]) -> Dict[str, Any]:
    seen = 0
    while isinstance(schema, dict) and "$ref" in schema and seen < 10:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            raise ValueError(f"unsupported $ref: {ref}")
        node = root
        for part in ref[2:].split("/"):
            node = node[part]
        schema = node
        seen += 1
    return schema


def _type_ok(value: Any, t: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "null": value is None,
    }.get(t, True)


def validate(instance: Any, schema: Any, root: Any, path: str = "$", errors: Optional[List[str]] = None) -> List[str]:
    """递归校验一个实例，返回 `path: message` 列表（不抛异常）。"""
    if errors is None:
        errors = []
    schema = _resolve(schema, root)
    if not isinstance(schema, dict):
        return errors
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_type_ok(instance, x) for x in types):
            errors.append(f"{path}: expected type {types}, got {type(instance).__name__}")
            return errors
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: expected one of {schema['enum']}, got {instance!r}")
    if isinstance(instance, str):
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: does not match pattern {schema['pattern']}")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength {schema['maxLength']}")
        if schema.get("format") == "date-time" and not DATE_TIME.match(instance):
            errors.append(f"{path}: invalid date-time {instance!r}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")
    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(f"{path}: missing required property {req!r}")
        props = schema.get("properties", {})
        add = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in props:
                validate(value, props[key], root, f"{path}.{key}", errors)
            elif add is False:
                errors.append(f"{path}: additional property {key!r} is not allowed")
            elif isinstance(add, dict):
                validate(value, add, root, f"{path}.{key}", errors)
    if isinstance(instance, list) and "items" in schema:
        for i, value in enumerate(instance):
            validate(value, schema["items"], root, f"{path}[{i}]", errors)
    if "oneOf" in schema:
        matches, collected = 0, []
        for i, sub in enumerate(schema["oneOf"]):
            errs = validate(instance, sub, root, path, [])
            if not errs:
                matches += 1
            else:
                collected.append(f"oneOf[{i}]: " + "; ".join(errs[:2]))
        if matches != 1:
            errors.append(f"{path}: expected exactly one oneOf match, got {matches} ({'; '.join(collected[:3])})")
    if "allOf" in schema:
        for sub in schema["allOf"]:
            validate(instance, sub, root, path, errors)
    if "if" in schema:
        if not validate(instance, schema["if"], root, path, []):
            if "then" in schema:
                validate(instance, schema["then"], root, path, errors)
    return errors


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _walk_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_strings(v)


def secret_errors(record: Any, path: str = "$") -> List[str]:
    """公开产物秘密断言：chain exit 禁止明文账号、禁止 socks5 user:pass URL、禁止 token 形状。"""
    errs: List[str] = []
    if not isinstance(record, dict):
        return errs
    if record.get("kind") == "chain":
        exit_obj = record.get("exit")
        if not isinstance(exit_obj, dict):
            errs.append(f"{path}: chain node requires exit")
        else:
            for bad in ("username", "password", "user", "pass"):
                if bad in exit_obj:
                    errs.append(f"{path}.exit.{bad}: plaintext credential field is forbidden (use auth_ref)")
    for value in _walk_strings(record):
        if SECRET_URL.search(value):
            errs.append(f"{path}: plaintext socks5 user:pass URL is forbidden")
        if TOKEN_SHAPE.search(value):
            errs.append(f"{path}: token-shaped value is forbidden")
    return errs


def validate_records(records: Sequence[Dict[str, Any]], schema: Optional[Dict[str, Any]] = None) -> List[str]:
    """校验一组 NodeRecord；返回 `record[i]: message` 列表。"""
    schema = schema or load_schema()
    node_schema = schema["$defs"]["NodeRecord"]
    errors: List[str] = []
    for i, rec in enumerate(records):
        errs = validate(rec, node_schema, schema)
        errs += secret_errors(rec)
        errors += [f"record[{i}]: {x}" for x in errs]
    return errors


def validate_file(path: str, schema: Optional[Dict[str, Any]] = None) -> List[str]:
    """校验 `.jsonl`（逐行 NodeRecord）或 `.json`（ArtifactEnvelope），错误带文件名前缀。"""
    p = Path(path)
    schema = schema or load_schema()
    text = p.read_text(encoding="utf-8")
    errors: List[str] = []
    if p.suffix.lower() == ".jsonl":
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception as e:
                errors.append(f"{p}: line {i}: invalid JSON: {e}")
                continue
            e = validate(rec, schema["$defs"]["NodeRecord"], schema)
            e += secret_errors(rec, f"line {i}")
            errors += [f"{p}: {x}" for x in e]
    else:
        try:
            obj = json.loads(text)
        except Exception as e:
            return [f"{p}: invalid JSON: {e}"]
        e = validate(obj, schema, schema)
        e += secret_errors(obj)
        errors += [f"{p}: {x}" for x in e]
    return errors


# ---------------------------------------------------------------------------
# 产物目录读取
# ---------------------------------------------------------------------------
def load_records(path: str) -> List[Dict[str, Any]]:
    """读取记录列表：`.jsonl` 每行一条；`.json` 支持 envelope.records / 裸数组 / 单条记录。"""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".jsonl":
        records: List[Dict[str, Any]] = []
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except Exception as e:
                raise ValueError(f"{p}: line {i}: invalid JSON: {e}") from e
        return records
    obj = json.loads(text)
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict) and isinstance(obj.get("records"), list):
        return obj["records"]
    if isinstance(obj, dict):
        return [obj]
    raise ValueError(f"{p}: unsupported record container {type(obj).__name__}")


def validate_artifact_dir(
    run_dir: str, schema: Optional[Dict[str, Any]] = None
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]], List[str]]:
    """读取并校验一个 run 目录（`nodes.jsonl` + `run.json`）。

    返回 `(records, run_meta, errors)`。目录产物不完整（缺文件）也记入 errors。
    """
    d = Path(run_dir)
    schema = schema or load_schema()
    errors: List[str] = []
    records: List[Dict[str, Any]] = []
    run_meta: Optional[Dict[str, Any]] = None

    nodes_path = d / "nodes.jsonl"
    if not nodes_path.is_file():
        errors.append(f"{nodes_path}: missing nodes.jsonl")
    else:
        errors += validate_file(str(nodes_path), schema)
        try:
            records = load_records(str(nodes_path))
        except ValueError as e:
            errors.append(str(e))

    run_path = d / "run.json"
    if not run_path.is_file():
        errors.append(f"{run_path}: missing run.json")
    else:
        errors += validate_file(str(run_path), schema)
        try:
            loaded = json.loads(run_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                run_meta = loaded
        except Exception:
            run_meta = None
    return records, run_meta, errors


def latest_run(base_dir: Optional[str] = None) -> Optional[Path]:
    """返回 `base_dir`（默认 `<repo>/artifacts`）下 run_id 最新的目录；没有则 None。

    run_id 形如 `YYYYMMDDTHHMMSSZ-<6hex>`，字典序即时间序；只认含 `nodes.jsonl` 的目录。
    """
    root = Path(base_dir) if base_dir else DEFAULT_SCHEMA_PATH.parents[2] / "artifacts"
    if not root.is_dir():
        return None
    runs = [p for p in root.iterdir() if p.is_dir() and (p / "nodes.jsonl").is_file()]
    if not runs:
        return None
    return max(runs, key=lambda p: p.name)


# ---------------------------------------------------------------------------
# 旧文本视图适配器（纯函数；view 只决定渲染格式，记录筛选仅 kind=direct）
# ---------------------------------------------------------------------------
def _entry(rec: Dict[str, Any]) -> Tuple[str, int]:
    entry = rec.get("entry") or {}
    return str(entry.get("host", "")).strip(), int(entry.get("port", 443))


def _country(rec: Dict[str, Any]) -> str:
    return str((rec.get("tags") or {}).get("country", "US")).upper()[:2]


def _metrics(rec: Dict[str, Any]) -> Tuple[float, float]:
    m = rec.get("metrics") or {}
    return float(m.get("speed_mbps", 0.0)), float(m.get("latency_ms", 0.0))


def _purity_suffix(rec: Dict[str, Any]) -> Optional[str]:
    purity = rec.get("purity")
    if not isinstance(purity, dict):
        return None
    return f"-P{int(purity.get('score', 0))}"


def _ranked_lines(records: Sequence[Dict[str, Any]], view: str, purity_in_name: bool) -> List[str]:
    lines: List[str] = []
    ips_by_country: Dict[str, List[str]] = {}
    for rec in records:
        host, port = _entry(rec)
        if not host:
            continue
        country = _country(rec)
        rank_list = ips_by_country.setdefault(country, [])
        if host not in rank_list:
            rank_list.append(host)
        rank = rank_list.index(host) + 1
        suffix = _purity_suffix(rec) if purity_in_name else ""
        if view == "actions":
            lines.append(f"{host}:{port}#{country}{suffix}-[{rank:02d}]:{port}")
        else:  # local
            speed, _ = _metrics(rec)
            lines.append(f"{host}:{port}#{country}{suffix}[{speed:.2f}MB/S]-{port}")
    return lines


def _download_lines(records: Sequence[Dict[str, Any]]) -> List[str]:
    """复刻 save_download_nodes：按端口升序，每端口取速度最高 1 个 + 剩余里延迟最低 1 个。"""
    by_port: Dict[int, List[Tuple[str, int, str, float, float]]] = {}
    for rec in records:
        host, port = _entry(rec)
        if not host:
            continue
        speed, latency = _metrics(rec)
        by_port.setdefault(port, []).append((host, port, _country(rec), speed, latency))

    lines: List[str] = []
    for port in sorted(by_port):
        items = by_port[port]
        if len(items) <= 2:
            selected = items
        else:
            best_speed = max(items, key=lambda x: x[3])
            remaining = [x for x in items if x[0] != best_speed[0]]
            if remaining:
                best_lat = min(remaining, key=lambda x: x[4])
                selected = [best_speed, best_lat]
            else:
                selected = [best_speed]
        for rank, item in enumerate(selected, 1):
            host, item_port, country = item[0], item[1], item[2]
            lines.append(f"{host}:{item_port}#{country}-DL-[{rank:02d}]:{item_port}")
    return lines


def records_to_lines(
    records: Sequence[Dict[str, Any]], view: str, purity_in_name: bool = False
) -> List[str]:
    """把 NodeRecord 渲染为旧订阅文本行。

    view：
    - `actions`：`ip:port#CC[-Pxx]-[NN]:port`（NN 为 country 内首次出现顺序）
    - `local`：`ip:port#CC[-Pxx][speed:.2fMB/S]-port`
    - `download`：`ip:port#CC-DL-[NN]:port`（每端口最多 2 条，NN 为该端口内选择序号）

    仅 `kind=direct` 记录参与；输入顺序保留；`purity_in_name=True` 时 actions/local 带 `-Pxx`。
    """
    if view not in LEGACY_VIEWS:
        raise ValueError(f"unknown view {view!r}; expected one of {LEGACY_VIEWS}")
    direct = [r for r in records if isinstance(r, dict) and r.get("kind") == "direct"]
    if view == "download":
        return _download_lines(direct)
    return _ranked_lines(direct, view, purity_in_name)