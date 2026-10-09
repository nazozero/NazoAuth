"""Source-declared model inventory; no source bodies or runtime data are emitted.

This is a review aid, not a Rust compiler or a semantic correctness certificate.
Macro definitions are reported separately: their generated types require review.
PostgreSQL mode reads only information_schema in an explicitly supplied test DB.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

from verify_static_contracts import mask_rust_non_code

IDENT = r"(?:r#)?[A-Za-z_][A-Za-z_0-9]*"
DECLARATION = re.compile(rf"\b(struct|enum|union|type)\s+({IDENT})\b")


def matching(source: str, start: int) -> int:
    closing = {"(": ")", "[": "]", "{": "}"}
    stack = [closing[source[start]]]
    for cursor in range(start + 1, len(source)):
        char = source[cursor]
        if char in closing:
            stack.append(closing[char])
        elif char in ")]}":
            if not stack or char != stack.pop():
                raise ValueError(f"unbalanced source at offset {cursor}")
            if not stack:
                return cursor
    raise ValueError(f"unterminated source at offset {start}")


def split_top(source: str, separator: str = ",") -> list[str]:
    parts, start, cursor, angle = [], 0, 0, 0
    while cursor < len(source):
        char = source[cursor]
        if char in "([{":
            cursor = matching(source, cursor)
        elif char == "<":
            angle += 1
        elif char == ">" and (cursor == 0 or source[cursor - 1] != "-"):
            angle = max(0, angle - 1)
        elif char == separator and angle == 0:
            parts.append(source[start:cursor])
            start = cursor + 1
        cursor += 1
    parts.append(source[start:])
    return [part.strip() for part in parts if part.strip()]


def strip_attributes(source: str) -> str:
    source = source.strip()
    while source.startswith("#["):
        source = source[matching(source, 1) + 1:].strip()
    return source


def fields(body: str, tuple_fields: bool = False) -> list[dict[str, str]]:
    result = []
    for item in split_top(body):
        item = strip_attributes(item)
        item = re.sub(r"^pub\b\s*(?:\([^)]*\))?\s*", "", item)
        if tuple_fields:
            name, field_type = str(len(result)), item
        else:
            match = re.match(rf"^({IDENT})\s*:(?!:)([\s\S]+)$", item)
            if match is None:
                raise ValueError(f"unrecognized field declaration: {item[:80]}")
            name, field_type = match.groups()
        result.append({"name": name, "type": re.sub(r"\s+", " ", field_type).strip()})
    return result


def declaration_shape(source: str, start: int, kind: str) -> tuple[str, int, int]:
    cursor, angle, where_clause = start, 0, False
    while cursor < len(source):
        char = source[cursor]
        if source[cursor:cursor + 5] == "where" and re.match(r"where\b", source[cursor:]):
            where_clause = True
        if char == "<":
            angle += 1
        elif char == ">" and source[cursor - 1] != "-":
            angle = max(0, angle - 1)
        elif char == "[":
            cursor = matching(source, cursor)
        elif char == "(" and (angle or kind == "type" or where_clause):
            cursor = matching(source, cursor)
        elif not angle and char in "{(;=":
            if char in "{(":
                return char, cursor, matching(source, cursor)
            if char == ";":
                return char, cursor, cursor
            if kind == "type":
                end = cursor + 1
                while end < len(source):
                    if source[end] in "([{":
                        end = matching(source, end)
                    elif source[end] == ";":
                        return char, cursor, end
                    end += 1
                raise ValueError("unterminated type alias")
        cursor += 1
    raise ValueError("unterminated type declaration")


def rust_models(source: str, path: str) -> list[dict]:
    code = mask_rust_non_code(source)
    result, occurrences = [], {}
    for match in DECLARATION.finditer(code):
        kind, name = match.groups()
        # Associated types without a concrete definition are contracts, not aliases.
        shape, start, end = declaration_shape(code, match.end(), kind)
        if kind == "type" and shape == ";":
            continue
        members = []
        if kind == "enum" and shape == "{":
            for variant in split_top(code[start + 1:end]):
                variant = strip_attributes(variant)
                head = re.match(rf"^({IDENT})", variant)
                if head is None:
                    raise ValueError(f"unrecognized variant in {name}")
                suffix = variant[head.end():].lstrip()
                if suffix.startswith(("{", "(")):
                    tail = matching(suffix, 0)
                    for field in fields(suffix[1:tail], suffix[0] == "("):
                        members.append({**field, "name": head[0] + "." + field["name"]})
                else:
                    members.append({"name": head[0], "type": "variant"})
        elif shape in "{(":
            members = fields(code[start + 1:end], shape == "(")
        elif kind == "type" and shape == "=":
            members = [{"name": "target", "type": re.sub(r"\s+", " ", code[start + 1:end]).strip()}]
        count = occurrences.get(name, 0) + 1
        occurrences[name] = count
        model_id = f"{path}::{name}" + (f"#{count}" if count > 1 else "")
        result.append({"id": model_id, "kind": kind, "line": code.count("\n", 0, match.start()) + 1, "fields": members})
    for match in re.finditer(rf"\bmacro_rules!\s*({IDENT})", code):
        result.append({"id": f"{path}::{match[1]}", "kind": "macro-definition", "line": code.count("\n", 0, match.start()) + 1, "fields": [], "review": "inspect expansions"})
    return result


def source_inventory(root: Path) -> tuple[list[dict], list[dict], int]:
    rows, errors, files = [], [], sorted(root.glob("crates/*/src/**/*.rs"))
    for path in files:
        relative = path.relative_to(root).as_posix()
        try:
            rows.extend(rust_models(path.read_text(encoding="utf-8"), relative))
        except ValueError as error:
            errors.append({"file": relative, "error": str(error)})
    return rows, errors, len(files)


def postgres_inventory() -> list[dict]:
    # DATABASE_URL is required explicitly; there is no default database or host.
    import os
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise ValueError("DATABASE_URL must name an isolated migrated test database")
    query = """SELECT json_build_object('id', 'public.' || table_name, 'kind', 'postgres-table',
        'fields', json_agg(json_build_object('name', column_name, 'type', udt_name,
        'nullable', is_nullable = 'YES') ORDER BY ordinal_position))::text
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name NOT LIKE '\\_\\_%'
        GROUP BY table_name ORDER BY table_name"""
    environment = {**os.environ, "PGDATABASE": url}
    completed = subprocess.run(["psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", query],
                               env=environment, capture_output=True, text=True, timeout=30, check=True)
    return [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--postgres", action="store_true")
    parser.add_argument("--minimum-fields", type=int, default=0)
    args = parser.parse_args()
    if args.postgres:
        rows, errors, files = postgres_inventory(), [], 0
    else:
        rows, errors, files = source_inventory(args.root)
    print(json.dumps({"summary": {"source_files": files, "models": len(rows),
                                 "fields": sum(len(row["fields"]) for row in rows),
                                 "unparsed_files": len(errors)}, "semantic_review": "not certified"}))
    for row in rows:
        if len(row["fields"]) >= args.minimum_fields:
            print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
    for error in errors:
        print(json.dumps({"unparsed": error}, ensure_ascii=False))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
