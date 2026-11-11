"""Dump every table's columns, row count and example rows, one file per table.

Refined from the original main.py: the connection comes from .env through
agent/db.py, and the output goes under data/ (gitignored), because example
rows hold real campus IPs.
"""
from __future__ import annotations

import logging
from pathlib import Path

from agent import db

EXCLUDED_DATABASES = {"system", "information_schema", "INFORMATION_SCHEMA"}
EXAMPLE_ROWS = 10


def _describe(table: str) -> str:
    schema = db.query(f"DESCRIBE TABLE {table}")
    rows = db.query(f"SELECT count() AS n FROM {table}")["n"].iloc[0]
    lines = [f"Table: {table}", f"Rows: {rows}", "", "Columns:"]
    width = max(len(str(n)) for n in schema["name"]) if not schema.empty else 4
    lines += [f"  {str(n):<{width}} | {t}" for n, t in zip(schema["name"], schema["type"])]
    lines += ["", "Example rows:"]
    try:
        example = db.query(f"SELECT * FROM {table} LIMIT {EXAMPLE_ROWS}")
        lines.append(example.to_string(index=False, max_colwidth=60))
    except Exception as exc:  # noqa: BLE001 - some tables refuse a bare SELECT *
        lines.append(f"(could not read example rows: {exc})")
    return "\n".join(lines) + "\n"


def dump_all(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    databases = [d for d in db.query("SHOW DATABASES")["name"] if d not in EXCLUDED_DATABASES]
    written = failed = 0
    for database in databases:
        (out_dir / database).mkdir(exist_ok=True)
        for table in db.query(f"SHOW TABLES FROM {database}")["name"]:
            try:
                (out_dir / database / f"{table}.txt").write_text(_describe(f"{database}.{table}"), encoding="utf-8")
                written += 1
            except Exception as exc:  # noqa: BLE001 - keep going past one bad table
                logging.error("Failed to dump %s.%s: %s", database, table, exc)
                failed += 1
    logging.info("%d table(s) written, %d failed", written, failed)
    return out_dir
