"""Structured queries against the mock company database.

The LLM never writes SQL. Requests arrive as the payload schemas from
contracts/payloads.py. Table and column names are checked against the real
schema (identifiers cannot be SQL parameters); all values are parameters.
"""

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from contracts.payloads import QueryAggregatePayload, QueryRowsPayload, UpdateRecordsPayload
from mocks.seed import SENSITIVE_COLUMNS


class DbError(ValueError):
    """Bad table/column in a request; maps to HTTP 400 or 404."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def table_from_resource(resource: str) -> str:
    prefix, _, table = resource.partition(":")
    if prefix != "db" or not table:
        raise DbError(f"resource must look like db:<table>, got {resource!r}")
    return table


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if table not in tables:
        raise DbError(f"unknown table {table!r}", status=404)
    return [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]


def _check(names, allowed: list[str], what: str) -> None:
    for name in names:
        if name not in allowed:
            raise DbError(f"unknown {what} {name!r}")


def _where(filters: dict[str, Any]) -> tuple[str, list[Any]]:
    if not filters:
        return "", []
    parts, args = [], []
    for col, value in filters.items():
        if value is None:
            parts.append(f'"{col}" IS NULL')
        else:
            parts.append(f'"{col}" = ?')
            args.append(value)
    return " WHERE " + " AND ".join(parts), args


def sensitive_in(table: str, columns) -> list[str]:
    return [c for c in columns if c in SENSITIVE_COLUMNS.get(table, ())]


def query_aggregate(db_path: Path, table: str, p: QueryAggregatePayload) -> dict:
    with closing(_connect(db_path)) as conn:
        cols = _columns(conn, table)
        _check([p.column] if p.column else [], cols, "column")
        _check(p.group_by, cols, "group_by column")
        _check(p.filters, cols, "filter column")
        target = f'"{p.column}"' if p.column else "*"
        groups = ", ".join(f'"{g}"' for g in p.group_by)
        where, args = _where(p.filters)
        select = f"{groups + ', ' if groups else ''}{p.metric.upper()}({target}) AS value"
        sql = f'SELECT {select} FROM "{table}"{where}'
        if groups:
            sql += f" GROUP BY {groups} ORDER BY {groups}"
        rows = [dict(r) for r in conn.execute(sql, args)]
    return {"rows": rows}


def query_rows(db_path: Path, table: str, p: QueryRowsPayload) -> dict:
    with closing(_connect(db_path)) as conn:
        cols = _columns(conn, table)
        _check(p.columns, cols, "column")
        _check(p.filters, cols, "filter column")
        where, args = _where(p.filters)
        select = ", ".join(f'"{c}"' for c in p.columns)
        sql = f'SELECT {select} FROM "{table}"{where} ORDER BY rowid LIMIT ?'
        rows = [dict(r) for r in conn.execute(sql, [*args, p.limit])]
    return {"rows": rows}


def update_records(db_path: Path, table: str, p: UpdateRecordsPayload) -> tuple[dict, dict]:
    """Apply the update; return (result, ground-truth details with before/after)."""
    with closing(_connect(db_path)) as conn:
        cols = _columns(conn, table)
        _check(p.filters, cols, "filter column")
        _check(p.updates, cols, "update column")
        where, args = _where(p.filters)
        rowids = [r[0] for r in conn.execute(f'SELECT rowid FROM "{table}"{where}', args)]
        marks = ",".join("?" * len(rowids))
        changed = ", ".join(f'"{c}"' for c in p.updates)

        def snapshot():
            if not rowids:
                return []
            sql = f'SELECT rowid AS _rowid, {changed} FROM "{table}" WHERE rowid IN ({marks}) ORDER BY rowid'
            return [dict(r) for r in conn.execute(sql, rowids)]

        before = snapshot()
        sets = ", ".join(f'"{c}" = ?' for c in p.updates)
        conn.execute(f'UPDATE "{table}" SET {sets}{where}', [*p.updates.values(), *args])
        conn.commit()
        after = snapshot()
    details = {"table": table, "filters": p.filters, "updates": p.updates,
               "rows_affected": len(rowids), "before": before, "after": after}
    return {"rows_affected": len(rowids)}, details
