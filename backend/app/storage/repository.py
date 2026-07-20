"""Object persistence behind a single narrow interface.

The walking skeleton ships two interchangeable backends:
- ``InMemoryRepository`` for tests and the demo.
- ``SqliteRepository`` for the API server (durable, zero external services).

The production target is PostgreSQL. Keeping every read/write behind this
interface is what lets that swap happen without touching the pipeline.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable, Protocol

from pydantic import BaseModel


def _dump(obj: BaseModel) -> str:
    return obj.model_dump_json()


class Repository(Protocol):
    def save(self, collection: str, obj_id: str, obj: BaseModel) -> None: ...
    def get(self, collection: str, obj_id: str) -> dict[str, Any] | None: ...
    def list(self, collection: str) -> list[dict[str, Any]]: ...


class InMemoryRepository:
    def __init__(self) -> None:
        self._data: dict[str, dict[str, dict[str, Any]]] = {}

    def save(self, collection: str, obj_id: str, obj: BaseModel) -> None:
        self._data.setdefault(collection, {})[obj_id] = json.loads(_dump(obj))

    def get(self, collection: str, obj_id: str) -> dict[str, Any] | None:
        return self._data.get(collection, {}).get(obj_id)

    def list(self, collection: str) -> list[dict[str, Any]]:
        return list(self._data.get(collection, {}).values())


class SqliteRepository:
    """One row per object: (collection, id) -> JSON document."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS objects (
                collection TEXT NOT NULL,
                obj_id     TEXT NOT NULL,
                document   TEXT NOT NULL,
                PRIMARY KEY (collection, obj_id)
            )
            """
        )
        self._conn.commit()

    def save(self, collection: str, obj_id: str, obj: BaseModel) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO objects (collection, obj_id, document) VALUES (?, ?, ?)",
            (collection, obj_id, _dump(obj)),
        )
        self._conn.commit()

    def get(self, collection: str, obj_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT document FROM objects WHERE collection = ? AND obj_id = ?",
            (collection, obj_id),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, collection: str) -> list[dict[str, Any]]:
        rows: Iterable[tuple[str]] = self._conn.execute(
            "SELECT document FROM objects WHERE collection = ? ORDER BY obj_id",
            (collection,),
        ).fetchall()
        return [json.loads(r[0]) for r in rows]
