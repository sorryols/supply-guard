"""Кеш на основі SQLite: HTTP-відповіді, результати аналізу, знімки власників."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


def default_cache_dir() -> Path:
    if os.environ.get("LIBSENTINEL_CACHE"):
        p = Path(os.environ["LIBSENTINEL_CACHE"])
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
        p = Path(base) / "libsentinel"
    p.mkdir(parents=True, exist_ok=True)
    return p


class Cache:
    def __init__(self, path: Optional[Path] = None, enabled: bool = True):
        self.enabled = enabled
        self.dir = default_cache_dir()
        self.path = path or (self.dir / "cache.db")
        self._db: Optional[sqlite3.Connection] = None
        if enabled:
            self._db = sqlite3.connect(str(self.path))
            self._db.execute("CREATE TABLE IF NOT EXISTS http (key TEXT PRIMARY KEY, ts REAL, body TEXT)")
            self._db.execute("CREATE TABLE IF NOT EXISTS results (key TEXT PRIMARY KEY, ts REAL, body TEXT)")
            self._db.execute("CREATE TABLE IF NOT EXISTS owners (package TEXT, ts REAL, body TEXT)")
            self._db.commit()

    # --- HTTP ---
    def get_http(self, key: str, ttl_hours: float) -> Optional[Any]:
        if not self._db:
            return None
        row = self._db.execute("SELECT ts, body FROM http WHERE key=?", (key,)).fetchone()
        if row and time.time() - row[0] < ttl_hours * 3600:
            return json.loads(row[1])
        return None

    def put_http(self, key: str, value: Any) -> None:
        if self._db:
            self._db.execute("REPLACE INTO http VALUES (?,?,?)", (key, time.time(), json.dumps(value)))
            self._db.commit()

    # --- результати ---
    def get_result(self, key: str) -> Optional[dict]:
        if not self._db:
            return None
        row = self._db.execute("SELECT body FROM results WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put_result(self, key: str, value: dict) -> None:
        if self._db:
            self._db.execute("REPLACE INTO results VALUES (?,?,?)", (key, time.time(), json.dumps(value)))
            self._db.commit()

    # --- знімки власників (для індикатора A2) ---
    def owners_history(self, package: str) -> list:
        if not self._db:
            return []
        rows = self._db.execute("SELECT ts, body FROM owners WHERE package=? ORDER BY ts", (package.lower(),))
        return [(ts, json.loads(b)) for ts, b in rows]

    def add_owners(self, package: str, owners: list) -> None:
        if self._db:
            self._db.execute("INSERT INTO owners VALUES (?,?,?)", (package.lower(), time.time(), json.dumps(sorted(owners))))
            self._db.commit()

    def clear(self) -> None:
        if self._db:
            for t in ("http", "results", "owners"):
                self._db.execute(f"DELETE FROM {t}")
            self._db.commit()
