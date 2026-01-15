import sqlite3
from pathlib import Path
from typing import Optional, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
  sha256 TEXT PRIMARY KEY,
  file_path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256 TEXT NOT NULL,
  service TEXT NOT NULL,
  external_id TEXT NOT NULL,
  status TEXT NOT NULL,
  error TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  UNIQUE(sha256, service),
  FOREIGN KEY (sha256) REFERENCES files(sha256)
);

CREATE TRIGGER IF NOT EXISTS submissions_updated_at
AFTER UPDATE ON submissions
BEGIN
  UPDATE submissions SET updated_at = datetime('now') WHERE id = NEW.id;
END;
"""

class DB:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(SCHEMA)

    def upsert_file(self, sha256: str, file_path: str) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO files(sha256, file_path) VALUES(?, ?) "
                "ON CONFLICT(sha256) DO UPDATE SET file_path=excluded.file_path",
                (sha256, file_path),
            )

    def upsert_submission(self, sha256: str, service: str, external_id: str, status: str, error: Optional[str]=None) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO submissions(sha256, service, external_id, status, error) VALUES(?, ?, ?, ?, ?) "
                "ON CONFLICT(sha256, service) DO UPDATE SET external_id=excluded.external_id, status=excluded.status, error=excluded.error",
                (sha256, service, external_id, status, error),
            )

    def update_status(self, sha256: str, service: str, status: str, error: Optional[str]=None) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE submissions SET status=?, error=? WHERE sha256=? AND service=?",
                (status, error, sha256, service),
            )

    def list_submissions(self) -> Iterable[sqlite3.Row]:
        with self._conn() as c:
            return c.execute("SELECT * FROM submissions ORDER BY updated_at DESC").fetchall()

    def get_submission(self, sha256: str, service: str) -> Optional[sqlite3.Row]:
        with self._conn() as c:
            return c.execute(
                "SELECT * FROM submissions WHERE sha256=? AND service=?",
                (sha256, service),
            ).fetchone()

    def list_sha256s(self) -> list[str]:
        with self._conn() as c:
            rows = c.execute("SELECT DISTINCT sha256 FROM submissions ORDER BY updated_at DESC").fetchall()
            return [r["sha256"] for r in rows]
    def list_completed_sha256s(self) -> list[str]:
        with self._conn() as c:
            rows = c.execute(
                """
                SELECT DISTINCT sha256
                FROM submissions
                WHERE status = 'COMPLETED'
                ORDER BY updated_at DESC
                """
            ).fetchall()
            return [r["sha256"] for r in rows]

