"""Durable SQLite outbox for telemetry batches awaiting central acknowledgement."""
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path


def _database_path():
    configured = os.getenv("SENTINELX_QUEUE_PATH")
    if configured:
        path = Path(configured).expanduser()
    else:
        path = Path.home() / ".sentinelx" / "outbox.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def _connection():
    connection = sqlite3.connect(str(_database_path()), timeout=10)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS dead_letter_batches (
                batch_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                rejected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS pending_batches (
                batch_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        with connection:
            yield connection
    finally:
        connection.close()


def enqueue_batch(payload):
    """Persist a batch before it is sent; duplicate IDs are harmless."""
    batch_id = payload.get("batch_id")
    if not batch_id:
        raise ValueError("A batch_id is required")
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    with _connection() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO pending_batches (batch_id, payload_json) VALUES (?, ?)",
            (batch_id, encoded),
        )


def get_pending_batch():
    """Return the oldest unacknowledged batch, if one exists."""
    with _connection() as connection:
        row = connection.execute(
            "SELECT payload_json FROM pending_batches ORDER BY created_at, rowid LIMIT 1"
        ).fetchone()
    return json.loads(row[0]) if row else None


def acknowledge_batch(batch_id):
    """Remove a batch only after the central API returns a successful response."""
    with _connection() as connection:
        connection.execute(
            "DELETE FROM pending_batches WHERE batch_id = ?", (batch_id,)
        )



def reject_batch(batch_id, reason):
    """Move a permanently invalid batch to a local dead-letter table for inspection."""
    with _connection() as connection:
        row = connection.execute(
            "SELECT payload_json FROM pending_batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        if row:
            connection.execute(
                "INSERT OR REPLACE INTO dead_letter_batches (batch_id, payload_json, reason) VALUES (?, ?, ?)",
                (batch_id, row[0], str(reason)[:1000]),
            )
            connection.execute("DELETE FROM pending_batches WHERE batch_id = ?", (batch_id,))
