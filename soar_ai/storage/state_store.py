"""
Storage: SQLite بسيط لتتبّع الـ alerts اللي اتعالجت قبل كده، عشان منعالجش
نفس الـ alert مرتين في كل polling cycle.
"""
from __future__ import annotations
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parent.parent.parent / "soar_state.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS processed_alerts (
            alert_id TEXT PRIMARY KEY,
            decision_outcome TEXT,
            processed_at TEXT
        )
        """
    )
    return conn


def already_processed(alert_id: str) -> bool:
    with _connect() as conn:
        row = conn.execute("SELECT 1 FROM processed_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return row is not None


def mark_processed(alert_id: str, decision_outcome: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO processed_alerts (alert_id, decision_outcome, processed_at) VALUES (?, ?, ?)",
            (alert_id, decision_outcome, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
