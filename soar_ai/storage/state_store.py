"""
Storage: SQLite بسيط لتتبّع الـ alerts اللي اتعالجت قبل كده، عشان منعالجش
نفس الـ alert مرتين في كل polling cycle.

FIXES:
  - إضافة INDEX على processed_at عشان queries الـ pruning تبقى سريعة
  - إضافة prune_old_records() عشان الـ DB ميكبرش للأبد
    (بتمسح records أقدم من N يوم، default 30)
"""
from __future__ import annotations
import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta

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
    # FIX: index على processed_at للـ pruning queries
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_processed_at
        ON processed_alerts (processed_at)
        """
    )
    conn.commit()
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


def prune_old_records(older_than_days: int = 30) -> int:
    """
    ADDED: يمسح records أقدم من older_than_days يوم.
    بيرجع عدد الـ records اللي اتمسحت.
    استدعيه دورياً (مثلاً في بداية كل polling cycle).

    مثال:
        from soar_ai.storage.state_store import prune_old_records
        deleted = prune_old_records(older_than_days=30)
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
    with _connect() as conn:
        cursor = conn.execute(
            "DELETE FROM processed_alerts WHERE processed_at < ?",
            (cutoff,),
        )
        conn.commit()
        return cursor.rowcount


def get_stats() -> dict[str, int]:
    """بيرجع stats بسيطة عن الـ DB (مفيد للـ monitoring)."""
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM processed_alerts").fetchone()[0]
        by_outcome = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT decision_outcome, COUNT(*) FROM processed_alerts GROUP BY decision_outcome"
            ).fetchall()
        }
    return {"total": total, **by_outcome}
