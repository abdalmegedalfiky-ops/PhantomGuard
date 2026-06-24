"""Tests for state store."""
import os
import tempfile
from pathlib import Path
import pytest

# Override DB path للـ tests عشان منلخبطش الـ production DB
import soar_ai.storage.state_store as ss


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """كل test يشتغل على DB مؤقت منفصل."""
    test_db = tmp_path / "test_soar.db"
    monkeypatch.setattr(ss, "DB_PATH", test_db)
    yield test_db


def test_mark_and_check():
    ss.mark_processed("alert-001", "AUTO_EXECUTE")
    assert ss.already_processed("alert-001") is True


def test_unknown_alert_not_processed():
    assert ss.already_processed("nonexistent-id") is False


def test_prune_old_records():
    """prune_old_records بيمسح القديم ويسيب الجديد."""
    from datetime import datetime, timezone, timedelta

    # ضيف record قديمة جداً يدوياً
    conn = ss._connect()
    old_date = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    conn.execute(
        "INSERT INTO processed_alerts VALUES (?, ?, ?)",
        ("old-alert", "NO_ACTION", old_date),
    )
    conn.commit()

    # ضيف واحدة جديدة
    ss.mark_processed("new-alert", "AUTO_EXECUTE")

    deleted = ss.prune_old_records(older_than_days=30)
    assert deleted == 1
    assert ss.already_processed("old-alert") is False
    assert ss.already_processed("new-alert") is True


def test_get_stats():
    ss.mark_processed("a1", "AUTO_EXECUTE")
    ss.mark_processed("a2", "AUTO_EXECUTE")
    ss.mark_processed("a3", "ESCALATE_TO_ANALYST")
    stats = ss.get_stats()
    assert stats["total"] == 3
    assert stats.get("AUTO_EXECUTE") == 2
