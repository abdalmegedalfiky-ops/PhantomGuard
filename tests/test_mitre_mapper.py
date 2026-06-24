"""Tests for MITRE mapper."""
from soar_ai.enrichment.mitre_mapper import map_alert_to_mitre


def test_brute_force_detected():
    results = map_alert_to_mitre("Brute Force SSH Attack", "")
    ids = [r["technique_id"] for r in results]
    assert "T1110" in ids


def test_powershell_detected():
    results = map_alert_to_mitre("Suspicious PowerShell Execution", "")
    ids = [r["technique_id"] for r in results]
    assert "T1059.001" in ids


def test_c2_beacon_detected():
    """C2/beacon keywords أُضيفوا في الـ fix."""
    results = map_alert_to_mitre("Outbound C2 Beacon Detected", "beacon to known c2 domain")
    ids = [r["technique_id"] for r in results]
    assert "T1071" in ids


def test_mimikatz_detected():
    """mimikatz keyword أُضيف في الـ fix."""
    results = map_alert_to_mitre("Mimikatz Execution", "lsass memory dump")
    ids = [r["technique_id"] for r in results]
    assert "T1003.001" in ids


def test_no_duplicates():
    """لو الـ technique نفسه يتطابق مع أكتر من keyword، ميتكررش."""
    results = map_alert_to_mitre("c2 beacon cobalt strike", "")
    ids = [r["technique_id"] for r in results]
    assert len(ids) == len(set(ids))


def test_no_match_returns_empty():
    results = map_alert_to_mitre("Login Success", "user logged in normally")
    assert results == []
