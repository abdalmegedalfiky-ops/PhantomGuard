"""
Data access layer للـ dashboard: يقرأ ملفات output_reports/*.json (اللي بيكتبها
report_generator.py) ويرجّعها بشكل جاهز للعرض. مفيش database إضافي - الملفات نفسها
هي مصدر الحقيقة (audit trail = UI source).
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "output_reports"


def load_all_reports() -> list[dict[str, Any]]:
    """يرجّع كل التقارير، الأحدث أولاً."""
    if not OUTPUT_DIR.exists():
        return []
    reports = []
    for path in sorted(OUTPUT_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            data["_id"] = path.stem
            reports.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def load_report(report_id: str) -> dict[str, Any] | None:
    path = OUTPUT_DIR / f"{report_id}.json"
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    data["_id"] = report_id
    return data


def compute_metrics(reports: list[dict[str, Any]]) -> dict[str, Any]:
    if not reports:
        return {"total": 0, "by_severity": {}, "by_decision": {}, "avg_confidence": 0.0}

    by_severity: dict[str, int] = {}
    by_decision: dict[str, int] = {}
    confidences = []

    for r in reports:
        sev = r.get("triage", {}).get("severity", "unknown")
        dec = r.get("decision", {}).get("outcome", "unknown")
        conf = r.get("triage", {}).get("confidence", 0.0)
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_decision[dec] = by_decision.get(dec, 0) + 1
        confidences.append(conf)

    return {
        "total": len(reports),
        "by_severity": by_severity,
        "by_decision": by_decision,
        "avg_confidence": sum(confidences) / len(confidences) if confidences else 0.0,
    }
