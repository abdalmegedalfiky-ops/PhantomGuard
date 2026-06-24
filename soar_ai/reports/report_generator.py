"""
Report Generator: يبني تقرير Markdown منظم لكل alert اتعالج، يتسجّل في output_reports/.
ده اللي بيوريك "ليه" الـ AI اتخذ القرار ده وبتاعمل audit trail.

كل تقرير بيتسجّل بنسختين:
  - .md  -> قراءة سريعة/يدوية
  - .json -> ده اللي الـ dashboard (Flask) بيقرأ منه مباشرة
"""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from soar_ai.ai.triage_engine import TriageResult
from soar_ai.decision.decision_engine import Decision

OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "output_reports"
OUTPUT_DIR.mkdir(exist_ok=True)


def generate_report(
    alert_context: dict[str, Any],
    triage: TriageResult,
    decision: Decision,
    execution_logs: list[str],
) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    alert_id = alert_context.get("alert_id", "unknown")
    base_name = f"{ts}_{alert_id}"
    filename = OUTPUT_DIR / f"{base_name}.md"
    json_filename = OUTPUT_DIR / f"{base_name}.json"

    mitre_lines = "\n".join(
        f"- `{m['technique_id']}` — {m['technique_name']}"
        for m in alert_context.get("mitre_techniques", [])
    ) or "- مفيش تطابق MITRE واضح"

    actions_lines = "\n".join(f"- {a}" for a in decision.actions_to_execute) or "- لا يوجد"
    exec_log_lines = "\n".join(f"- {line}" for line in execution_logs) or "- مفيش تنفيذ"

    content = f"""# تقرير Incident: {alert_context.get('rule_name', 'unknown')}

**Alert ID:** `{alert_id}`
**Timestamp:** {alert_context.get('timestamp')}
**Host:** {alert_context.get('host')}
**Source IP:** {alert_context.get('source_ip')}
**Destination IP:** {alert_context.get('destination_ip')}
**User:** {alert_context.get('user')}

## MITRE ATT&CK Mapping
{mitre_lines}

## تحليل AI (Claude Triage)
- **Severity:** {triage.severity}
- **Classification:** {triage.classification}
- **Confidence:** {triage.confidence:.2f}

**Summary:** {triage.summary}

**Reasoning:** {triage.reasoning}

## القرار (Decision Engine)
- **Outcome:** {decision.outcome.value}
- **Rationale:** {decision.rationale}

### Actions
{actions_lines}

## Execution Log
{exec_log_lines}
"""
    filename.write_text(content, encoding="utf-8")

    json_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert": alert_context,
        "triage": {
            "severity": triage.severity,
            "classification": triage.classification,
            "confidence": triage.confidence,
            "summary": triage.summary,
            "recommended_actions": triage.recommended_actions,
            "reasoning": triage.reasoning,
        },
        "decision": {
            "outcome": decision.outcome.value,
            "actions_to_execute": decision.actions_to_execute,
            "rationale": decision.rationale,
        },
        "execution_logs": execution_logs,
        "report_md": filename.name,
    }
    json_filename.write_text(json.dumps(json_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    return filename
