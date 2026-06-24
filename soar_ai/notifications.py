"""
Notifications: إرسال Slack webhook لما يحصل ESCALATE_TO_ANALYST.
اختياري تماماً - لو SLACK_WEBHOOK_URL مش موجود في .env، بيتجاهل بصمت.

الاستخدام:
    from soar_ai.notifications import notify_escalation
    notify_escalation(alert_context, triage, decision)
"""
from __future__ import annotations
import json
import logging
import urllib.request
import urllib.error
from typing import Any

from soar_ai.config import settings
from soar_ai.ai.triage_engine import TriageResult
from soar_ai.decision.decision_engine import Decision, DecisionOutcome

logger = logging.getLogger(__name__)

# ألوان Slack attachments حسب severity
_SEV_COLORS = {
    "critical": "#E5484D",
    "high": "#F5A623",
    "medium": "#3DA9FC",
    "low": "#6B7785",
}


def notify_escalation(
    alert_context: dict[str, Any],
    triage: TriageResult,
    decision: Decision,
) -> bool:
    """
    يبعت Slack notification لو:
    1. SLACK_WEBHOOK_URL موجود في .env
    2. decision.outcome == ESCALATE_TO_ANALYST

    بيرجع True لو الإرسال نجح، False لو فشل أو مفيش webhook.
    """
    if not settings.slack_webhook_url:
        return False
    if decision.outcome != DecisionOutcome.ESCALATE_TO_ANALYST:
        return False

    rule = alert_context.get("rule_name", "unknown")
    alert_id = alert_context.get("alert_id", "—")
    host = alert_context.get("host") or "—"
    src_ip = alert_context.get("source_ip") or "—"
    user = alert_context.get("user") or "—"
    sev = triage.severity
    color = _SEV_COLORS.get(sev, "#8A93A3")
    confidence_pct = f"{triage.confidence * 100:.0f}%"

    mitre_text = ", ".join(
        m["technique_id"] for m in alert_context.get("mitre_techniques", [])
    ) or "—"

    actions_text = "\n• ".join(decision.actions_to_execute) or "—"

    payload = {
        "text": f":rotating_light: *SOAR-AI — Analyst Escalation Required*",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "Rule", "value": rule, "short": False},
                    {"title": "Alert ID", "value": alert_id, "short": True},
                    {"title": "Severity", "value": sev.upper(), "short": True},
                    {"title": "AI Confidence", "value": confidence_pct, "short": True},
                    {"title": "Classification", "value": triage.classification, "short": True},
                    {"title": "Host", "value": host, "short": True},
                    {"title": "Source IP", "value": src_ip, "short": True},
                    {"title": "User", "value": user, "short": True},
                    {"title": "MITRE ATT&CK", "value": mitre_text, "short": True},
                    {"title": "Suggested Actions", "value": f"• {actions_text}", "short": False},
                    {"title": "AI Reasoning", "value": triage.reasoning[:300], "short": False},
                    {"title": "Rationale", "value": decision.rationale, "short": False},
                ],
                "footer": "PhantomGuard SOAR-AI",
            }
        ],
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        settings.slack_webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            ok = resp.status == 200
            if not ok:
                logger.warning("Slack webhook رجّع status %s", resp.status)
            return ok
    except urllib.error.URLError as exc:
        logger.warning("Slack webhook فشل: %s", exc)
        return False
