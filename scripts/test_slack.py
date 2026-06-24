"""
Test Slack Webhook — PhantomGuard
يبعت test notification على Slack عشان تتأكد إن الإعداد صح.

تشغيل:
    python scripts/test_slack.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar_ai.ai.triage_engine import TriageResult
from soar_ai.decision.decision_engine import Decision, DecisionOutcome
from soar_ai.notifications import notify_escalation
from soar_ai.config import settings

def main():
    if not settings.slack_webhook_url:
        print("❌ SLACK_WEBHOOK_URL مش موجود في .env")
        print("   أضفه: SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...")
        sys.exit(1)

    print(f"✅ Webhook URL موجود: {settings.slack_webhook_url[:50]}...")
    print("⏳ بيبعت test notification...")

    alert_context = {
        "alert_id": "test-001",
        "rule_name": "🧪 PhantomGuard Test Alert",
        "host": "web-prod-03",
        "source_ip": "185.220.101.7",
        "destination_ip": "10.0.4.21",
        "user": "root",
        "timestamp": "2025-01-01T12:00:00Z",
        "mitre_techniques": [
            {"technique_id": "T1110", "technique_name": "Brute Force"},
            {"technique_id": "T1110.003", "technique_name": "Password Spraying"},
        ],
    }

    triage = TriageResult(
        severity="high",
        classification="true_positive",
        confidence=0.91,
        summary="Test alert من PhantomGuard SOAR — لو وصلك الـ message ده، الإعداد شغّال ✅",
        recommended_actions=["block_ip", "escalate_to_analyst"],
        reasoning="This is a test notification to verify Slack webhook integration.",
    )

    decision = Decision(
        outcome=DecisionOutcome.ESCALATE_TO_ANALYST,
        actions_to_execute=["block_ip", "escalate_to_analyst"],
        rationale="Test escalation — confidence=0.91 لكن severity=high يحتاج مراجعة.",
    )

    success = notify_escalation(alert_context, triage, decision)

    if success:
        print("✅ النوتيفيكيشن اتبعت بنجاح — افتح الـ Slack channel بتاعك!")
    else:
        print("❌ فشل الإرسال — تأكد من الـ webhook URL في .env")
        sys.exit(1)

if __name__ == "__main__":
    main()
