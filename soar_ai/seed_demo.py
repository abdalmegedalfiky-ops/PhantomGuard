"""
Seed Demo: يولّد reports تجريبية (JSON + Markdown) في output_reports/ من غير
ما يحتاج اتصال حقيقي بـ Elasticsearch أو Claude API - مفيد لتجربة الـ dashboard
وعرضه بسرعة.

تشغيل: python -m soar_ai.seed_demo
"""
from __future__ import annotations
import random
from datetime import datetime, timedelta, timezone

from soar_ai.ai.triage_engine import TriageResult
from soar_ai.decision.decision_engine import decide
from soar_ai.enrichment.mitre_mapper import map_alert_to_mitre
from soar_ai.reports.report_generator import generate_report

_SCENARIOS = [
    dict(
        rule_name="Possible Brute Force Attack Detected",
        description="12 failed SSH logins from a single source within 90 seconds",
        host="web-prod-03", source_ip="185.220.101.7", destination_ip="10.0.4.21", user="root",
        severity="high", classification="true_positive", confidence=0.91,
        summary="12 failed SSH login attempts against root from a known Tor exit node within 90 seconds, no successful login.",
        recommended_actions=["block_ip", "escalate_to_analyst"],
        reasoning="Source IP is a known Tor exit node; target account is root; attempt velocity matches automated brute force.",
    ),
    dict(
        rule_name="Suspicious PowerShell Execution",
        description="Encoded PowerShell command spawned from Word process",
        host="fin-laptop-12", source_ip=None, destination_ip="91.219.x.x", user="m.hassan",
        severity="critical", classification="true_positive", confidence=0.88,
        summary="A Base64-encoded PowerShell command was launched as a child process of winword.exe, consistent with a malicious macro.",
        recommended_actions=["isolate_host", "escalate_to_analyst"],
        reasoning="Office spawning PowerShell with encoded commands is a well-known macro-malware pattern; outbound connection followed immediately.",
    ),
    dict(
        rule_name="New Local Admin Account Created",
        description="Account 'svc_backup2' created and added to Administrators group",
        host="dc-01", source_ip="10.0.1.5", destination_ip=None, user="svc_backup2",
        severity="medium", classification="needs_investigation", confidence=0.55,
        summary="A new local admin account was created outside of the normal provisioning window. No malicious activity confirmed yet.",
        recommended_actions=["escalate_to_analyst"],
        reasoning="Off-hours account creation is suspicious but matches a pattern seen during legitimate backup tooling rollouts too; insufficient certainty for auto action.",
    ),
    dict(
        rule_name="Phishing Email - Spearphishing Link Reported",
        description="User reported email with shortened link mimicking IT helpdesk",
        host=None, source_ip=None, destination_ip=None, user="r.fathy",
        severity="low", classification="false_positive", confidence=0.74,
        summary="User self-reported a suspicious email; analysis shows the link points to an internal, sanctioned helpdesk portal shortener.",
        recommended_actions=["no_action"],
        reasoning="Link destination resolved to a verified internal domain; user report was precautionary, not indicative of compromise.",
    ),
    dict(
        rule_name="Outbound Connection to Known C2 Domain",
        description="DNS query for a domain on threat-intel C2 blocklist from production host",
        host="api-gw-02", source_ip="10.0.2.40", destination_ip="45.137.x.x", user=None,
        severity="critical", classification="true_positive", confidence=0.93,
        summary="A production API gateway resolved and connected to a domain flagged on a current threat-intel C2 list.",
        recommended_actions=["isolate_host", "block_ip", "escalate_to_analyst"],
        reasoning="High-confidence threat-intel match plus an active outbound connection from a production host is a strong true-positive signal.",
    ),
]


def seed(count: int = len(_SCENARIOS)) -> None:
    now = datetime.now(timezone.utc)
    for i, scenario in enumerate(_SCENARIOS[:count]):
        mitre = map_alert_to_mitre(scenario["rule_name"], scenario["description"])
        alert_context = {
            "alert_id": f"demo-{i+1:03d}",
            "rule_name": scenario["rule_name"],
            "severity_raw": scenario["severity"],
            "description": scenario["description"],
            "host": scenario["host"],
            "source_ip": scenario["source_ip"],
            "destination_ip": scenario["destination_ip"],
            "user": scenario["user"],
            "timestamp": (now - timedelta(minutes=random.randint(1, 240))).isoformat(),
            "mitre_techniques": mitre,
        }

        triage = TriageResult(
            severity=scenario["severity"],
            classification=scenario["classification"],
            confidence=scenario["confidence"],
            summary=scenario["summary"],
            recommended_actions=scenario["recommended_actions"],
            reasoning=scenario["reasoning"],
        )

        decision = decide(triage)
        execution_logs = []
        if decision.outcome.value == "AUTO_EXECUTE":
            execution_logs = [
                "[log_intent] تسجيل نية التنفيذ قبل أي أكشن فعلي",
                f"DRY_RUN=true → مفيش تنفيذ فعلي. كان هيتنفذ: {decision.actions_to_execute}",
            ]

        path = generate_report(alert_context, triage, decision, execution_logs)
        print(f"✅ {path.name}")

    print(f"\nتم توليد {min(count, len(_SCENARIOS))} demo reports في output_reports/")
    print("شغّل: python -m soar_ai.cli serve   ثم افتح http://localhost:5000")


if __name__ == "__main__":
    seed()
