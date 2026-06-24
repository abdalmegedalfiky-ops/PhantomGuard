"""
Decision Engine: يحوّل نتيجة الـ AI triage لقرار تنفيذي واضح.
بيدمج بين ثقة الـ AI (confidence) وseverity وwhitelist للأكشنز المسموح
تتنفذ تلقائي، عشان مفيش action حساس يتنفذ بدون مراجعة لو الثقة مش كافية.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

from soar_ai.ai.triage_engine import TriageResult

# الأكشنز المسموح تتنفذ تلقائي (auto-execute) لو الشروط اتحققت.
AUTO_EXECUTABLE_ACTIONS = {"block_ip", "isolate_host", "disable_user"}

# عتبات القرار - عدّلها حسب سياسة SOC عندك
MIN_CONFIDENCE_FOR_AUTO = 0.85
SEVERITIES_ELIGIBLE_FOR_AUTO = {"high", "critical"}


class DecisionOutcome(str, Enum):
    AUTO_EXECUTE = "AUTO_EXECUTE"
    ESCALATE_TO_ANALYST = "ESCALATE_TO_ANALYST"
    NO_ACTION = "NO_ACTION"


@dataclass
class Decision:
    outcome: DecisionOutcome
    actions_to_execute: list[str]
    rationale: str


def decide(triage: TriageResult) -> Decision:
    if triage.classification == "false_positive" or "no_action" in triage.recommended_actions:
        return Decision(
            outcome=DecisionOutcome.NO_ACTION,
            actions_to_execute=[],
            rationale="AI صنّف الـ alert كـ false positive أو ماعندوش action مطلوب.",
        )

    auto_candidates = [a for a in triage.recommended_actions if a in AUTO_EXECUTABLE_ACTIONS]

    eligible_for_auto = (
        triage.confidence >= MIN_CONFIDENCE_FOR_AUTO
        and triage.severity in SEVERITIES_ELIGIBLE_FOR_AUTO
        and triage.classification == "true_positive"
        and len(auto_candidates) > 0
    )

    if eligible_for_auto:
        return Decision(
            outcome=DecisionOutcome.AUTO_EXECUTE,
            actions_to_execute=auto_candidates,
            rationale=(
                f"Confidence={triage.confidence:.2f} >= {MIN_CONFIDENCE_FOR_AUTO}, "
                f"severity={triage.severity} في نطاق auto-execute، classification=true_positive."
            ),
        )

    return Decision(
        outcome=DecisionOutcome.ESCALATE_TO_ANALYST,
        actions_to_execute=triage.recommended_actions,
        rationale=(
            f"الثقة أو الـ severity مش كافية للتنفيذ التلقائي "
            f"(confidence={triage.confidence:.2f}, severity={triage.severity}, "
            f"classification={triage.classification}) - يحتاج مراجعة Analyst."
        ),
    )
