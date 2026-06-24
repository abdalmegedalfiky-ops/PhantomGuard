from soar_ai.ai.triage_engine import TriageResult
from soar_ai.decision.decision_engine import decide, DecisionOutcome


def _triage(**overrides):
    base = dict(
        severity="high",
        classification="true_positive",
        confidence=0.9,
        summary="test",
        recommended_actions=["block_ip"],
        reasoning="test reasoning",
    )
    base.update(overrides)
    return TriageResult(**base)


def test_high_confidence_auto_executes():
    decision = decide(_triage())
    assert decision.outcome == DecisionOutcome.AUTO_EXECUTE
    assert "block_ip" in decision.actions_to_execute


def test_low_confidence_escalates():
    decision = decide(_triage(confidence=0.4))
    assert decision.outcome == DecisionOutcome.ESCALATE_TO_ANALYST


def test_false_positive_no_action():
    decision = decide(_triage(classification="false_positive", recommended_actions=["no_action"]))
    assert decision.outcome == DecisionOutcome.NO_ACTION


def test_medium_severity_escalates_even_with_high_confidence():
    decision = decide(_triage(severity="medium", confidence=0.95))
    assert decision.outcome == DecisionOutcome.ESCALATE_TO_ANALYST
