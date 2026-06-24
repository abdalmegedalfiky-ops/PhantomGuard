"""Tests for Slack notifications module.
Note: Settings هو frozen dataclass، فـ patch.object مش بيشتغل عليه.
بدلاً منه بنعمل mock على الـ `settings` reference جوا الـ notifications module.
"""
from unittest.mock import patch, MagicMock
from soar_ai.ai.triage_engine import TriageResult
from soar_ai.decision.decision_engine import Decision, DecisionOutcome
import soar_ai.notifications as notif_module


def _make_triage(**kw):
    defaults = dict(
        severity="high", classification="true_positive", confidence=0.9,
        summary="test", recommended_actions=["escalate_to_analyst"], reasoning="r",
    )
    defaults.update(kw)
    return TriageResult(**defaults)


def _make_decision(outcome, actions=None):
    return Decision(
        outcome=outcome,
        actions_to_execute=actions or [],
        rationale="test rationale",
    )


def _mock_settings(webhook_url):
    """بيرجع mock settings بـ slack_webhook_url محدد."""
    m = MagicMock()
    m.slack_webhook_url = webhook_url
    return m


def test_no_webhook_returns_false():
    """لو SLACK_WEBHOOK_URL مش موجود → False."""
    with patch.object(notif_module, "settings", _mock_settings(None)):
        result = notif_module.notify_escalation(
            {"alert_id": "x", "rule_name": "test", "mitre_techniques": []},
            _make_triage(),
            _make_decision(DecisionOutcome.ESCALATE_TO_ANALYST),
        )
    assert result is False


def test_non_escalate_returns_false():
    """لو القرار مش ESCALATE → مبيبعتش حاجة."""
    with patch.object(notif_module, "settings", _mock_settings("https://hooks.slack.com/fake")):
        result = notif_module.notify_escalation(
            {"alert_id": "x", "rule_name": "test", "mitre_techniques": []},
            _make_triage(),
            _make_decision(DecisionOutcome.AUTO_EXECUTE),
        )
    assert result is False


def test_escalate_with_webhook_sends():
    """لو SLACK_WEBHOOK_URL موجود والقرار ESCALATE → بيبعت HTTP request."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch.object(notif_module, "settings", _mock_settings("https://hooks.slack.com/fake")):
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = notif_module.notify_escalation(
                {"alert_id": "x", "rule_name": "Brute Force", "host": "h1",
                 "source_ip": "1.2.3.4", "user": "admin", "mitre_techniques": []},
                _make_triage(),
                _make_decision(DecisionOutcome.ESCALATE_TO_ANALYST, ["escalate_to_analyst"]),
            )
    assert result is True
