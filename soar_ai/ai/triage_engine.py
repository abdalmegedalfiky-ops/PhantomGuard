"""
AI Triage Engine: يبعت الـ alert (بعد الـ enrichment) لـ Claude API ويرجّع تحليل
بنيوي (structured JSON): severity, classification, confidence, recommended_actions, reasoning.

ده القلب اللي يوفر "اكتشاف سريع" و"حل مقترح للمشكلة" المطلوبين في المشروع.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Any

from anthropic import Anthropic

from soar_ai.config import settings

_SYSTEM_PROMPT = """You are a SOC Tier-2 triage analyst assistant inside an automated SOAR pipeline.
You receive one security alert plus enrichment context (MITRE ATT&CK mapping).
Respond with ONLY a single JSON object, no prose, no markdown fences, matching exactly this schema:

{
  "severity": "low|medium|high|critical",
  "classification": "true_positive|false_positive|needs_investigation",
  "confidence": 0.0-1.0,
  "summary": "one paragraph plain-language summary of what happened",
  "recommended_actions": ["block_ip", "isolate_host", "disable_user", "reset_credentials", "escalate_to_analyst", "no_action"],
  "reasoning": "short chain of reasoning behind the severity/classification/action choice"
}

Rules:
- Only include actions in recommended_actions that are directly justified by the alert data given.
- If data is insufficient to be confident, set classification to "needs_investigation" and confidence below 0.6.
- Never recommend an action you cannot justify from the provided fields.
"""


@dataclass
class TriageResult:
    severity: str
    classification: str
    confidence: float
    summary: str
    recommended_actions: list[str]
    reasoning: str
    raw_response: dict[str, Any] = field(default_factory=dict)


def _client() -> Anthropic:
    if not settings.anthropic_api_key:
        raise RuntimeError("ANTHROPIC_API_KEY غير موجود - راجع .env")
    return Anthropic(api_key=settings.anthropic_api_key)


def triage_alert(alert_context: dict[str, Any]) -> TriageResult:
    """
    alert_context المتوقع يحتوي على:
    rule_name, severity (raw from ES), description, host, source_ip,
    destination_ip, user, timestamp, mitre_techniques (list)
    """
    user_prompt = "Alert + enrichment context (JSON):\n" + json.dumps(alert_context, ensure_ascii=False, indent=2)

    client = _client()
    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=1024,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    text_blocks = [b.text for b in response.content if getattr(b, "type", None) == "text"]
    raw_text = "\n".join(text_blocks).strip()
    raw_text = raw_text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"AI رجّع رد غير JSON صالح: {raw_text[:300]}") from exc

    return TriageResult(
        severity=parsed.get("severity", "medium"),
        classification=parsed.get("classification", "needs_investigation"),
        confidence=float(parsed.get("confidence", 0.0)),
        summary=parsed.get("summary", ""),
        recommended_actions=parsed.get("recommended_actions", []),
        reasoning=parsed.get("reasoning", ""),
        raw_response=parsed,
    )
