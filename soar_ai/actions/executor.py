"""
Executor: يقرأ playbook YAML وينفذ خطواته.
DRY_RUN=true (الافتراضي) = يسجّل بس النية (intended action) من غير أي تنفيذ فعلي
على أي نظام حقيقي. وده مهم جدًا لحد ما تربط integrations حقيقية (firewall/EDR/IdP)
وتتأكد إنها مضبوطة صح.

لما تكون جاهز تفعّل تنفيذ حقيقي: زوّد دالة فعلية في _REAL_HANDLERS بدل الـ placeholder.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
import yaml

from soar_ai.config import settings

PLAYBOOK_DIR = Path(__file__).resolve().parent.parent / "playbooks"


@dataclass
class ExecutionResult:
    action: str
    dry_run: bool
    steps_log: list[str]
    success: bool


def _load_playbook(action_name: str) -> dict[str, Any]:
    path = PLAYBOOK_DIR / f"{action_name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"مفيش playbook لـ action='{action_name}' في {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# هنا تحط التكامل الحقيقي بتاعك لاحقاً (مثال: استدعاء API الفايروول الفعلي)
_REAL_HANDLERS: dict[str, Callable[[dict[str, Any]], bool]] = {
    # "block_ip": my_firewall_integration.block,
    # "isolate_host": my_edr_integration.isolate,
    # "disable_user": my_idp_integration.disable,
}


def execute_action(action_name: str, alert_fields: dict[str, Any]) -> ExecutionResult:
    playbook = _load_playbook(action_name)
    steps_log: list[str] = []

    missing = [f for f in playbook.get("required_fields", []) if not alert_fields.get(f)]
    if missing:
        steps_log.append(f"⚠️ ناقص حقول مطلوبة: {missing} - الـ action متوقّف.")
        return ExecutionResult(action=action_name, dry_run=settings.dry_run, steps_log=steps_log, success=False)

    for step in playbook.get("steps", []):
        steps_log.append(f"[{step['step']}] {step['detail']}")

    if settings.dry_run:
        steps_log.append(f"DRY_RUN=true → مفيش تنفيذ فعلي. الـ action '{action_name}' كان هيتنفذ على: {alert_fields}")
        return ExecutionResult(action=action_name, dry_run=True, steps_log=steps_log, success=True)

    handler = _REAL_HANDLERS.get(action_name)
    if handler is None:
        steps_log.append(f"❌ مفيش real handler متسجل لـ '{action_name}' - رجوع لـ dry-run تلقائياً.")
        return ExecutionResult(action=action_name, dry_run=True, steps_log=steps_log, success=False)

    success = handler(alert_fields)
    steps_log.append(f"✅ تم تنفيذ '{action_name}' فعلياً - success={success}")
    return ExecutionResult(action=action_name, dry_run=False, steps_log=steps_log, success=success)
