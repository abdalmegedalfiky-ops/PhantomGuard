"""
Centralized configuration loader for SOAR-AI.
يقرأ كل القيم من البيئة (.env) — مفيش أي secret مكتوب هنا.

ADDED: SLACK_WEBHOOK_URL لإرسال notifications لما يحصل ESCALATE_TO_ANALYST.
"""
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


def _bool(env_val: str | None, default: bool = False) -> bool:
    if env_val is None:
        return default
    return env_val.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # Elasticsearch
    es_host: str = os.getenv("ES_HOST", "https://localhost:9200")
    es_api_key: str | None = os.getenv("ES_API_KEY") or None
    es_username: str | None = os.getenv("ES_USERNAME") or None
    es_password: str | None = os.getenv("ES_PASSWORD") or None
    es_verify_certs: bool = _bool(os.getenv("ES_VERIFY_CERTS"), default=False)
    es_alert_index: str = os.getenv("ES_ALERT_INDEX", ".alerts-security.alerts-default")

    # Anthropic
    anthropic_api_key: str | None = os.getenv("ANTHROPIC_API_KEY") or None
    anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

    # Safety
    dry_run: bool = _bool(os.getenv("DRY_RUN"), default=True)

    # Polling
    poll_interval_seconds: int = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))

    # Notifications — اختياري. لو موجود، بيبعت Slack message لما يحصل ESCALATE_TO_ANALYST
    slack_webhook_url: str | None = os.getenv("SLACK_WEBHOOK_URL") or None

    def validate(self) -> list[str]:
        """Returns a list of missing/invalid config problems (empty = OK)."""
        problems = []
        if not self.anthropic_api_key:
            problems.append("ANTHROPIC_API_KEY غير موجود في .env")
        if not self.es_api_key and not (self.es_username and self.es_password):
            problems.append("لازم ES_API_KEY أو ES_USERNAME+ES_PASSWORD")
        return problems


settings = Settings()
