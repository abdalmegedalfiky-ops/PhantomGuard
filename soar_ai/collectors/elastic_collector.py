"""
Collector: يسحب alerts جديدة من Elasticsearch/Kibana Security alerts index.
بيرجع شكل موحّد (normalized) عشان باقي الـ pipeline (enrichment/AI/decision) ميهمهوش
شكل الـ raw document الأصلي.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from elasticsearch import Elasticsearch

from soar_ai.config import settings


@dataclass
class NormalizedAlert:
    alert_id: str
    rule_name: str
    severity: str          # low | medium | high | critical
    description: str
    host: str | None
    source_ip: str | None
    destination_ip: str | None
    user: str | None
    timestamp: str
    raw: dict[str, Any] = field(default_factory=dict)


def get_client() -> Elasticsearch:
    kwargs: dict[str, Any] = {"hosts": [settings.es_host], "verify_certs": settings.es_verify_certs}
    if settings.es_api_key:
        kwargs["api_key"] = settings.es_api_key
    elif settings.es_username and settings.es_password:
        kwargs["basic_auth"] = (settings.es_username, settings.es_password)
    return Elasticsearch(**kwargs)


def fetch_recent_alerts(lookback_minutes: int = 15, max_alerts: int = 50) -> list[NormalizedAlert]:
    """
    يسحب alerts من آخر lookback_minutes دقيقة.
    Query افتراضي مبني على حقول Kibana Security Detection alerts (kibana.alert.*).
    عدّل الحقول لو الـ index/mapping عندك مختلف.
    """
    es = get_client()
    since = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()

    query = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since}}},
                ]
            }
        },
        "sort": [{"@timestamp": "desc"}],
        "size": max_alerts,
    }

    resp = es.search(index=settings.es_alert_index, body=query)
    hits = resp.get("hits", {}).get("hits", [])

    alerts: list[NormalizedAlert] = []
    for hit in hits:
        src = hit.get("_source", {})
        alerts.append(_normalize(hit["_id"], src))
    return alerts


def _normalize(doc_id: str, src: dict[str, Any]) -> NormalizedAlert:
    """يطبّع حقول Kibana Security alert الشائعة. عدّل المسارات لو عندك schema مخصص."""
    kibana_alert = src.get("kibana.alert", {}) if isinstance(src.get("kibana.alert"), dict) else {}

    return NormalizedAlert(
        alert_id=doc_id,
        rule_name=src.get("kibana.alert.rule.name") or kibana_alert.get("rule", {}).get("name", "unknown_rule"),
        severity=(src.get("kibana.alert.severity") or "medium").lower(),
        description=src.get("kibana.alert.reason") or src.get("message", ""),
        host=_dig(src, "host.name"),
        source_ip=_dig(src, "source.ip"),
        destination_ip=_dig(src, "destination.ip"),
        user=_dig(src, "user.name"),
        timestamp=src.get("@timestamp", datetime.now(timezone.utc).isoformat()),
        raw=src,
    )


def _dig(d: dict[str, Any], dotted_path: str) -> str | None:
    cur: Any = d
    for part in dotted_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur if isinstance(cur, str) else None
