# PhantomGuard

[![CI](https://github.com/abdalmegedalfiky-ops/PhantomGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/abdalmegedalfiky-ops/PhantomGuard/actions/workflows/ci.yml/badge.svg) [![License](https://img.shields.io/badge/license-MIT-00D4B0)](LICENSE) [![Python](https://img.shields.io/badge/python-3.11%2B-3DA9FC)](https://www.python.org/)

AI-powered SOAR pipeline يدمج Claude API مع Elasticsearch (ELK Stack) لاكتشاف سريع
للـ alerts، تحليلها، واتخاذ قرار استجابة مناسب — مع safety-first design (dry-run افتراضي).

## Architecture

```
Elasticsearch (Kibana Security alerts)
        │
        ▼
 Collector (elastic_collector.py)
        │  normalize alert fields  [FIX: nested field lookup]
        ▼
 Enrichment (mitre_mapper.py)
        │  map keywords -> MITRE ATT&CK  [EXPANDED: +20 techniques]
        ▼
 AI Triage Engine (triage_engine.py)
        │  Claude API -> severity, classification, confidence, recommended_actions
        ▼
 Decision Engine (decision_engine.py)
        │  AUTO_EXECUTE | ESCALATE_TO_ANALYST | NO_ACTION
        ▼
 Notifications (notifications.py)  [NEW]
        │  Slack webhook لما يحصل ESCALATE_TO_ANALYST (اختياري)
        ▼
 Action Executor (executor.py)
        │  playbook YAML -> dry-run log (أو تنفيذ حقيقي لو فعّلته)
        ▼
 Report Generator (report_generator.py)
        │  Markdown + JSON report لكل alert -> output_reports/
        ▼
 State Store (state_store.py)
        SQLite + INDEX على processed_at + pruning دوري  [FIX]
```

## ليه الديزاين بالشكل ده

- **Confidence-gated automation**: مفيش action حساس (block_ip / isolate_host / disable_user)
  بيتنفذ تلقائي إلا لو الـ AI confidence ≥ 0.85 والـ severity high/critical والـ
  classification = true_positive. غير ده، بيروح لـ Analyst review.
- **DRY_RUN=true افتراضي**: أول ما تشغّل المشروع، كل الـ actions بتتسجّل في الـ log
  بس من غير تنفيذ فعلي على أي نظام حقيقي.
- **Audit trail**: كل alert بيخرج منه تقرير Markdown + JSON فيه الـ MITRE mapping،
  تحليل الـ AI الكامل، القرار، وأي خطوات تنفيذ.
- **Slack notifications**: لما يحصل ESCALATE_TO_ANALYST، بيبعت Slack message فيها
  كل التفاصيل (severity, confidence, MITRE, reasoning, suggested actions).

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# عبّي ANTHROPIC_API_KEY و ES_API_KEY (أو ES_USERNAME/ES_PASSWORD) في .env
# اختياري: أضف SLACK_WEBHOOK_URL للـ escalation notifications
```

## Usage

```bash
# يتأكد إن الإعدادات سليمة
python -m soar_ai.cli check-config

# يشغّل دورة واحدة (سحب آخر 15 دقيقة)
python -m soar_ai.cli run

# يشغّل بشكل مستمر كل POLL_INTERVAL_SECONDS
python -m soar_ai.cli run --loop

# عايز تجرب الـ UI بسرعة من غير ES/Claude حقيقيين؟
python -m soar_ai.cli seed-demo

# يشغّل الـ SOC console (Flask dashboard) على http://localhost:5000
python -m soar_ai.cli serve

# Tests
pytest tests/ -v
pytest tests/ -v --cov=soar_ai --cov-report=term-missing
```

## Dashboard (PhantomGuard Console)

- **Filtering/search**: فلترة فورية بالـ severity والـ decision outcome، وبحث نصي بدون أي round-trip للسيرفر.
- **Alert detail**: تحليل AI الكامل (summary + reasoning + classification)، MITRE ATT&CK chips، الـ decision rationale، وexecution log بستايل terminal.
- **API endpoints**: `/api/metrics` و `/api/alerts` بيرجعوا JSON للـ monitoring.
- مفيش auth دلوقتي - مصمم كـ MVP شخصي لمستخدم واحد.

## Bug Fixes (v1.1)

| # | الملف | المشكلة | الحل |
|---|-------|---------|------|
| 1 | `elastic_collector.py` | `src.get("kibana.alert.rule.name")` دايمًا بترجع None (dotted key مش nested lookup) | استبدال بـ `_dig()` في كل الحقول + flat key fallback |
| 2 | `seed_demo.py` | AUTO_EXECUTE execution_logs كانت hardcoded strings مش playbook steps حقيقية | استبدال بـ `execute_action()` الفعلي |
| 3 | `cli.py` | already_processed alerts بتتجاهل بصمت من غير عداد | إضافة `skipped_count` في الـ summary |
| 4 | `cli.py` | `execute_action result.success` مش بيتراقب | إضافة عمود "Exec OK" في الجدول + تسجيل الفشل |
| 5 | `seed_demo.py` | alert_id دايمًا demo-001..005 → re-run يكتب فوق نفس الـ reports | استخدام timestamp prefix في كل run |
| 6 | `config.py` | مفيش Slack config | إضافة `SLACK_WEBHOOK_URL` |
| 7 | `notifications.py` | مش موجود | ملف جديد: Slack webhook integration |
| 8 | `mitre_mapper.py` | keywords ناقصة (C2, mimikatz, DLL injection, etc.) | إضافة +20 technique |
| 9 | `webapp/app.py` | مفيش 500 error handler | إضافة handler + `/api/metrics` + `/api/alerts` |
| 10 | `requirements.txt` | pytest مش مضاف | إضافة pytest + pytest-cov |
| 11 | `state_store.py` | مفيش index على processed_at + DB بيكبر للأبد | إضافة INDEX + `prune_old_records()` |

## Roadmap (الخطوات الجاية)

- [ ] ربط `_REAL_HANDLERS` بـ integrations حقيقية (Firewall API / EDR / IdP)
- [ ] Basic auth للـ Flask dashboard
- [ ] دعم multi-index sources (Splunk, custom webhook) بجانب Elasticsearch
- [ ] Feedback loop: لو Analyst عدّل قرار الـ AI، يتسجّل كـ training signal
- [ ] MTTD / MTTR metrics في الـ dashboard

## Safety Note

هذا مشروع SOAR دفاعي (blue-team automation) فقط. كل الـ playbooks
(`soar_ai/playbooks/*.yaml`) عبارة عن استجابة احتوائية (containment) -
مفيش أي كود هجومي أو exploit جوه المشروع.
