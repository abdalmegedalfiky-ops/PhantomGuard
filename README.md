# PhantomGuard

![CI](https://github.com/abdalmegedalfiky-ops/PhantomGuard/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-00D4B0)
![Python](https://img.shields.io/badge/python-3.11%2B-3DA9FC)

AI-powered SOAR pipeline يدمج Claude API مع Elasticsearch (ELK Stack) لاكتشاف سريع
للـ alerts، تحليلها، واتخاذ قرار استجابة مناسب — مع safety-first design (dry-run افتراضي).

## Architecture

```
Elasticsearch (Kibana Security alerts)
        │
        ▼
 Collector (elastic_collector.py)
        │  normalize alert fields
        ▼
 Enrichment (mitre_mapper.py)
        │  map keywords -> MITRE ATT&CK technique IDs
        ▼
 AI Triage Engine (triage_engine.py)
        │  Claude API -> severity, classification, confidence, recommended_actions
        ▼
 Decision Engine (decision_engine.py)
        │  AUTO_EXECUTE | ESCALATE_TO_ANALYST | NO_ACTION
        ▼
 Action Executor (executor.py)
        │  playbook YAML -> dry-run log (أو تنفيذ حقيقي لو فعّلته)
        ▼
 Report Generator (report_generator.py)
        │  Markdown report لكل alert -> output_reports/
        ▼
 State Store (state_store.py)
        SQLite لتفادي إعادة معالجة نفس الـ alert
```

## ليه الديزاين بالشكل ده

- **Confidence-gated automation**: مفيش action حساس (block_ip / isolate_host / disable_user)
  بيتنفذ تلقائي إلا لو الـ AI confidence ≥ 0.85 والـ severity high/critical والـ
  classification = true_positive. غير ده، بيروح لـ Analyst review.
- **DRY_RUN=true افتراضي**: أول ما تشغّل المشروع، كل الـ actions بتتسجّل في الـ log
  بس من غير تنفيذ فعلي على أي نظام حقيقي. لما تبني integrations حقيقية
  (firewall/EDR/IdP) في `soar_ai/actions/executor.py` (`_REAL_HANDLERS`)، تقدر تحوّل
  DRY_RUN=false بثقة.
- **Audit trail**: كل alert بيخرج منه تقرير Markdown فيه الـ MITRE mapping، تحليل
  الـ AI الكامل، القرار، وأي خطوات تنفيذ - عشان أي مراجعة لاحقة (أو compliance).

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# عبّي ANTHROPIC_API_KEY و ES_API_KEY (أو ES_USERNAME/ES_PASSWORD) في .env
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
```

## Dashboard (PhantomGuard Console)

- **Filtering/search**: فلترة فورية بالـ severity والـ decision outcome، وبحث نصي بدون أي round-trip للسيرفر.
- **Alert detail**: تحليل AI الكامل (summary + reasoning + classification)، MITRE ATT&CK chips، الـ decision rationale، وexecution log بستايل terminal.
- مفيش auth دلوقتي - مصمم كـ MVP شخصي لمستخدم واحد.

## Roadmap (الخطوات الجاية)

- [ ] ربط `_REAL_HANDLERS` بـ integrations حقيقية (Firewall API / EDR / IdP)
- [ ] دعم Slack/Teams notification لما يحصل ESCALATE_TO_ANALYST
- [ ] Dashboard خفيف (Flask/FastAPI) لعرض الـ reports بدل قراية Markdown يدوي
- [ ] دعم multi-index sources (Splunk, custom webhook) بجانب Elasticsearch
- [ ] Feedback loop: لو Analyst عدّل قرار الـ AI، يتسجّل كـ training signal

## Safety Note

هذا مشروع SOAR دفاعي (blue-team automation) فقط. كل الـ playbooks
(`soar_ai/playbooks/*.yaml`) عبارة عن استجابة احتوائية (containment) -
مفيش أي كود هجومي أو exploit جوه المشروع.
