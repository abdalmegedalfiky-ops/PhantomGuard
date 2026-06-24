# إعداد Slack Notifications — PhantomGuard

لما يحصل `ESCALATE_TO_ANALYST`، PhantomGuard بيبعت message زي ده على Slack:

```
🚨 SOAR-AI — Analyst Escalation Required
───────────────────────────────────────
Rule        Possible Brute Force Attack Detected
Alert ID    demo-143201-001
Severity    HIGH
Confidence  91%
Host        web-prod-03
Source IP   185.220.101.7
MITRE       T1110
Reasoning   Source IP is a known Tor exit node...
```

---

## الخطوة 1 — اعمل Slack App

1. افتح: https://api.slack.com/apps
2. اضغط **"Create New App"**
3. اختر **"From scratch"**
4. اكتب اسم الـ app: `PhantomGuard`
5. اختر الـ Workspace بتاعك → اضغط **"Create App"**

---

## الخطوة 2 — فعّل Incoming Webhooks

1. في الـ sidebar اضغط **"Incoming Webhooks"**
2. حوّل الـ toggle لـ **"On"**
3. اسحب للأسفل واضغط **"Add New Webhook to Workspace"**
4. اختر الـ channel اللي عايز الـ alerts تيجي فيه (مثلاً `#soc-alerts`)
5. اضغط **"Allow"**
6. انسخ الـ **Webhook URL** — بيبدأ بـ `https://hooks.slack.com/services/...`

---

## الخطوة 3 — حط الـ URL في .env

افتح ملف `.env` في المشروع وأضف:

```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR_TEAM_ID/YOUR_APP_ID/YOUR_TOKEN
```

---

## الخطوة 4 — اتأكد إن الإعداد صح

```bash
python -m soar_ai.cli check-config
```

المفروض تشوف:
```
✅ الإعدادات سليمة.
Slack webhook: مفعّل ✓
```

---

## الخطوة 5 — اختبر بـ demo alert

```bash
python -m soar_ai.cli seed-demo
```

هتلاقي notification وصلت على الـ Slack channel — بس للـ alerts اللي قرارها `ESCALATE_TO_ANALYST`.

أو اختبر مباشرة بالـ script:

```bash
python scripts/test_slack.py
```

---

## ملاحظات

- الـ notifications بتتبعت **فقط** لـ `ESCALATE_TO_ANALYST` — مش لـ AUTO_EXECUTE أو NO_ACTION.
- لو الـ webhook فاشل (network error)، المشروع بيكمل عادي ومبيوقفش — بيسجّل warning بس.
- تقدر تعمل channel منفصل لكل severity لو عايز (محتاج تعمل أكتر من webhook).
