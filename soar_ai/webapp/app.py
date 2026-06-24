"""
SOAR-AI Console: Flask app (MVP شخصي - مفيش auth دلوقتي).
يعرض الـ alerts المعالجة + تحليل الـ AI العميق + MITRE mapping لكل alert.

ADDED:
  - 500 error handler عشان مش يبان debug page في production
  - /api/metrics endpoint بيرجع JSON للـ metrics (مفيد للـ monitoring)
  - /api/alerts endpoint بيرجع JSON list بالـ alerts
"""
from __future__ import annotations
from flask import Flask, render_template, abort, jsonify

from soar_ai.webapp.data_access import load_all_reports, load_report, compute_metrics


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def dashboard():
        reports = load_all_reports()
        metrics = compute_metrics(reports)
        return render_template("dashboard.html", reports=reports, metrics=metrics)

    @app.route("/alert/<report_id>")
    def alert_detail(report_id: str):
        report = load_report(report_id)
        if report is None:
            abort(404)
        return render_template("alert_detail.html", r=report)

    # API endpoints — مفيدين للـ monitoring وliveness checks
    @app.route("/api/metrics")
    def api_metrics():
        """يرجع الـ metrics بصيغة JSON."""
        reports = load_all_reports()
        return jsonify(compute_metrics(reports))

    @app.route("/api/alerts")
    def api_alerts():
        """يرجع الـ alerts list بصيغة JSON (بدون الـ raw field عشان ميكبرش)."""
        reports = load_all_reports()
        slim = []
        for r in reports:
            slim.append({
                "id": r.get("_id"),
                "generated_at": r.get("generated_at"),
                "rule_name": r.get("alert", {}).get("rule_name"),
                "alert_id": r.get("alert", {}).get("alert_id"),
                "severity": r.get("triage", {}).get("severity"),
                "classification": r.get("triage", {}).get("classification"),
                "confidence": r.get("triage", {}).get("confidence"),
                "outcome": r.get("decision", {}).get("outcome"),
            })
        return jsonify(slim)

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(e):
        """
        ADDED: Flask كان بيعرض debug page عند أي خطأ لو debug=False.
        دلوقتي بيرجع صفحة واضحة بدل stacktrace.
        """
        return render_template("500.html", error=str(e)), 500

    return app


if __name__ == "__main__":
    create_app().run(debug=True, port=5000)
