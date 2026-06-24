"""
SOAR-AI Console: Flask app بسيط (MVP شخصي - مفيش auth دلوقتي).
يعرض الـ alerts المعالجة + تحليل الـ AI العميق + MITRE mapping لكل alert.
"""
from __future__ import annotations
from flask import Flask, render_template, abort

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

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("404.html"), 404

    return app


if __name__ == "__main__":
    create_app().run(debug=True, port=5000)
