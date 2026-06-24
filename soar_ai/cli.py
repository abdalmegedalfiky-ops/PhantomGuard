"""
CLI entrypoint: soar-ai
الأوامر:
  soar-ai run                  -> يسحب alerts من ES، يحللها، يتخذ قرار، يولّد تقرير (مرة واحدة)
  soar-ai run --loop            -> يكرر نفس الحاجة كل POLL_INTERVAL_SECONDS
  soar-ai check-config          -> يتأكد إن .env متظبط صح
  soar-ai seed-demo [--count N] -> يولّد demo reports
  soar-ai serve [--port N]      -> يشغّل Flask dashboard

FIXES:
  - skipped alerts دلوقتي بتتعدّ وبتظهر في الـ summary
  - execute_action result.success دلوقتي بيتراقب وبيظهر في الجدول
  - Slack notification بتتبعت لما يحصل ESCALATE_TO_ANALYST
"""
from __future__ import annotations
import time
import click
from rich.console import Console
from rich.table import Table

from soar_ai.config import settings
from soar_ai.collectors.elastic_collector import fetch_recent_alerts, NormalizedAlert
from soar_ai.enrichment.mitre_mapper import map_alert_to_mitre
from soar_ai.ai.triage_engine import triage_alert
from soar_ai.decision.decision_engine import decide, DecisionOutcome
from soar_ai.actions.executor import execute_action
from soar_ai.reports.report_generator import generate_report
from soar_ai.storage.state_store import already_processed, mark_processed
from soar_ai.notifications import notify_escalation

console = Console()


@click.group()
def cli():
    """SOAR-AI: Security Orchestration, Automation & Response مدمج بـ Claude API."""
    pass


@cli.command()
def check_config():
    """يفحص .env ويوريك أي حاجة ناقصة."""
    problems = settings.validate()
    if not problems:
        console.print("[green]✅ الإعدادات سليمة.[/green]")
        console.print(f"DRY_RUN = {settings.dry_run}  |  Model = {settings.anthropic_model}")
        if settings.slack_webhook_url:
            console.print("[green]Slack webhook: مفعّل ✓[/green]")
        else:
            console.print("[yellow]Slack webhook: غير مفعّل (اختياري - أضف SLACK_WEBHOOK_URL في .env)[/yellow]")
    else:
        console.print("[red]❌ في مشاكل في الإعدادات:[/red]")
        for p in problems:
            console.print(f"  - {p}")


@cli.command()
@click.option("--loop", is_flag=True, help="يكرر السحب والتحليل بشكل دوري")
@click.option("--lookback", default=15, help="عدد الدقائق اللي يرجع لها في كل سحب")
def run(loop: bool, lookback: int):
    """يشغّل الـ pipeline الكامل: Collect -> Enrich -> AI Triage -> Decide -> Act -> Report."""
    problems = settings.validate()
    if problems:
        console.print("[red]الإعدادات ناقصة، شغّل: soar-ai check-config[/red]")
        return

    while True:
        _run_once(lookback_minutes=lookback)
        if not loop:
            break
        console.print(f"[dim]نايم {settings.poll_interval_seconds} ثانية قبل الدورة الجاية...[/dim]")
        time.sleep(settings.poll_interval_seconds)


def _run_once(lookback_minutes: int):
    console.rule("[bold cyan]جولة سحب جديدة[/bold cyan]")
    alerts = fetch_recent_alerts(lookback_minutes=lookback_minutes)
    console.print(f"تم سحب {len(alerts)} alert.")

    table = Table(title="نتائج المعالجة")
    table.add_column("Alert ID")
    table.add_column("Rule")
    table.add_column("Decision")
    table.add_column("Exec OK")
    table.add_column("Slack")
    table.add_column("Report")

    processed_count = 0
    skipped_count = 0

    for alert in alerts:
        if already_processed(alert.alert_id):
            skipped_count += 1
            continue
        outcome, exec_ok, slack_sent, report_name = _process_alert(alert)
        table.add_row(
            alert.alert_id,
            alert.rule_name[:55],
            outcome,
            "[green]✓[/green]" if exec_ok else "[red]✗[/red]",
            "[green]✓[/green]" if slack_sent else "[dim]—[/dim]",
            report_name,
        )
        processed_count += 1

    console.print(table)
    console.print(
        f"[dim]معالج: {processed_count} | متجاهل (سبق معالجته): {skipped_count}[/dim]"
    )


def _process_alert(alert: NormalizedAlert) -> tuple[str, bool, bool, str]:
    """
    بيرجع (outcome, exec_success, slack_sent, report_filename).
    """
    mitre = map_alert_to_mitre(alert.rule_name, alert.description)
    alert_context = {
        "alert_id": alert.alert_id,
        "rule_name": alert.rule_name,
        "severity_raw": alert.severity,
        "description": alert.description,
        "host": alert.host,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "user": alert.user,
        "timestamp": alert.timestamp,
        "mitre_techniques": mitre,
    }

    triage = triage_alert(alert_context)
    decision = decide(triage)

    execution_logs: list[str] = []
    all_exec_ok = True

    if decision.outcome == DecisionOutcome.AUTO_EXECUTE:
        for action_name in decision.actions_to_execute:
            result = execute_action(action_name, alert_context)
            execution_logs.extend(result.steps_log)
            if not result.success:
                all_exec_ok = False
                execution_logs.append(
                    f"⚠️ action '{action_name}' فاشل (success=False)"
                )

    # Slack notification لـ ESCALATE_TO_ANALYST
    slack_sent = notify_escalation(alert_context, triage, decision)

    report_path = generate_report(alert_context, triage, decision, execution_logs)
    mark_processed(alert.alert_id, decision.outcome.value)

    return decision.outcome.value, all_exec_ok, slack_sent, report_path.name


@cli.command()
@click.option("--count", default=5, help="عدد الـ demo alerts المطلوب توليدها")
def seed_demo(count: int):
    """يولّد reports تجريبية عشان تجرب الـ dashboard من غير ES/Claude حقيقيين."""
    from soar_ai.seed_demo import seed
    seed(count=count)


@cli.command()
@click.option("--port", default=5000, help="البورت اللي الداشبورد هيشتغل عليه")
@click.option("--debug/--no-debug", default=True)
def serve(port: int, debug: bool):
    """يشغّل SOAR-AI Console (Flask dashboard) على http://localhost:<port>"""
    from soar_ai.webapp.app import create_app
    app = create_app()
    console.print(f"[green]SOAR-AI Console شغّال على[/green] http://localhost:{port}")
    app.run(debug=debug, port=port)


if __name__ == "__main__":
    cli()
