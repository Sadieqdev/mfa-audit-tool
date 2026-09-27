"""Reporting & Dashboard: console, JSON, and HTML report generation."""
from __future__ import annotations
import html
import json
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from .models import AssessmentResult, Severity

TEMPLATE_DIR = Path(__file__).parent / "templates"
SEV_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}


class Reporter:
    def __init__(self, result: AssessmentResult):
        self.result = result
        self.console = Console()

    # ---- console ----
    def print_console(self) -> None:
        r = self.result
        self.console.print()
        self.console.print(Panel.fit(
            f"[bold]MFA Security Assessment Report[/bold]\n"
            f"Target: {r.target}\n"
            f"MFA Resilience Score: [bold]{r.resilience_score:.0f}/100[/bold] "
            f"({r.rating})",
            border_style="green",
        ))

        table = Table(title="Findings", box=box.SIMPLE_HEAVY)
        table.add_column("ID", style="bold")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Compliance")
        for f in sorted(r.findings, key=lambda x: list(Severity).index(x.severity)):
            table.add_row(
                f.check_id,
                f"[{SEV_COLOR[f.severity]}]{f.severity.value}[/]",
                f.title,
                (f.nist_ref or "") + ("\n" + f.owasp_ref if f.owasp_ref else ""),
            )
        self.console.print(table)

        breakdown = r.metadata.get("severity_breakdown", {})
        self.console.print(
            "[bold]Severity breakdown:[/bold] "
            + ", ".join(f"{k}: {v}" for k, v in breakdown.items())
        )

    # ---- JSON ----
    def write_json(self, path: str) -> None:
        data = {
            "target": self.result.target,
            "resilience_score": self.result.resilience_score,
            "rating": self.result.rating,
            "scan_started": self.result.scan_started.isoformat(),
            "scan_finished": (
                self.result.scan_finished.isoformat()
                if self.result.scan_finished else None
            ),
            "severity_breakdown": self.result.metadata.get("severity_breakdown"),
            "findings": [f.to_dict() for f in self.result.findings],
            "endpoints": [
                {
                    "url": e.url, "status": e.status_code,
                    "auth_type": e.auth_type, "mfa_indicators": e.mfa_indicators,
                }
                for e in self.result.endpoints
            ],
        }
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.console.print(f"[green]JSON report written to {path}[/green]")

    # ---- HTML ----
    def write_html(self, path: str) -> None:
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        tpl = env.get_template("report.html.j2")
        html = tpl.render(
            r=self.result,
            findings=[f.to_dict() for f in self.result.findings],
        )
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(html, encoding="utf-8")
        self.console.print(f"[green]HTML report written to {path}[/green]")