"""Command-line interface for the MFA Security Assessment Tool."""
from __future__ import annotations
import argparse
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.prompt import Confirm

from . import __version__
from .analysis import AnalysisEngine
from .assessment import AssessmentEngine
from .discovery import DiscoveryModule
from .models import AssessmentResult
from .reporting import Reporter

console = Console()


def _authorized(target: str, assume_yes: bool) -> bool:
    console.print(
        "\n[bold yellow]Authorization notice[/bold yellow]\n"
        "This tool performs non-destructive security auditing. You must have "
        "explicit written permission from the owner of the target system "
        "before running any assessment.\n"
    )
    if assume_yes:
        return True
    return Confirm.ask(f"Do you have authorization to assess '{target}'?", default=False)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mfa-audit",
        description="MFA Security Assessment Tool — non-destructive auditor.",
    )
    p.add_argument("target", help="Target base URL (e.g., https://app.example.com)")
    p.add_argument("--timeout", type=int, default=10, help="Per-request timeout (s)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("--json", metavar="PATH", help="Write JSON report to PATH")
    p.add_argument("--html", metavar="PATH", help="Write HTML report to PATH")
    p.add_argument("--yes", action="store_true", help="Assume authorization (CI mode)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target.startswith(("http://", "https://")):
        console.print("[red]Target must start with http:// or https://[/red]")
        return 2
    if not _authorized(args.target, args.yes):
        console.print("[red]Authorization not confirmed. Aborting.[/red]")
        return 3

    result = AssessmentResult(
        target=args.target,
        scan_started=datetime.now(timezone.utc),
    )

    # 1) Discovery
    console.rule("[bold]Discovery Module[/bold]")
    discovery = DiscoveryModule(args.target, timeout=args.timeout,
                                verify_tls=not args.insecure)
    result.endpoints = discovery.run()
    console.print(f"Discovered {len(result.endpoints)} endpoints.")

    # 2) Assessment / Attack Engine
    console.rule("[bold]Assessment / Attack Engine[/bold]")
    engine = AssessmentEngine(args.target, timeout=args.timeout,
                              verify_tls=not args.insecure)
    result.findings = engine.run(result.endpoints)
    console.print(f"Produced {len(result.findings)} finding(s).")

    # 3) Analysis Engine
    console.rule("[bold]Analysis Engine[/bold]")
    result = AnalysisEngine().run(result)
    console.print(f"MFA Resilience Score: [bold]{result.resilience_score:.0f}[/bold] "
                  f"({result.rating})")

    result.scan_finished = datetime.now(timezone.utc)

    # 4) Reporting
    console.rule("[bold]Reporting & Dashboard[/bold]")
    reporter = Reporter(result)
    reporter.print_console()
    if args.json:
        reporter.write_json(args.json)
    if args.html:
        reporter.write_html(args.html)

    return 0


if __name__ == "__main__":
    sys.exit(main())