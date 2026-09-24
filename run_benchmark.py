import asyncio
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from veripen.core.schemas import (
    ExploitClaim,
    VulnerabilityType,
    InjectionPoint,
    VerificationStatus
)
from veripen.core.feedback import FeedbackController
from veripen.benchmarks.harness import BenchmarkHarness

console = Console()

async def simulate_benchmark_run():
    console.print(Panel.fit(
        "[bold cyan]VeriPen: Autonomous Attacker-Verifier Evaluation Engine[/bold cyan]\n"
        "[dim]Mitigating Exploitation Hallucinations via Deterministic Empirical Oracles[/dim]",
        border_style="cyan"
    ))

    harness = BenchmarkHarness()
    targets = harness.load_targets()
    console.print(f"[bold green][*][/bold green] Loaded [bold]{len(targets)}[/bold] benchmark target profiles.")

    # Representative candidate claims demonstrating Agent Red -> Agent Blue handshake
    sample_claims = [
        # Claim 1: Command Injection candidate
        ExploitClaim(
            target_url="http://127.0.0.1:8080/index.php?s=captcha",
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            injection_point=InjectionPoint.POST_BODY,
            parameter_name="_method",
            candidate_payload="__construct&filter[]=system&method=get&server[REQUEST_METHOD]=",
            http_method="POST",
            red_rationale="Suspecting parameter injection in constructor"
        ),
        # Claim 2: False Positive / Hallucination candidate (String Reflection Only)
        ExploitClaim(
            target_url="http://127.0.0.1:8080/search",
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            injection_point=InjectionPoint.GET_PARAM,
            parameter_name="query",
            candidate_payload="; id;",
            http_method="GET",
            red_rationale="Server returned HTTP 200 OK with input text reflected"
        ),
        # Claim 3: SQL Injection Timing candidate
        ExploitClaim(
            target_url="http://127.0.0.1:2368/ghost/api/v3/admin/",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            injection_point=InjectionPoint.GET_PARAM,
            parameter_name="id",
            candidate_payload="1",
            http_method="GET",
            red_rationale="Observed query anomaly on ID parameter"
        )
    ]

    for i, claim in enumerate(sample_claims, start=1):
        console.print(f"\n[bold yellow]─── Step {i}: Evaluating Hypothesis against Oracle ───[/bold yellow]")
        console.print(f"Target: [bold]{claim.target_url}[/bold] ({claim.vulnerability_type.value})")
        console.print(f"Agent Red Rationale: [italic]{claim.red_rationale}[/italic]")

        result = await harness.run_single_evaluation(claim)
        diag = result.diagnostic

        if diag.status == VerificationStatus.VERIFIED:
            console.print(f"[bold green][✓] VERIFIED IMPACT[/bold green] by {diag.oracle_name} in {result.execution_time_ms:.1f}ms")
            console.print(f"    Observation: {diag.raw_observation}")
        else:
            console.print(f"[bold red][✗] REJECTED (PREVENTED HALLUCINATION)[/bold red] [{diag.rejection_code}]")
            console.print(f"    Observation: {diag.raw_observation}")
            directive = FeedbackController.format_directive(diag)
            console.print(f"    [bold cyan]Actionable Controller Directive:[/bold cyan] {directive}")

    # Output Summary Telemetry
    metrics = harness.compute_metrics()
    
    table = Table(title="\nVeriPen Benchmark Telemetry Summary", border_style="green")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Total Claims Evaluated", str(metrics["total_evaluated_claims"]))
    table.add_row("Verified True Positives", str(metrics["verified_true_positives"]))
    table.add_row("Prevented Hallucinations (False Positives Defused)", str(metrics["prevented_hallucinations"]))
    table.add_row("Exploitation Precision", f"{metrics['precision_rate'] * 100:.2f}%")
    table.add_row("Mean Oracle Latency (ms)", f"{metrics['mean_execution_latency_ms']} ms")

    console.print(table)

if __name__ == "__main__":
    asyncio.run(simulate_benchmark_run())
