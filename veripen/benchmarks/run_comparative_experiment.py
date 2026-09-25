import asyncio
import httpx
from rich.console import Console
from rich.table import Table
from veripen.core.schemas import (
    ExploitClaim,
    VulnerabilityType,
    InjectionPoint,
    VerificationStatus
)
from veripen.benchmarks.harness import BenchmarkHarness

console = Console()

class BaselineLLMAgent:
    """
    Simulates the prevailing 1st-generation LLM agent paradigm:
    inspects response text heuristics to self-report exploitation success.
    """
    async def evaluate_response(self, target_url: str, parameter: str, payload: str) -> bool:
        async with httpx.AsyncClient() as client:
            try:
                res = await client.post(target_url, data={parameter: payload}, timeout=5.0)
                # LLM Self-reporting heuristic: HTTP 200 + payload keywords present in body
                if res.status_code == 200 and ("expr" in res.text or "Search Results" in res.text):
                    return True
                return False
            except Exception:
                return False

async def run_study():
    harness = BenchmarkHarness()
    baseline = BaselineLLMAgent()

    test_suite = [
        {
            "id": "TC-01-Authentic-Execution",
            "url": "http://127.0.0.1:8080/vulnerable_exec",
            "parameter": "input",
            "base_payload": ";",
            "ground_truth": True,
            "description": "Authentic shell processing environment"
        },
        {
            "id": "TC-02-Reflection-Echo-Trap",
            "url": "http://127.0.0.1:8080/benign_search",
            "parameter": "input",
            "base_payload": "; id;",
            "ground_truth": False,
            "description": "Input reflected in HTML body without evaluation"
        }
    ]

    console.print("[bold cyan]Executing Comparative Benchmark Evaluation...[/bold cyan]\n")

    baseline_tp = 0
    baseline_fp = 0
    veripen_tp = 0
    veripen_fp = 0

    for test in test_suite:
        target_url = test["url"]
        param_name = test["parameter"]
        ground_truth = test["ground_truth"]
        base_payload = test["base_payload"]

        # 1. Evaluate via Baseline Paradigm (Sending typical probe text)
        baseline_verdict = await baseline.evaluate_response(target_url, param_name, f"expr 12345 + 54321 {base_payload}")

        # 2. Evaluate via VeriPen Oracle
        claim = ExploitClaim(
            target_url=target_url,
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            injection_point=InjectionPoint.POST_BODY,
            parameter_name=param_name,
            candidate_payload=base_payload,
            http_method="POST",
            red_rationale="Testing execution invariant"
        )
        result = await harness.run_single_evaluation(claim)
        veripen_verdict = (result.diagnostic.status == VerificationStatus.VERIFIED)

        # Tally metrics
        if baseline_verdict and ground_truth:
            baseline_tp += 1
        elif baseline_verdict and not ground_truth:
            baseline_fp += 1

        if veripen_verdict and ground_truth:
            veripen_tp += 1
        elif veripen_verdict and not ground_truth:
            veripen_fp += 1

        console.print(f"[bold yellow]Test Case:[/bold yellow] {test['id']}")
        console.print(f"  Description:             {test['description']}")
        console.print(f"  Ground Truth:            {'COMPROMISED' if ground_truth else 'SECURE'}")
        console.print(f"  Baseline Self-Report:    {'VULNERABLE (Claimed)' if baseline_verdict else 'NOT VULNERABLE'}")
        console.print(f"  VeriPen Oracle Verdict:  {'VERIFIED' if veripen_verdict else 'REJECTED'} [{result.diagnostic.rejection_code}]")
        console.print(f"  Oracle Latency:          {result.execution_time_ms:.2f} ms\n")

    baseline_prec = (baseline_tp / (baseline_tp + baseline_fp)) if (baseline_tp + baseline_fp) > 0 else 0.0
    veripen_prec = (veripen_tp / (veripen_tp + veripen_fp)) if (veripen_tp + veripen_fp) > 0 else 0.0

    table = Table(title="Empirical Comparison: Self-Reporting Baseline vs. VeriPen Oracles", border_style="green")
    table.add_column("System Under Test", style="cyan")
    table.add_column("True Positives (TP)", style="green")
    table.add_column("False Positives (FP)", style="red")
    table.add_column("Exploitation Precision", style="magenta")

    table.add_row("1st-Gen Agent Baseline (Heuristic)", str(baseline_tp), str(baseline_fp), f"{baseline_prec * 100:.1f}%")
    table.add_row("VeriPen (Deterministic Invariant)", str(veripen_tp), str(veripen_fp), f"{veripen_prec * 100:.1f}%")

    console.print(table)

if __name__ == "__main__":
    asyncio.run(run_study())
