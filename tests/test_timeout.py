import asyncio
from rich.console import Console
from veripen.core.schemas import (
    ExploitClaim, VulnerabilityType, InjectionPoint,
)
from veripen.oracles.canary_rce import CanaryRCEOracle

console = Console()

async def main():
    oracle = CanaryRCEOracle(timeout_seconds=3.0)
    claim = ExploitClaim(
        target_url="http://127.0.0.1:8082/",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        injection_point=InjectionPoint.POST_BODY,
        parameter_name="cmd",
        candidate_payload="; echo test;",
        http_method="POST",
        red_rationale="Testing timeout handling"
    )
    diag = await oracle.verify(claim)
    console.print(f"[bold]Status:[/bold] {diag.status}")
    console.print(f"[bold]Rejection Code:[/bold] {diag.rejection_code}")
    console.print(f"[bold]Observation:[/bold] {diag.raw_observation}")

if __name__ == "__main__":
    asyncio.run(main())
