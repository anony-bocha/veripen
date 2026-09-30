import asyncio
from rich.console import Console
from veripen.core.schemas import (
    ExploitClaim, VulnerabilityType, InjectionPoint,
)
from veripen.oracles.canary_rce import CanaryRCEOracle

console = Console()

async def main():
    oracle = CanaryRCEOracle()
    claim = ExploitClaim(
        target_url="http://127.0.0.1:8081/",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        injection_point=InjectionPoint.POST_BODY,
        parameter_name="cmd",
        candidate_payload="; echo test;",
        http_method="POST",
        red_rationale="Testing echo reflection without execution"
    )
    diag = await oracle.verify(claim)
    console.print(f"[bold]Status:[/bold] {diag.status}")
    console.print(f"[bold]Rejection Code:[/bold] {diag.rejection_code}")
    console.print(f"[bold]Observation:[/bold] {diag.raw_observation}")
    console.print(f"[bold]Canary ID:[/bold] {diag.mutated_canary}")

if __name__ == "__main__":
    asyncio.run(main())
