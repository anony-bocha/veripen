import subprocess
import time
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional
import httpx
from rich.console import Console

from veripen.benchmarks.harness import BenchmarkHarness
from veripen.core.schemas import ExploitClaim, VerificationResult

console = Console()

class VulHubRunner:
    """
    Manages the lifecycle of Docker Compose targets sequentially
    to enable benchmarking within constrained memory footprints.
    """

    def __init__(self, vulhub_root: str, harness: Optional[BenchmarkHarness] = None):
        self.vulhub_root = Path(vulhub_root)
        self.harness = harness or BenchmarkHarness()

    def _run_compose_cmd(self, target_dir: Path, action: list[str]) -> bool:
        cmd = ["docker", "compose"] + action
        try:
            result = subprocess.run(
                cmd,
                cwd=str(target_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            console.print(f"[bold red][!] Docker error in {target_dir}:[/bold red] {e}")
            return False

    async def _wait_for_port(self, host: str, port: int, timeout_sec: int = 30) -> bool:
        """Polls the HTTP endpoint until the containerized service is ready."""
        url = f"http://{host}:{port}/"
        start = time.perf_counter()
        async with httpx.AsyncClient(verify=False) as client:
            while time.perf_counter() - start < timeout_sec:
                try:
                    await client.get(url, timeout=2.0)
                    return True
                except (httpx.ConnectError, httpx.TimeoutException):
                    await asyncio.sleep(1.5)
        return False

    async def evaluate_target(self, target_meta: Dict[str, Any], candidate_claim: ExploitClaim) -> Optional[VerificationResult]:
        target_dir = self.vulhub_root / target_meta["docker_path"]
        if not target_dir.exists():
            console.print(f"[bold red][!] Directory not found:[/bold red] {target_dir}")
            return None

        console.print(f"\n[bold blue][*] Starting environment:[/bold blue] {target_meta['target_id']}")
        started = self._run_compose_cmd(target_dir, ["up", "-d"])
        if not started:
            return None

        try:
            is_ready = await self._wait_for_port("127.0.0.1", target_meta["port"], timeout_sec=25)
            if not is_ready:
                console.print(f"[yellow][!] Target failed healthcheck on port {target_meta['port']}. Skipping.[/yellow]")
                return None

            console.print(f"[green][✓] Target ready.[/green] Running VeriPen evaluation...")
            result = await self.harness.run_single_evaluation(candidate_claim)
            return result

        finally:
            console.print(f"[dim][*] Tearing down environment: {target_meta['target_id']}[/dim]")
            self._run_compose_cmd(target_dir, ["down", "-v"])
