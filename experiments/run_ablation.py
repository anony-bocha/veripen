"""Top-level ablation runner."""
import argparse
import asyncio
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional

from rich.console import Console
from rich.table import Table

from veripen.core.schemas import ExploitClaim, VulnerabilityType, InjectionPoint
from experiments.conditions import CONDITIONS, VerifierResult
from experiments.red_agent import AgentRed
from experiments.logger import AblationLogger

console = Console()
VULHUB_ROOT = Path("../vulhub")
TARGETS_FILE = Path("experiments/targets.json")
MAX_STEPS = 20


def compose(action: List[str], compose_path: Path) -> bool:
    cmd = ["docker", "compose", "-f", str(compose_path)] + action
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[red]docker compose failed:[/red] {e.stderr}")
        return False


def wait_healthy(url: str, timeout: int = 30) -> bool:
    import httpx
    start = time.perf_counter()
    while time.perf_counter() - start < timeout:
        try:
            httpx.get(url, timeout=2.0, verify=False)
            return True
        except Exception:
            time.sleep(1.5)
    return False


def bring_up_target(target: Dict[str, Any]) -> Optional[subprocess.Popen]:
    """Start the target. Returns a Popen handle for mock targets, None for docker."""
    if target.get("type") == "mock":
        script = Path(target["mock_script"])
        proc = subprocess.Popen(
            [sys.executable, str(script), str(target["port"])],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc
    else:
        compose_path = VULHUB_ROOT / target["compose_path"] / "docker-compose.yml"
        if not compose(["up", "-d"], compose_path):
            return None
        return None  # docker has no Popen handle


def tear_down_target(target: Dict[str, Any], proc: Optional[subprocess.Popen]) -> None:
    if target.get("type") == "mock":
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    else:
        compose_path = VULHUB_ROOT / target["compose_path"] / "docker-compose.yml"
        compose(["down", "-v"], compose_path)


async def run_trial(target, condition_name, trial_index, red, logger):
    verifier = CONDITIONS[condition_name]()
    feedback_history = []
    tokens_in_total = 0
    tokens_out_total = 0
    final_verdict = "INCONCLUSIVE"
    l_deg = 0
    seen_payloads = set()

    for step in range(1, MAX_STEPS + 1):
        try:
            claim, t_in, t_out = red.propose(
                target_url=target["url"],
                target_context=(
                    f"Language: {target['language']}. "
                    f"Vulnerability class: {target['vulnerability_type']}. "
                    f"Injection point: {target['injection_point']}."
                ),
                target_description=target["target_description"],
                feedback_history=feedback_history,
            )
        except Exception as e:
            console.print(f"[red]Red failed on step {step}:[/red] {e}")
            break

        tokens_in_total += t_in
        tokens_out_total += t_out

        result = await verifier.verify(claim)

        payload_key = claim.candidate_payload
        if result.verdict != "VERIFIED" and payload_key in seen_payloads:
            l_deg += 1
        seen_payloads.add(payload_key)

        logger.step(
            target_id=target["id"], condition=condition_name,
            trial=trial_index, step_index=step,
            claim=claim.model_dump(mode="json"),
            verdict=result.verdict, rejection_code=result.rejection_code,
            feedback=result.feedback, response_text=result.response_text,
            latency_ms=result.latency_ms,
            tokens_in=tokens_in_total, tokens_out=tokens_out_total,
        )

        feedback_history.append({
            "payload": claim.candidate_payload,
            "verdict": result.verdict,
            "rejection_code": result.rejection_code,
            "feedback": result.feedback,
        })

        if result.verdict == "VERIFIED":
            final_verdict = "VERIFIED"
            break
        if result.verdict == "ERROR":
            final_verdict = "ERROR"
            break

    return {
        "target": target["id"], "condition": condition_name,
        "trial": trial_index, "final_verdict": final_verdict,
        "steps": len(feedback_history), "l_deg": l_deg,
        "tokens_in": tokens_in_total, "tokens_out": tokens_out_total,
    }


async def run_all(targets, conditions, trials):
    run_id = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    logger = AblationLogger(run_id)
    red = AgentRed()
    summary = []

    for target in targets:
        console.rule(f"[bold cyan]Target: {target['name']}[/bold cyan]")

        for cond in conditions:
            console.print(f"[yellow]Bringing up target for {target['id']} / {cond}...[/yellow]")
            proc = bring_up_target(target)
            if target.get("type") != "mock" and proc is None and not wait_healthy(target["url"], timeout=1):
                pass  # docker path; we check health below
            time.sleep(target.get("boot_wait_seconds", 5))
            if not wait_healthy(target["url"], timeout=20):
                console.print("[yellow]Healthcheck failed; continuing anyway[/yellow]")

            for t in range(1, trials + 1):
                console.print(f"  -> trial {t}/{trials} [{cond}]")
                try:
                    result = await run_trial(target, cond, t, red, logger)
                    summary.append(result)
                except Exception as e:
                    console.print(f"[red]Trial error:[/red] {e}")

            tear_down_target(target, proc)

    logger.close()

    console.rule("[bold green]Ablation Summary[/bold green]")
    table = Table()
    table.add_column("Target")
    table.add_column("Cond")
    table.add_column("Trial")
    table.add_column("Verdict")
    table.add_column("Steps", justify="right")
    table.add_column("L_deg", justify="right")
    table.add_column("Tok_in", justify="right")
    table.add_column("Tok_out", justify="right")
    for r in summary:
        table.add_row(
            r["target"], r["condition"], str(r["trial"]),
            r["final_verdict"], str(r["steps"]), str(r["l_deg"]),
            str(r["tokens_in"]), str(r["tokens_out"]),
        )
    console.print(table)

    out = Path(f"experiments/results/summary_{run_id}.json")
    out.write_text(json.dumps(summary, indent=2))
    console.print(f"[green]Summary saved to {out}[/green]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", help="Single target id")
    ap.add_argument("--condition", help="Single condition (C1..C4)")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    targets = json.loads(TARGETS_FILE.read_text())
    if args.target:
        targets = [t for t in targets if t["id"] == args.target]

    conditions = list(CONDITIONS.keys()) if args.all else [args.condition or "C3"]

    asyncio.run(run_all(targets, conditions, args.trials))


if __name__ == "__main__":
    main()