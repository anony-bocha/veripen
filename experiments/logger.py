"""Per-step JSONL logging for ablation runs."""
import json
import hashlib
import time
from pathlib import Path
from typing import Any, Dict, Optional

RESULTS_DIR = Path("experiments/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def _hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class AblationLogger:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.path = RESULTS_DIR / f"run_{run_id}.jsonl"
        self._fh = open(self.path, "a", encoding="utf-8")

    def step(
        self,
        target_id: str,
        condition: str,
        trial: int,
        step_index: int,
        claim: Dict[str, Any],
        verdict: str,
        rejection_code: str,
        feedback: str,
        response_text: Optional[str],
        latency_ms: float,
        tokens_in: int,
        tokens_out: int,
    ) -> None:
        record = {
            "run_id": self.run_id,
            "target": target_id,
            "condition": condition,
            "trial": trial,
            "step": step_index,
            "timestamp": time.time(),
            "claim": claim,
            "verdict": verdict,
            "rejection_code": rejection_code,
            "feedback": feedback,
            "feedback_tokens_est": len(feedback.split()),
            "response_hash": _hash(response_text) if response_text else None,
            "response_len": len(response_text) if response_text else 0,
            "latency_ms": latency_ms,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
        }
        self._fh.write(json.dumps(record) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()
