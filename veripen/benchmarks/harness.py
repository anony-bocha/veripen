import json
from typing import List, Dict, Any
from veripen.core.schemas import ExploitClaim, VerificationResult, VerificationStatus
from veripen.agents.blue_verifier import AgentBlueVerifier

class BenchmarkHarness:
    """
    Automated evaluation harness for executing sequential benchmark targets.
    Manages claims, runs deterministic oracles, and computes metrics.
    """

    def __init__(self, registry_path: str = "veripen/benchmarks/targets_67.json"):
        self.registry_path = registry_path
        self.verifier = AgentBlueVerifier()
        self.results: List[VerificationResult] = []

    def load_targets(self) -> List[Dict[str, Any]]:
        with open(self.registry_path, "r") as f:
            return json.load(f)

    async def run_single_evaluation(self, claim: ExploitClaim) -> VerificationResult:
        """Runs the deterministic oracle on the incoming claim and captures diagnostics."""
        result = await self.verifier.evaluate_claim(claim)
        self.results.append(result)
        return result

    def compute_metrics(self) -> Dict[str, Any]:
        """Calculates Exploitation Precision and False Positive / True Positive metrics."""
        total = len(self.results)
        if total == 0:
            return {"total_tests": 0, "precision": 0.0}

        true_positives = sum(1 for r in self.results if r.confirmed_impact)
        prevented_hallucinations = sum(
            1 for r in self.results 
            if r.diagnostic.status == VerificationStatus.REJECTED
        )

        precision = (true_positives / total) if total > 0 else 0.0

        return {
            "total_evaluated_claims": total,
            "verified_true_positives": true_positives,
            "prevented_hallucinations": prevented_hallucinations,
            "precision_rate": round(precision, 4),
            "mean_execution_latency_ms": round(
                sum(r.execution_time_ms for r in self.results) / total, 2
            )
        }
