import pytest
from veripen.benchmarks.harness import BenchmarkHarness
from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VerificationResult,
    VerificationStatus,
    RecommendedAction,
    VulnerabilityType,
    InjectionPoint
)

def test_benchmark_metrics_computation():
    harness = BenchmarkHarness()

    claim = ExploitClaim(
        target_url="http://127.0.0.1:8080/test",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        injection_point=InjectionPoint.POST_BODY,
        parameter_name="cmd",
        candidate_payload="; id;",
        red_rationale="Claiming RCE"
    )

    # 1. Add a Verified Result (True Positive)
    diag_verified = FailureDiagnostic(
        status=VerificationStatus.VERIFIED,
        oracle_name="CanaryRCEOracle",
        rejection_code="PROVEN_EXECUTION",
        raw_observation="Arithmetic verified",
        recommended_action=RecommendedAction.PROCEED_POST_EXPLOIT
    )
    harness.results.append(VerificationResult(
        claim=claim,
        diagnostic=diag_verified,
        execution_time_ms=120.0,
        confirmed_impact=True
    ))

    # 2. Add a Rejected Result (Prevented Hallucination)
    diag_rejected = FailureDiagnostic(
        status=VerificationStatus.REJECTED,
        oracle_name="CanaryRCEOracle",
        rejection_code="CANARY_ECHO_ONLY",
        raw_observation="Reflected literal string",
        recommended_action=RecommendedAction.MUTATE_PAYLOAD
    )
    harness.results.append(VerificationResult(
        claim=claim,
        diagnostic=diag_rejected,
        execution_time_ms=80.0,
        confirmed_impact=False
    ))

    metrics = harness.compute_metrics()
    assert metrics["total_evaluated_claims"] == 2
    assert metrics["verified_true_positives"] == 1
    assert metrics["prevented_hallucinations"] == 1
    assert metrics["precision_rate"] == 0.5
    assert metrics["mean_execution_latency_ms"] == 100.0
