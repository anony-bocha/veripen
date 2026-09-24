import pytest
from pydantic import ValidationError
from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VulnerabilityType,
    InjectionPoint,
    VerificationStatus,
    RecommendedAction
)

def test_exploit_claim_serialization():
    claim = ExploitClaim(
        target_url="http://127.0.0.1:8080/exec",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        injection_point=InjectionPoint.POST_BODY,
        parameter_name="cmd",
        candidate_payload="; id;",
        red_rationale="Received 200 OK with uid=0 in response"
    )
    assert claim.http_method == "POST"
    assert claim.vulnerability_type == "CWE-78_Command_Injection"

def test_invalid_claim_schema():
    with pytest.raises(ValidationError):
        ExploitClaim(
            target_url="http://127.0.0.1:8080/exec",
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            injection_point=InjectionPoint.POST_BODY,
            red_rationale="Testing invalid input"
        )

def test_failure_diagnostic_creation():
    diagnostic = FailureDiagnostic(
        status=VerificationStatus.REJECTED,
        oracle_name="CanaryRCEOracle",
        rejection_code="CANARY_ECHO_ONLY",
        raw_observation="Response body contained literal token without execution",
        recommended_action=RecommendedAction.MUTATE_PAYLOAD
    )
    assert diagnostic.status == VerificationStatus.REJECTED
