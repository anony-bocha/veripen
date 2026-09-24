import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from veripen.core.feedback import FeedbackController
from veripen.agents.blue_verifier import AgentBlueVerifier
from veripen.agents.red_exploiter import AgentRedExploiter
from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VerificationStatus,
    RecommendedAction,
    VulnerabilityType,
    InjectionPoint
)

def test_feedback_controller_directives():
    diag = FailureDiagnostic(
        status=VerificationStatus.REJECTED,
        oracle_name="CanaryRCEOracle",
        rejection_code="CANARY_ECHO_ONLY",
        raw_observation="Echoed literal string without evaluation",
        recommended_action=RecommendedAction.MUTATE_PAYLOAD
    )
    directive = FeedbackController.format_directive(diag)
    assert "CANARY_ECHO_ONLY" in directive
    assert "alternative command separators" in directive

@pytest.mark.asyncio
async def test_blue_verifier_routing():
    verifier = AgentBlueVerifier()
    claim = ExploitClaim(
        target_url="[http://127.0.0.1:8080/test](http://127.0.0.1:8080/test)",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        injection_point=InjectionPoint.POST_BODY,
        parameter_name="cmd",
        candidate_payload="; id;",
        red_rationale="Testing router"
    )

    mock_diag = FailureDiagnostic(
        status=VerificationStatus.VERIFIED,
        oracle_name="CanaryRCEOracle",
        rejection_code="PROVEN_EXECUTION",
        raw_observation="Executed arithmetic proof",
        recommended_action=RecommendedAction.PROCEED_POST_EXPLOIT
    )

    with patch.object(verifier.oracles[VulnerabilityType.COMMAND_INJECTION], "verify", return_value=mock_diag):
        result = await verifier.evaluate_claim(claim)
        assert result.confirmed_impact is True
        assert result.diagnostic.oracle_name == "CanaryRCEOracle"

def test_red_exploiter_parsing():
    red = AgentRedExploiter()
    mock_payload = {
        "target_url": "[http://127.0.0.1:8080/exec](http://127.0.0.1:8080/exec)",
        "vulnerability_type": "CWE-78_Command_Injection",
        "injection_point": "POST_BODY",
        "parameter_name": "cmd",
        "candidate_payload": "; id;",
        "http_method": "POST",
        "headers": {},
        "red_rationale": "Testing parsing"
    }

    mock_resp = MagicMock()
    mock_resp.choices = [MagicMock()]
    mock_resp.choices[0].message.content = str(mock_payload).replace("'", '"')

    with patch("veripen.agents.red_exploiter.completion", return_value=mock_resp):
        claim = red.synthesize_claim("[http://127.0.0.1:8080/exec](http://127.0.0.1:8080/exec)", "Linux Apache endpoint")
        assert claim.parameter_name == "cmd"
        assert claim.vulnerability_type == VulnerabilityType.COMMAND_INJECTION
