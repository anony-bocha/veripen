import pytest
from unittest.mock import AsyncMock, patch
from veripen.oracles.canary_rce import CanaryRCEOracle
from veripen.core.schemas import (
    ExploitClaim,
    VulnerabilityType,
    InjectionPoint,
    VerificationStatus,
    RecommendedAction
)

@pytest.mark.asyncio
async def test_canary_oracle_detects_echo_hallucination():
    oracle = CanaryRCEOracle()
    claim = ExploitClaim(
        target_url="http://mock-target.local/vuln",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        injection_point=InjectionPoint.POST_BODY,
        parameter_name="input",
        candidate_payload="; id;",
        red_rationale="Agent Red claims 200 OK confirms compromise"
    )

    with patch("httpx.AsyncClient.post") as mock_post:
        val1, val2 = 12345, 67890
        oracle._generate_arithmetic_challenge = lambda: (val1, val2, val1 + val2)
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = f"<html><body>Search results for: ; expr {val1} + {val2};</body></html>"
        mock_post.return_value = mock_response

        diagnostic = await oracle.verify(claim)
        
        assert diagnostic.status == VerificationStatus.REJECTED
        assert diagnostic.rejection_code == "CANARY_ECHO_ONLY"
        assert diagnostic.recommended_action == RecommendedAction.MUTATE_PAYLOAD

@pytest.mark.asyncio
async def test_canary_oracle_confirms_genuine_execution():
    oracle = CanaryRCEOracle()
    claim = ExploitClaim(
        target_url="http://mock-target.local/vuln",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        injection_point=InjectionPoint.POST_BODY,
        parameter_name="cmd",
        candidate_payload="; id;",
        red_rationale="Checking execution"
    )

    with patch("httpx.AsyncClient.post") as mock_post:
        val1, val2 = 11111, 22222
        expected_sum = val1 + val2
        oracle._generate_arithmetic_challenge = lambda: (val1, val2, expected_sum)
        
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = f"uid=0(root) gid=0(root)\n{expected_sum}\n"
        mock_post.return_value = mock_response

        diagnostic = await oracle.verify(claim)
        
        assert diagnostic.status == VerificationStatus.VERIFIED
        assert diagnostic.rejection_code == "PROVEN_EXECUTION"
        assert diagnostic.recommended_action == RecommendedAction.PROCEED_POST_EXPLOIT
