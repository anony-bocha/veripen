import pytest
from unittest.mock import AsyncMock, patch
from veripen.oracles.differential_sqli import DifferentialSQLiOracle
from veripen.oracles.dom_sandbox import DOMSandboxOracle
from veripen.core.schemas import ExploitClaim, VulnerabilityType, InjectionPoint, VerificationStatus

@pytest.mark.asyncio
async def test_sqli_oracle_timing_detection():
    oracle = DifferentialSQLiOracle()
    claim = ExploitClaim(
        target_url="http://mock-db.local/item",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        injection_point=InjectionPoint.GET_PARAM,
        parameter_name="id",
        candidate_payload="1",
        red_rationale="Testing timing delta"
    )

    with patch.object(oracle, "_send_probe") as mock_probe:
        base_resp = AsyncMock(text="normal", status_code=200)
        true_resp = AsyncMock(text="normal", status_code=200)
        false_resp = AsyncMock(text="normal", status_code=200)
        sleep_resp = AsyncMock(text="delayed", status_code=200)

        # Baseline fast, Sleep slow (3.1 seconds)
        mock_probe.side_effect = [
            (base_resp, 0.05),
            (true_resp, 0.05),
            (false_resp, 0.05),
            (sleep_resp, 3.1)
        ]

        diagnostic = await oracle.verify(claim)
        assert diagnostic.status == VerificationStatus.VERIFIED
        assert diagnostic.rejection_code == "PROVEN_TIMING_SQLI"

@pytest.mark.asyncio
async def test_dom_oracle_rejects_non_executing_payload():
    oracle = DOMSandboxOracle()
    claim = ExploitClaim(
        target_url="https://example.com",
        vulnerability_type=VulnerabilityType.CROSS_SITE_SCRIPTING,
        injection_point=InjectionPoint.GET_PARAM,
        parameter_name="q",
        candidate_payload="<h1>safe text</h1>",
        red_rationale="Checking XSS"
    )
    # Testing against standard domain should not fire alert dialogs
    diagnostic = await oracle.verify(claim)
    assert diagnostic.status == VerificationStatus.REJECTED
    assert diagnostic.rejection_code == "DOM_EXECUTION_ABSENT"
