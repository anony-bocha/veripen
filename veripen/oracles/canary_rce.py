import secrets
import re
import httpx
from typing import Tuple
from veripen.oracles.base_oracle import BaseOracle
from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VerificationStatus,
    RecommendedAction,
    InjectionPoint
)

class CanaryRCEOracle(BaseOracle):
    """
    Deterministic Verification Oracle for Remote Code Execution / Command Injection.
    Eliminates echo-hallucinations via dynamic arithmetic and nonce challenges.
    """

    def __init__(self, timeout_seconds: float = 8.0):
        super().__init__(oracle_name="CanaryRCEOracle", timeout_seconds=timeout_seconds)

    def _generate_arithmetic_challenge(self) -> Tuple[int, int, int]:
        val1 = secrets.randbelow(89999) + 10000
        val2 = secrets.randbelow(89999) + 10000
        return val1, val2, val1 + val2

    def _synthesize_canary_payload(self, base_payload: str, val1: int, val2: int) -> str:
        proof_cmd = f"expr {val1} + {val2}"
        if ";" in base_payload:
            return f"; {proof_cmd};"
        elif "&&" in base_payload:
            return f" && {proof_cmd}"
        elif "|" in base_payload:
            return f" | {proof_cmd}"
        elif "$(" in base_payload or "`" in base_payload:
            return f"$({proof_cmd})"
        else:
            return f"{base_payload}; {proof_cmd}"

    async def verify(self, claim: ExploitClaim) -> FailureDiagnostic:
        val1, val2, expected_sum = self._generate_arithmetic_challenge()
        canary_payload = self._synthesize_canary_payload(claim.candidate_payload, val1, val2)
        expected_str = str(expected_sum)
        literal_pattern = f"{val1} + {val2}"

        headers = claim.headers.copy()
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, verify=False) as client:
                if claim.injection_point == InjectionPoint.GET_PARAM:
                    params = {claim.parameter_name or "cmd": canary_payload}
                    response = await client.get(claim.target_url, params=params, headers=headers)
                elif claim.injection_point == InjectionPoint.POST_BODY:
                    data = {claim.parameter_name or "cmd": canary_payload}
                    response = await client.post(claim.target_url, data=data, headers=headers)
                elif claim.injection_point == InjectionPoint.JSON_FIELD:
                    json_data = {claim.parameter_name or "cmd": canary_payload}
                    response = await client.post(claim.target_url, json=json_data, headers=headers)
                elif claim.injection_point == InjectionPoint.HEADER:
                    headers[claim.parameter_name or "X-Command"] = canary_payload
                    response = await client.post(claim.target_url, headers=headers)
                else:
                    return FailureDiagnostic(
                        status=VerificationStatus.ERROR,
                        oracle_name=self.oracle_name,
                        rejection_code="UNSUPPORTED_INJECTION_POINT",
                        raw_observation=f"Injection point {claim.injection_point} not supported by this oracle.",
                        recommended_action=RecommendedAction.TRY_ALTERNATIVE_VECTOR
                    )

            body = response.text
            sum_match = re.search(r'\b' + re.escape(expected_str) + r'\b', body)
            literal_match = literal_pattern in body

            if sum_match and not literal_match:
                return FailureDiagnostic(
                    status=VerificationStatus.VERIFIED,
                    oracle_name=self.oracle_name,
                    rejection_code="PROVEN_EXECUTION",
                    raw_observation=f"Canary proof evaluated successfully. Expected {expected_str} found in body.",
                    recommended_action=RecommendedAction.PROCEED_POST_EXPLOIT,
                    mutated_canary=str(expected_sum)
                )
            elif literal_match and not sum_match:
                return FailureDiagnostic(
                    status=VerificationStatus.REJECTED,
                    oracle_name=self.oracle_name,
                    rejection_code="CANARY_ECHO_ONLY",
                    raw_observation=f"Target reflected literal string '{literal_pattern}' without shell evaluation.",
                    recommended_action=RecommendedAction.MUTATE_PAYLOAD,
                    mutated_canary=str(expected_sum)
                )
            else:
                return FailureDiagnostic(
                    status=VerificationStatus.REJECTED,
                    oracle_name=self.oracle_name,
                    rejection_code="CANARY_ABSENT",
                    raw_observation=f"Neither execution proof ({expected_str}) nor reflection detected. HTTP Status: {response.status_code}.",
                    recommended_action=RecommendedAction.BACKTRACK_BRANCH,
                    mutated_canary=str(expected_sum)
                )

        except httpx.TimeoutException:
            return FailureDiagnostic(
                status=VerificationStatus.REJECTED,
                oracle_name=self.oracle_name,
                rejection_code="PROBE_TIMEOUT",
                raw_observation=f"Target connection timed out after {self.timeout_seconds}s.",
                recommended_action=RecommendedAction.BACKTRACK_BRANCH
            )
        except Exception as e:
            return FailureDiagnostic(
                status=VerificationStatus.ERROR,
                oracle_name=self.oracle_name,
                rejection_code="CONNECTION_FAILURE",
                raw_observation=f"Oracle network error: {str(e)}",
                recommended_action=RecommendedAction.BACKTRACK_BRANCH
            )
