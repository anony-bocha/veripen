from typing import Dict
from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VerificationResult,
    VerificationStatus,
    RecommendedAction,
    VulnerabilityType
)
from veripen.oracles.base_oracle import BaseOracle
from veripen.oracles.canary_rce import CanaryRCEOracle
from veripen.oracles.oast_listener import OASTListenerOracle
from veripen.oracles.differential_sqli import DifferentialSQLiOracle
from veripen.oracles.dom_sandbox import DOMSandboxOracle

class AgentBlueVerifier:
    """
    Agent Blue: Deterministic Verification Oracle Router.
    Evaluates claims emitted by Agent Red against concrete empirical oracles.
    """

    def __init__(self, oast_host: str = "127.0.0.1", oast_port: int = 8888):
        self.oracles: Dict[VulnerabilityType, BaseOracle] = {
            VulnerabilityType.COMMAND_INJECTION: CanaryRCEOracle(),
            VulnerabilityType.SERVER_SIDE_REQUEST_FORGERY: OASTListenerOracle(listener_host=oast_host, listener_port=oast_port),
            VulnerabilityType.SQL_INJECTION: DifferentialSQLiOracle(),
            VulnerabilityType.CROSS_SITE_SCRIPTING: DOMSandboxOracle(),
        }

    async def evaluate_claim(self, claim: ExploitClaim) -> VerificationResult:
        oracle = self.oracles.get(claim.vulnerability_type)
        if not oracle:
            diagnostic = FailureDiagnostic(
                status=VerificationStatus.ERROR,
                oracle_name="OracleRouter",
                rejection_code="UNSUPPORTED_VULN_TYPE",
                raw_observation=f"No verification oracle registered for {claim.vulnerability_type.value}.",
                recommended_action=RecommendedAction.TRY_ALTERNATIVE_VECTOR
            )
            return VerificationResult(
                claim=claim,
                diagnostic=diagnostic,
                execution_time_ms=0.0,
                confirmed_impact=False
            )

        return await oracle.run_assessment(claim)
