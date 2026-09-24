from abc import ABC, abstractmethod
import time
from veripen.core.schemas import ExploitClaim, FailureDiagnostic, VerificationResult, VerificationStatus

class BaseOracle(ABC):
    """
    Abstract interface for deterministic empirical verification oracles (Agent Blue).
    """

    def __init__(self, oracle_name: str, timeout_seconds: float = 10.0):
        self.oracle_name = oracle_name
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    async def verify(self, claim: ExploitClaim) -> FailureDiagnostic:
        """
        Executes deterministic probes against the target to prove or disprove the claim.
        """
        pass

    async def run_assessment(self, claim: ExploitClaim) -> VerificationResult:
        """
        Executes the oracle verification probe and logs telemetry metrics.
        """
        start_time = time.perf_counter()
        diagnostic = await self.verify(claim)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return VerificationResult(
            claim=claim,
            diagnostic=diagnostic,
            execution_time_ms=elapsed_ms,
            confirmed_impact=(diagnostic.status == VerificationStatus.VERIFIED)
        )
