from typing import Dict, Any
from veripen.core.schemas import FailureDiagnostic, VerificationStatus, RecommendedAction

class FeedbackController:
    """
    Translates empirical oracle diagnostics into structured refinement directives.
    """

    @staticmethod
    def format_directive(diagnostic: FailureDiagnostic) -> str:
        """
        Builds a high-priority prompt directive based on the oracle's findings.
        """
        if diagnostic.status == VerificationStatus.VERIFIED:
            return (
                "[STATUS: VERIFIED] The security test confirmed genuine impact. "
                "Do not re-test this vector. Record this finding and proceed to the next objective."
            )

        action_guidance: Dict[str, str] = {
            "CANARY_ECHO_ONLY": (
                "The target only reflected the payload string without execution. "
                "Try alternative command separators or context termination (e.g. quotes or backticks)."
            ),
            "CANARY_ABSENT": (
                "Neither the proof nor reflection was observed. "
                "The current parameter appears non-vulnerable or input is blocked. Switch parameters or endpoints."
            ),
            "OAST_TIMEOUT": (
                "No out-of-band interaction was detected within the timeout window. "
                "Outbound egress may be restricted or the input is not reaching external network calls. Backtrack."
            ),
            "SQLI_INVARIANT_STATIC": (
                "Boolean and timing invariants showed no response divergence. "
                "The query logic was not altered. Mutate quotes/delimiters or test another parameter."
            ),
            "DOM_EXECUTION_ABSENT": (
                "The input was rendered without executing client-side scripts (likely filtered or sanitized). "
                "Try alternate event handlers or evaluate context boundaries."
            ),
        }

        specific_advice = action_guidance.get(
            diagnostic.rejection_code,
            "The candidate hypothesis was rejected. Formulate an alternative approach."
        )

        return (
            f"[VERIFICATION FAILED: {diagnostic.rejection_code}]\n"
            f"Observation: {diagnostic.raw_observation}\n"
            f"Required Action: {diagnostic.recommended_action.value}\n"
            f"Guidance: {specific_advice}"
        )
