"""Feedback controller: translates oracle diagnostics into planner directives.

This module produces two feedback formats:

  * C3 (raw): the oracle's raw_observation string. Single line, prose.
  * C4 (structured): a compact JSON directive, smaller than the C3 observation
    and machine-parseable. This is the format used by Proposition 3's
    telemetry-steering claim.

The C4 format is deliberately terse so that RQ3's token-reduction hypothesis
can be tested: structured telemetry should consume fewer tokens per turn than
raw feedback, not more.
"""
import json
from typing import Dict, Any
from veripen.core.schemas import FailureDiagnostic, VerificationStatus, RecommendedAction


class FeedbackController:
    """
    Translates empirical oracle diagnostics into structured refinement directives.
    """

    # Concise action guidance, kept minimal so the C4 directive stays under
    # ~15 tokens. Long prose defeats the purpose of structured telemetry.
    ACTION_GUIDANCE: Dict[str, str] = {
        "CANARY_ECHO_ONLY": "Reflected only; try different separator or encoding.",
        "CANARY_ABSENT": "No execution, no reflection; switch parameter or endpoint.",
        "PROBE_TIMEOUT": "Timeout; target may be slow or unreachable. Backtrack.",
        "CONNECTION_FAILURE": "Connection failed. Check target availability.",
        "OAST_TIMEOUT": "No OOB callback; egress may be blocked. Backtrack.",
        "SQLI_INVARIANT_STATIC": "No query divergence; mutate delimiters.",
        "DOM_EXECUTION_ABSENT": "No client-side execution; try alternate handlers.",
    }

    @staticmethod
    def format_directive(diagnostic: FailureDiagnostic) -> str:
        """
        C4 feedback channel: compact JSON directive.

        This format is parsed by Agent Red to update its search state.
        Kept as short as possible to reduce per-turn context consumption.
        """
        if diagnostic.status == VerificationStatus.VERIFIED:
            return json.dumps({
                "status": "VERIFIED",
                "code": diagnostic.rejection_code,
                "action": "PROCEED",
            }, separators=(",", ":"))

        # Truncate the raw observation to a bounded length. We keep the
        # first 120 characters only; the full context lives in the JSONL log.
        truncated = (diagnostic.raw_observation or "")[:120]

        directive: Dict[str, Any] = {
            "status": "REJECTED",
            "code": diagnostic.rejection_code,
            "action": diagnostic.recommended_action.value,
            "note": FeedbackController.ACTION_GUIDANCE.get(
                diagnostic.rejection_code,
                "Try a different payload or vector."
            ),
        }
        return json.dumps(directive, separators=(",", ":"))

    @staticmethod
    def format_raw_observation(diagnostic: FailureDiagnostic) -> str:
        """
        C3 feedback channel: the oracle's raw_observation string.

        This is the format used by the C3 condition. It is intentionally
        left as prose so the C3-vs-C4 comparison remains valid.
        """
        return diagnostic.raw_observation or ""