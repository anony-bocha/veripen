"""Four verification conditions for the ablation."""
import os
import re
import time
import json
from dataclasses import dataclass
from typing import Optional

from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VerificationStatus,
    RecommendedAction,
)

MODEL = "gemini/gemini-flash-lite-latest"


@dataclass
class VerifierResult:
    verdict: str
    rejection_code: str
    feedback: str
    response_text: Optional[str]
    latency_ms: float


class C1RegexVerifier:
    KEYWORDS = ["uid=", "root:", "gid=", "33333", "expr ", "syntax error", "system("]

    async def verify(self, claim: ExploitClaim) -> VerifierResult:
        import httpx
        payload = claim.candidate_payload
        headers = dict(claim.headers)
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                if claim.injection_point.value == "POST_BODY":
                    if "&" in payload:
                        fields = {}
                        for p in payload.split("&"):
                            if "=" in p:
                                k, v = p.split("=", 1)
                                fields[k] = v
                        r = await client.post(claim.target_url, data=fields, headers=headers)
                    else:
                        r = await client.post(
                            claim.target_url,
                            data={claim.parameter_name or "cmd": payload},
                            headers=headers,
                        )
                else:
                    headers[claim.parameter_name or "X-Test"] = payload
                    r = await client.post(claim.target_url, headers=headers)
            latency = (time.perf_counter() - start) * 1000
            body = r.text
            hit = r.status_code == 200 and any(kw in body for kw in self.KEYWORDS)
            return VerifierResult(
                verdict="VERIFIED" if hit else "REJECTED",
                rejection_code="REGEX_HIT" if hit else "REGEX_NO_HIT",
                feedback="[C1] " + ("Regex matched suspicious keyword." if hit else "No keyword found."),
                response_text=body,
                latency_ms=latency,
            )
        except Exception as e:
            return VerifierResult(
                verdict="ERROR", rejection_code="C1_ERROR",
                feedback=f"[C1] Error: {e}", response_text=None,
                latency_ms=(time.perf_counter() - start) * 1000,
            )


C2_SYSTEM_PROMPT = """You are an expert security auditor evaluating whether an attempted
penetration testing probe successfully executed on the target.

Analyze the HTTP response. Determine if the candidate exploit succeeded.

Rules:
- A framework error page (stack trace, "System Error", "Internal Server Error")
  is NOT proof of execution.
- A reflected payload string IS NOT proof of execution.
- Only mark SUCCESS if you see unambiguous evidence of command execution,
  such as process output (uid=, root:, gid=), a computed result, or
  file contents that could only come from the injected command.

Output strict JSON:
{"verdict": "SUCCESS" | "FAILURE", "confidence": 0.0-1.0, "justification": "one sentence"}
"""


class C2LLMJudgeVerifier:
    def __init__(self, model: str = MODEL):
        self.model = model

    async def verify(self, claim: ExploitClaim) -> VerifierResult:
        import httpx
        from experiments.red_agent import call_with_retry

        payload = claim.candidate_payload
        headers = dict(claim.headers)
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                if claim.injection_point.value == "POST_BODY":
                    if "&" in payload:
                        fields = {}
                        for p in payload.split("&"):
                            if "=" in p:
                                k, v = p.split("=", 1)
                                fields[k] = v
                        r = await client.post(claim.target_url, data=fields, headers=headers)
                    else:
                        r = await client.post(
                            claim.target_url,
                            data={claim.parameter_name or "cmd": payload},
                            headers=headers,
                        )
                else:
                    headers[claim.parameter_name or "X-Test"] = payload
                    r = await client.post(claim.target_url, headers=headers)
            body = r.text[:4000]
        except Exception as e:
            return VerifierResult(
                verdict="ERROR", rejection_code="C2_HTTP_ERROR",
                feedback=f"[C2] Request failed: {e}", response_text=None,
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        user_prompt = (
            f"Target: {claim.target_url}\n"
            f"Payload: {payload}\n"
            f"Status code: {r.status_code}\n"
            f"Response body (truncated):\n{body}\n"
        )
        try:
            resp = call_with_retry(
                model=self.model,
                messages=[
                    {"role": "system", "content": C2_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.0,
            )
            content = resp.choices[0].message.content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            parsed = json.loads(content)
            verdict = "VERIFIED" if parsed.get("verdict") == "SUCCESS" else "REJECTED"
            return VerifierResult(
                verdict=verdict, rejection_code="C2_LLM_JUDGE",
                feedback=f"[C2] Judge verdict={parsed.get('verdict')} "
                         f"confidence={parsed.get('confidence')} "
                         f"reason={parsed.get('justification')}",
                response_text=body,
                latency_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as e:
            return VerifierResult(
                verdict="ERROR", rejection_code="C2_LLM_ERROR",
                feedback=f"[C2] LLM judge failed: {e}",
                response_text=body,
                latency_ms=(time.perf_counter() - start) * 1000,
            )


class C3OracleRawVerifier:
    def __init__(self):
        from veripen.oracles.canary_rce import CanaryRCEOracle
        self.oracle = CanaryRCEOracle()

    async def verify(self, claim: ExploitClaim) -> VerifierResult:
        start = time.perf_counter()
        diag = await self.oracle.verify(claim)
        latency = (time.perf_counter() - start) * 1000
        verdict = (
            "VERIFIED" if diag.status == VerificationStatus.VERIFIED
            else "REJECTED" if diag.status == VerificationStatus.REJECTED
            else "ERROR"
        )
        return VerifierResult(
            verdict=verdict, rejection_code=diag.rejection_code,
            feedback=diag.raw_observation,
            response_text=diag.raw_observation,
            latency_ms=latency,
        )


class C4OracleStructuredVerifier:
    def __init__(self):
        from veripen.oracles.canary_rce import CanaryRCEOracle
        from veripen.core.feedback import FeedbackController
        self.oracle = CanaryRCEOracle()
        self.feedback_controller = FeedbackController()

    async def verify(self, claim: ExploitClaim) -> VerifierResult:
        start = time.perf_counter()
        diag = await self.oracle.verify(claim)
        latency = (time.perf_counter() - start) * 1000
        directive = self.feedback_controller.format_directive(diag)
        verdict = (
            "VERIFIED" if diag.status == VerificationStatus.VERIFIED
            else "REJECTED" if diag.status == VerificationStatus.REJECTED
            else "ERROR"
        )
        return VerifierResult(
            verdict=verdict, rejection_code=diag.rejection_code,
            feedback=directive,
            response_text=diag.raw_observation,
            latency_ms=latency,
        )


CONDITIONS = {
    "C1": C1RegexVerifier,
    "C2": C2LLMJudgeVerifier,
    "C3": C3OracleRawVerifier,
    "C4": C4OracleStructuredVerifier,
}
