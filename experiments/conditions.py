"""Four verification conditions for the ablation."""
import os
import re
import time
import json
import asyncio as _asyncio
from dataclasses import dataclass
from typing import Optional

from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VerificationStatus,
    RecommendedAction,
)

MODEL = "gemini/gemini-flash-lite-latest"


# -------------------------------------------------------------------------
# Shared curl-based HEADER dispatch
#
# Both C1 and C2 use this for HEADER injection points because:
#   1. httpx percent-encodes header values, breaking OGNL payloads
#   2. httpx raises on incomplete chunked reads, which Struts2 produces
#      when OGNL writes to getOutputStream() and the connection closes
#      before the response is fully streamed
# -------------------------------------------------------------------------
async def _curl_header_post(
    target_url: str,
    header_name: str,
    header_value: str,
    extra_headers: dict,
) -> tuple:
    """Send a POST with a raw header value using curl as a subprocess.

    Returns (status_code, body).
    """
    args = [
        "curl", "-s", "-i", "-X", "POST",
        target_url,
        "-H", f"{header_name}: {header_value}",
    ]
    for k, v in (extra_headers or {}).items():
        if k.lower() == header_name.lower():
            continue
        if k.lower() == "content-type":
            continue
        args.extend(["-H", f"{k}: {v}"])

    proc = await _asyncio.create_subprocess_exec(
        *args,
        stdout=_asyncio.subprocess.PIPE,
        stderr=_asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    raw = stdout.decode("utf-8", errors="replace")

    status_code = 200
    body = raw
    if raw.startswith("HTTP/"):
        parts = raw.split("\r\n\r\n", 1)
        if len(parts) == 2:
            header_block, body = parts
            first_line = header_block.split("\r\n", 1)[0]
            tokens = first_line.split()
            if len(tokens) >= 2:
                try:
                    status_code = int(tokens[1])
                except ValueError:
                    pass
    return status_code, body


def _resolve_cmd_placeholder(payload: str, replacement: str = "id") -> str:
    """
    C1 and C2 do not use arithmetic canaries. If the planner's payload
    contains the {CMD} placeholder (Red now always emits one), substitute
    a plain command so the payload actually executes.

    A real regex/LLM baseline would substitute whatever exploit command
    the operator requested. We use 'id' because its output (uid=, gid=)
    is easy for both C1 and C2 to recognise.
    """
    if "{CMD}" in payload:
        return payload.replace("{CMD}", replacement)
    return payload


def _is_raw_php_body(payload: str) -> bool:
    """CVE-2012-1823 style: the payload IS the request body, not a form field."""
    return payload.strip().startswith("<?php")


class _CurlShim:
    """Minimal response object so C1/C2 can treat curl and httpx
    responses identically. Only `.status_code` and `.text` are used."""
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


@dataclass
class VerifierResult:
    verdict: str
    rejection_code: str
    feedback: str
    response_text: Optional[str]
    latency_ms: float


# =========================================================================
# C1 — Regex baseline
# =========================================================================
class C1RegexVerifier:
    KEYWORDS = ["uid=", "root:", "gid=", "33333", "expr ", "syntax error", "system("]

    async def verify(self, claim: ExploitClaim) -> VerifierResult:
        import httpx
        payload = _resolve_cmd_placeholder(claim.candidate_payload, "id")
        headers = dict(claim.headers)
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                if claim.injection_point.value == "POST_BODY":
                    if _is_raw_php_body(payload):
                        r = await client.post(
                            claim.target_url,
                            content=payload.encode("utf-8"),
                            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                        )
                    elif "&" in payload:
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
                elif claim.injection_point.value == "HEADER":
                    sc, body_text = await _curl_header_post(
                        claim.target_url,
                        claim.parameter_name or "X-Test",
                        payload,
                        headers,
                    )
                    r = _CurlShim(status_code=sc, text=body_text)
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


# =========================================================================
# C2 — LLM-as-a-Judge baseline
# =========================================================================
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

        payload = _resolve_cmd_placeholder(claim.candidate_payload, "id")
        headers = dict(claim.headers)
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                if claim.injection_point.value == "POST_BODY":
                    if _is_raw_php_body(payload):
                        r = await client.post(
                            claim.target_url,
                            content=payload.encode("utf-8"),
                            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                        )
                    elif "&" in payload:
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
                elif claim.injection_point.value == "HEADER":
                    sc, body_text = await _curl_header_post(
                        claim.target_url,
                        claim.parameter_name or "X-Test",
                        payload,
                        headers,
                    )
                    r = _CurlShim(status_code=sc, text=body_text)
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


# =========================================================================
# C3 — Deterministic oracle (raw feedback to Red)
# =========================================================================
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


# =========================================================================
# C4 — Deterministic oracle (structured feedback to Red)
# =========================================================================
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