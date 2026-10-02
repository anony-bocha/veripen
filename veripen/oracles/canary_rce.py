import secrets
import re
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
        # secrets.randbelow is rejection-sampled -> no modulo bias.
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
        # This is the ThinkPHP-style primitive:
        #   __construct&filter[]=system&method=get&server[REQUEST_METHOD]=<CMD>
        if base_payload.endswith("="):
            return f"{base_payload}{proof_cmd}"

        # Case C: shell-style concatenation (simple command injection)
        if ";" in base_payload:
            return f"{base_payload}; {proof_cmd}"
        elif "&&" in base_payload:
            return f"{base_payload} && {proof_cmd}"
        elif "|" in base_payload:
            return f"{base_payload} | {proof_cmd}"
        elif "$(" in base_payload or "`" in base_payload:
            return f"$({proof_cmd})"

        # Case D: default -- append with a separator
        return f"{base_payload}; {proof_cmd}"

    # ------------------------------------------------------------------ #
    # Payload -> form-field parsing (multi-field body support)
    # ------------------------------------------------------------------ #
    def _parse_payload_to_fields(
        self, payload: str, default_first_key: Optional[str] = None
    ) -> Dict[str, str]:
        """
        If the payload looks like a multi-field form body
        (key1=val1&key2=val2&...), split it into a dict.
        Otherwise return an empty dict (caller falls back to single-field).

        If the first segment has no '=' (e.g. the ThinkPHP template starts
        with the bare token `__construct`), it is treated as the value of
        `default_first_key` -- typically the claim's parameter_name
        (e.g. `_method`).
        """
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
            # else: malformed segment; skip
        return fields

    # ------------------------------------------------------------------ #
    # Response normalization
    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize_response(raw: str) -> str:
        """
        Normalize the response body before substring matching:
          - strip ANSI escape sequences
          - URL-decode percent-encoded sequences (one pass)
        """
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
    # HEADER injection via curl (bypasses httpx header-escaping)
    # ------------------------------------------------------------------ #
    async def _dispatch_header_via_curl(
        self,
        claim: ExploitClaim,
        canary_payload: str,
        headers: Dict[str, str],
    ) -> _CurlResponse:
        """
        Send a POST with a raw header value using curl as a subprocess.

        This bypasses httpx's header-escaping behavior, which mangles OGNL
        payloads (Struts2 S2-045) and other payloads containing special
        characters such as spaces, braces, and quotes.
        """
        import asyncio as _asyncio

        header_name = claim.parameter_name or "X-Command"
        args = [
            "curl", "-s", "-i", "-X", "POST",
            claim.target_url,
            "-H", f"{header_name}: {canary_payload}",
        ]
        # Add any additional headers from the claim (skip Content-Type and the
        # payload header itself; curl will set Content-Type from -H above).
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

        # Parse curl's raw HTTP response into a minimal shim object.
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
            # Try multi-field parsing first (ThinkPHP-style primitives).
            fields = self._parse_payload_to_fields(
                canary_payload, default_first_key=claim.parameter_name
            )
            if fields:
                return await client.post(claim.target_url, data=fields, headers=headers)
            data = {claim.parameter_name or "cmd": canary_payload}
            return await client.post(claim.target_url, data=data, headers=headers)

        if claim.injection_point == InjectionPoint.JSON_FIELD:
            json_data = {claim.parameter_name or "cmd": canary_payload}
            return await client.post(claim.target_url, json=json_data, headers=headers)

        if claim.injection_point == InjectionPoint.HEADER:
            # Use curl for raw header transmission. httpx escapes special chars.
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

        # Cache-Control headers to defeat stale responses (Assumption A1)
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

            # Word-boundary search for the sum
            sum_match = re.search(r"\b" + re.escape(expected_str) + r"\b", body)
            # Reflection search: does either nonce (as a token) appear?
            echo_x = re.search(r"\b" + re.escape(str(val1)) + r"\b", body) is not None
            echo_y = re.search(r"\b" + re.escape(str(val2)) + r"\b", body) is not None
            literal_match = literal_pattern in body
            any_echo = echo_x or echo_y or literal_match

            # --- VERIFIED ---
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

            # --- ECHO_ONLY ---
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

            # --- ABSENT ---
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