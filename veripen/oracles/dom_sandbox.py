from playwright.async_api import async_playwright
import urllib.parse
from veripen.oracles.base_oracle import BaseOracle
from veripen.core.schemas import (
    ExploitClaim,
    FailureDiagnostic,
    VerificationStatus,
    RecommendedAction,
    InjectionPoint
)

class DOMSandboxOracle(BaseOracle):
    """
    Deterministic Verification Oracle for Client-Side Script Injection (XSS - CWE-79).
    Launches headless Playwright Chromium to verify runtime JavaScript execution.
    """

    def __init__(self, timeout_seconds: float = 8.0):
        super().__init__(oracle_name="DOMSandboxOracle", timeout_seconds=timeout_seconds)

    async def verify(self, claim: ExploitClaim) -> FailureDiagnostic:
        dialog_captured = []
        canary_alert_text = "VERIPEN_CONFIRMED"

        # Ensure payload triggers detectable dialog or window property
        test_payload = claim.candidate_payload
        if "<script>" not in test_payload and "alert" not in test_payload:
            test_payload = f"<script>alert('{canary_alert_text}')</script>"

        # Construct target URL with parameter
        parsed_url = urllib.parse.urlparse(claim.target_url)
        params = urllib.parse.parse_qs(parsed_url.query)
        params[claim.parameter_name or "q"] = [test_payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        final_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                # Event listener for JS alert/confirm/prompt
                async def handle_dialog(dialog):
                    dialog_captured.append(dialog.message)
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)

                try:
                    await page.goto(final_url, timeout=int(self.timeout_seconds * 1000), wait_until="domcontentloaded")
                    await page.wait_for_timeout(1500)
                except Exception:
                    pass
                finally:
                    await browser.close()

            if dialog_captured:
                return FailureDiagnostic(
                    status=VerificationStatus.VERIFIED,
                    oracle_name=self.oracle_name,
                    rejection_code="PROVEN_DOM_EXECUTION",
                    raw_observation=f"JavaScript dialog triggered in headless browser: {dialog_captured[0]}.",
                    recommended_action=RecommendedAction.PROCEED_POST_EXPLOIT
                )
            else:
                return FailureDiagnostic(
                    status=VerificationStatus.REJECTED,
                    oracle_name=self.oracle_name,
                    rejection_code="DOM_EXECUTION_ABSENT",
                    raw_observation="Page rendered without triggering JavaScript dialog execution (likely encoded or filtered).",
                    recommended_action=RecommendedAction.MUTATE_PAYLOAD
                )

        except Exception as e:
            return FailureDiagnostic(
                status=VerificationStatus.ERROR,
                oracle_name=self.oracle_name,
                rejection_code="DOM_SANDBOX_ERROR",
                raw_observation=f"Browser sandbox exception: {str(e)}",
                recommended_action=RecommendedAction.TRY_ALTERNATIVE_VECTOR
            )
