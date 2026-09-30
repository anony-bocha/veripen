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
            return litellm.completion(model=model, messages=messages, **kwargs)
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
        resp = call_with_retry(
            model=self.model,
            messages=[
                {"role": "system", "content": RED_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=self.temperature,
        )
        raw = resp.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if not m:
                raise
            data = json.loads(m.group(0))
        claim = ExploitClaim(**data)

        usage = getattr(resp, "usage", None)
        tokens_in = getattr(usage, "prompt_tokens", 0) if usage else 0
        tokens_out = getattr(usage, "completion_tokens", 0) if usage else 0
        return claim, tokens_in, tokens_out