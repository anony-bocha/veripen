from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class VulnerabilityType(str, Enum):
    COMMAND_INJECTION = "CWE-78_Command_Injection"
    SQL_INJECTION = "CWE-89_SQL_Injection"
    SERVER_SIDE_REQUEST_FORGERY = "CWE-918_SSRF"
    CROSS_SITE_SCRIPTING = "CWE-79_XSS"
    PATH_TRAVERSAL = "CWE-22_Path_Traversal"

class InjectionPoint(str, Enum):
    GET_PARAM = "GET_PARAM"
    POST_BODY = "POST_BODY"
    HEADER = "HEADER"
    JSON_FIELD = "JSON_FIELD"
    URI_PATH = "URI_PATH"

class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"

class RecommendedAction(str, Enum):
    MUTATE_PAYLOAD = "MUTATE_PAYLOAD"
    BACKTRACK_BRANCH = "BACKTRACK_BRANCH"
    TRY_ALTERNATIVE_VECTOR = "TRY_ALTERNATIVE_VECTOR"
    PROCEED_POST_EXPLOIT = "PROCEED_POST_EXPLOIT"

class ExploitClaim(BaseModel):
    """
    Structured hypothesis emitted by Agent Red asserting suspected compromise.
    """
    target_url: str = Field(..., description="Target URL or endpoint being attacked")
    vulnerability_type: VulnerabilityType = Field(..., description="CWE category of the exploit")
    injection_point: InjectionPoint = Field(..., description="Where the parameter is injected")
    parameter_name: Optional[str] = Field(None, description="Vulnerable parameter name, if applicable")
    candidate_payload: str = Field(..., description="Exact payload string synthesized by Red")
    http_method: str = Field("POST", description="HTTP Method (GET, POST, PUT, etc.)")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom request headers")
    red_rationale: str = Field(..., description="Why Red believes this exploit succeeded")

class FailureDiagnostic(BaseModel):
    """
    Deterministic telemetry emitted by Agent Blue upon failed verification probe.
    """
    status: VerificationStatus = Field(..., description="VERIFIED, REJECTED, or ERROR")
    oracle_name: str = Field(..., description="Identifier of the oracle used")
    rejection_code: str = Field(..., description="Structured code (e.g. CANARY_ECHO_ONLY)")
    raw_observation: str = Field(..., description="Empirical evidence observed by Blue's probe")
    recommended_action: RecommendedAction = Field(..., description="Action directive for Red's controller")
    mutated_canary: Optional[str] = Field(None, description="Canary nonce used during test")

class VerificationResult(BaseModel):
    """
    Full audit transaction for benchmark evaluation logging.
    """
    claim: ExploitClaim
    diagnostic: FailureDiagnostic
    execution_time_ms: float
    confirmed_impact: bool
