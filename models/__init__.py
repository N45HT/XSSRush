from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Set
import uuid

@dataclass
class ReflectionResult:
    parameter_name: str
    reflected: bool
    context: str = "unknown"
    tags: Optional[str] = None
    response_body: Optional[str] = None
    request_url: Optional[str] = None
    request_body: Optional[str] = None
    request_method: Optional[str] = None
    request_headers: Optional[Dict[str, Any]] = None
    response_headers: Optional[Dict[str, Any]] = None
    response_url: Optional[str] = None
    text: str = ""
    reflection_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class Parameter:
    param_name: str
    param_value: Optional[str] = None
    location: str = "GET"
    action_url: str = ""
    tested: bool = False
    custom_context: Optional[str] = None
    reflections: List[ReflectionResult] = field(default_factory=list)
    char_matrix: Dict[str, str] = field(default_factory=dict)
    uuid: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class XSSFinding:
    endpoint: str
    param_name: Optional[str]
    context: str
    payload_name: str
    payload_key: str
    payload_value: str
    request_method: str
    request_url: str
    request_body: Optional[str] = None
    xss: int = 0
    confidence: float = 0.0
    xs_scan: int = 0
    xs_match: int = 0
    response_url: Optional[str] = None
    request_headers: Optional[Dict[str, Any]] = None
    response_headers: Optional[Dict[str, Any]] = None
    response_body: Optional[str] = None
    text: str = ""
    created_at: str = ""
    proof_of_concept: Optional[str] = None
    finding_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class ScanConfig:
    target_url: str
    postfields: Optional[Dict[str, Any]] = None
    browser_type: str = "firefox"
    headless: bool = True
    timeout_ms: int = 15000
    delay_min: int = 3000
    delay_max: int = 5000
    verbose: bool = False
    output_file: Optional[str] = None
    scan_modules: Set[str] = field(default_factory=lambda: {"get", "post"})
    skip_headers: bool = False
    skip_paths: bool = False
    skip_fragments: bool = False
    target_params: List[str] = field(default_factory=list)
    target_param_contexts: Dict[str, str] = field(default_factory=dict)
    default_context: Optional[str] = None
    exclude_params: List[str] = field(default_factory=list)
    include_headers: List[str] = field(default_factory=list)
    exclude_headers: List[str] = field(default_factory=list)
    wordlist_path: Optional[str] = None
    wordlist_params: List[str] = field(default_factory=list)
    mining_only: bool = False
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    cookie_string: Optional[str] = None

__all__ = [
    "ReflectionResult",
    "Parameter",
    "XSSFinding",
    "ScanConfig",
]
