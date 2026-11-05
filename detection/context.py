from typing import List
from payloads.xss import XSSR_CONTEXT_MAP

def resolve_context_name(raw_context: str, location: str) -> str:
    if raw_context == "html" and location == "DOM":
        return "dom_js_html"
    elif raw_context == "unknown":
        return "dom_js_html" if location == "DOM" else "html"
    return raw_context or "html"

def get_payload_keys_for_context(context_name: str) -> List[str]:
    return XSSR_CONTEXT_MAP.get(context_name, XSSR_CONTEXT_MAP.get("html", []))
