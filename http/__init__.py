from urllib.parse import urlparse
from typing import Dict, Any, Optional

def build_raw_http_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None
) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    if parsed.fragment:
        path += f"#{parsed.fragment}"

    host = parsed.netloc

    raw = [f"{method.upper()} {path} HTTP/1.1", f"Host: {host}"]
    if headers:
        for k, v in headers.items():
            raw.append(f"{k.title()}: {v}")

    raw.append("")
    if body:
        raw.append(body)

    return "\r\n".join(raw)

def build_raw_http_response(
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None
) -> str:
    raw = [f"HTTP/1.1 {status_code} OK"]
    if headers:
        for k, v in headers.items():
            raw.append(f"{k.title()}: {v}")

    raw.append("")
    if body:
        raw.append(body)

    return "\r\n".join(raw)

__all__ = [
    "build_raw_http_request",
    "build_raw_http_response",
]
