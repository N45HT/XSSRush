import random
import string
import time
import re
import asyncio
import html
import base64
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from bs4 import BeautifulSoup
from typing import Optional, List, Dict, Any
from config import DEFAULT_USER_AGENT

def generate_random_string(length: int = 10) -> str:
    charset = string.ascii_letters + string.digits
    return "".join(random.choice(charset) for _ in range(length))

def get_random_confidence() -> float:
    val = random.uniform(0.1, 0.9)
    return round(val, 1)

def get_random_confidence_on_xss() -> float:
    val = random.uniform(5.0, 8.3)
    return round(val, 1)

def get_random_confidence_on_match() -> float:
    val = random.uniform(0.3, 0.8)
    return round(val, 1)

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme in ("http", "https") and parsed.netloc)
    except Exception:
        return False

def get_main_domain(url: str) -> str:
    try:
        return urlparse(url).netloc
    except Exception:
        return ""

def is_same_origin(url1: str, url2: str) -> bool:
    try:
        p1 = urlparse(url1)
        p2 = urlparse(url2)
        return (p1.scheme, p1.netloc) == (p2.scheme, p2.netloc)
    except Exception:
        return False

def clean_error_text(err_text: str) -> str:
    if not err_text:
        return "Unknown error"
    first_line = err_text.strip().split("\n")[0]
    first_line = re.sub(r"\s+", " ", first_line)
    return first_line[:120]

def get_current_time() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_excluded_param(name: str, excluded_vars: List[str], excluded_vars_regex: List[str]) -> bool:
    if not name:
        return True
    lower_name = str(name).lower()
    for item in excluded_vars:
        if str(item).lower() == lower_name:
            return True
    for pattern in excluded_vars_regex:
        if str(pattern).lower() in lower_name:
            return True
    return False

def extract_tokens(text: str) -> List[str]:
    if not text:
        return []
    tokens = re.findall(r"[A-Za-z0-9_-]{3,}", text)
    return list(dict.fromkeys(tokens))

async def async_delay(min_ms: int = 3000, max_ms: int = 5000):
    if max_ms <= min_ms:
        delay_sec = min_ms / 1000.0
    else:
        delay_sec = random.uniform(min_ms, max_ms) / 1000.0
    await asyncio.sleep(delay_sec)

def get_rendered_payload_variants(payload: str) -> List[str]:
    variants = set()
    variants.add(payload)

    try:
        soup = BeautifulSoup(f"<div>{payload}</div>", "html.parser")
        div = soup.find("div")
        if div:
            variants.add("".join(str(c) for c in div.contents))
            first_child = div.find()
            if first_child:
                variants.add(str(first_child))
    except Exception:
        pass

    return [v for v in variants if v]

def build_payloaded_url(url: str, param_name: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param_name] = [payload]

    flat_params = []
    for k, v in qs.items():
        for item in v:
            flat_params.append((k, item))

    new_query = urlencode(flat_params, doseq=True)

    port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    path_part = parsed.path or "/"
    query_part = f"?{new_query}" if new_query else ""
    frag_part = f"#{parsed.fragment}" if parsed.fragment else ""

    return f"{parsed.scheme}://{parsed.hostname}{port_part}{path_part}{query_part}{frag_part}"

def build_payloaded_body(params: List[Any], target_param_name: str, payload: str) -> str:
    body_items = []
    found = False

    for param in params:
        name = getattr(param, "param_name", str(param))
        val = getattr(param, "param_value", "") or ""
        if name == target_param_name:
            body_items.append((name, payload))
            found = True
        else:
            body_items.append((name, val))

    if not found:
        body_items.append((target_param_name, payload))

    return urlencode(body_items)

def build_path_payload_url(test_path: str, payload: str) -> str:
    encoded = quote(payload, safe="")
    return test_path.replace("[PATH_BASED_TESTING]", encoded)

def build_fragment_payload_url(url: str, payload: str) -> str:
    base = url.split("#")[0]
    return f"{base}#{payload}"

def generate_post_based_poc(action: str, form_data: Dict[str, str]) -> str:
    hidden_inputs = []
    for k, v in form_data.items():
        safe_val = html.escape(str(v or ""))
        safe_key = html.escape(str(k))
        hidden_inputs.append(f'<input type="hidden" name="{safe_key}" value="{safe_val}">')

    inputs_html = "\n".join(hidden_inputs)
    opt_out_poc = html.escape(
        f'<form method="post" action="{action}">\n{inputs_html}\n<button>XSS</button>\n</form>'
    )
    final_poc = (
        f"<h1>XSS by XSSRush!</h1>\n"
        f'<form method="post" action="{action}">\n{inputs_html}\n<button>XSS</button>\n</form>\n'
        f"<br><pre>{opt_out_poc}</pre>"
    )
    b64 = base64.b64encode(final_poc.encode("utf-8")).decode("utf-8")
    return f"data:text/html;base64,{b64}"

def detect_match(rendered_html: str, payload_data: Any) -> bool:
    if getattr(payload_data, "check_for_match", 1) != 1:
        return False

    for reg in (getattr(payload_data, "regex", None), getattr(payload_data, "cheerio_regex", None)):
        if reg:
            pat = reg.pattern.lstrip("^").rstrip("$")
            if re.search(pat, rendered_html, re.IGNORECASE):
                return True

    variants = get_rendered_payload_variants(payload_data.payload)
    for variant in variants:
        if variant.lower() in rendered_html.lower():
            return True

    try:
        soup = BeautifulSoup(rendered_html, "html.parser")
        expected = str(getattr(payload_data, "expected_value", ""))
        dialog_type = getattr(payload_data, "dialog_type", "alert").lower()

        injected_tags = {t.lower() for t in re.findall(r"<([a-zA-Z0-9]+)", payload_data.payload)}

        for tag_name in injected_tags:
            for el in soup.find_all(tag_name):
                if tag_name in ("img", "svg", "body", "iframe", "input", "button", "video", "audio", "details"):
                    for attr_name, attr_val in el.attrs.items():
                        if attr_name.lower().startswith("on"):
                            val = str(attr_val).lower()
                            if dialog_type in val and (not expected or expected in val):
                                return True
                elif tag_name == "script":
                    has_matching_attr = any(
                        attr.lower() in payload_data.payload.lower() for attr in el.attrs
                    )
                    text = el.string or el.get_text() or ""
                    clean_lines = [
                        line.strip() for line in text.splitlines()
                        if not line.strip().startswith("//") and not line.strip().startswith("/*")
                    ]
                    clean_text = " ".join(clean_lines).lower()
                    if (has_matching_attr or f"<{tag_name}" in payload_data.payload.lower()) and dialog_type in clean_text and (not expected or expected in clean_text):
                        return True
    except Exception:
        pass

    return False

def build_raw_http_request(finding: Any, user_agent: Optional[str] = None) -> str:
    ua = user_agent or DEFAULT_USER_AGENT
    raw_url = getattr(finding, "request_url", "") or getattr(finding, "endpoint", "") or "/"
    if not raw_url.startswith(("http://", "https://")):
        raw_url = f"http://{raw_url}"
    parsed = urlparse(raw_url)

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    if parsed.fragment:
        path = f"{path}#{parsed.fragment}"

    host = parsed.netloc or "localhost"

    req_method = getattr(finding, "request_method", "GET").upper()
    payload_val = getattr(finding, "payload_value", "")
    param_name = getattr(finding, "param_name", "") or ""

    if req_method == "HEADER":
        method = "GET"
        h_name = param_name
        if h_name.startswith("Header: "):
            h_name = h_name[len("Header: "):]
        h_name = h_name.strip()
        h_lower = h_name.lower()

        if h_lower == "host":
            lines = [
                f"{method} {path}",
                f"Host: {payload_val}",
                f"User-Agent: {ua}",
            ]
        elif h_lower in ("user-agent", "useragent"):
            lines = [
                f"{method} {path}",
                f"Host: {host}",
                f"User-Agent: {payload_val}",
            ]
        else:
            lines = [
                f"{method} {path}",
                f"Host: {host}",
                f"User-Agent: {ua}",
                f"{h_name}: {payload_val}",
            ]
        return "\n".join(lines)

    elif req_method == "POST":
        method = "POST"
        body = getattr(finding, "request_body", "") or ""
        lines = [
            f"{method} {path}",
            f"Host: {host}",
            f"User-Agent: {ua}",
            "",
            body,
        ]
        return "\n".join(lines)

    else:
        method = "GET"
        lines = [
            f"{method} {path}",
            f"Host: {host}",
            f"User-Agent: {ua}",
        ]
        return "\n".join(lines)

