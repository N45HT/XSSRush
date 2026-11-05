from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Optional, Any

def resolve_action_url(action: Optional[str], base_url: str) -> str:
    if not action or action.strip() == "":
        return base_url

    action = action.strip()
    parsed_base = urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    if action.startswith("//"):
        return f"{parsed_base.scheme}:{action}"
    if action.startswith("/"):
        return f"{origin}{action}"
    if action.startswith("http://") or action.startswith("https://"):
        return action

    separator = "" if origin.endswith("/") or action.startswith("/") else "/"
    return f"{origin}{separator}{action}"

def parse_postfields_string(raw: Optional[str]) -> Dict[str, str]:
    if not raw or not isinstance(raw, str):
        return {}

    raw = raw.strip()
    if not raw:
        return {}

    result = {}
    pairs = raw.split("&")
    for pair in pairs:
        pair = pair.strip()
        if not pair:
            continue
        if "=" in pair:
            key, value = pair.split("=", 1)
        else:
            key, value = pair, ""

        key = unquote(key.strip())
        value = unquote(value.strip())
        if key:
            result[key] = value

    return result

def build_test_paths(url: str) -> List[str]:
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port not in (80, 443):
        base_url += f":{parsed.port}"

    raw_path = parsed.path.strip("/")
    segments = [s for s in raw_path.split("/") if s] if raw_path else []

    test_paths: List[str] = []

    if len(segments) == 0:
        test_paths.append(f"{base_url}/[PATH_BASED_TESTING]")
    else:
        test_paths.append(f"{base_url}/{'/'.join(segments)}/[PATH_BASED_TESTING]")

        test_segments = list(segments)
        test_segments[-1] = "[PATH_BASED_TESTING]"
        test_paths.append(f"{base_url}/{'/'.join(test_segments)}")

        for i in range(len(segments) - 2, -1, -1):
            test_segments = list(segments)
            test_segments[i] = "[PATH_BASED_TESTING]"
            test_paths.append(f"{base_url}/{'/'.join(test_segments)}")

    return test_paths

def extract_query_dict(url: str) -> Dict[str, str]:
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        return {k: v[0] if v else "" for k, v in qs.items()}
    except Exception:
        return {}
