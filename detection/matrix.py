import json
from typing import Dict, List, Any

PROBE_CHARS = ["'", '"', '<', '>', '/', ';', '(', ')', '{', '}', '=', '`']

ESCAPE_MAP = {
    '<': ['&lt;', '&#60;', '&#x3c;', r'\u003c', r'\x3c', '%3c'],
    '>': ['&gt;', '&#62;', '&#x3e;', r'\u003e', r'\x3e', '%3e'],
    '"': ['&quot;', '&#34;', '&#x22;', r'\"', r'\u0022', r'\x22', '%22'],
    "'": ['&#39;', '&apos;', '&#x27;', r"\'", r'\u0027', r'\x27', '%27'],
    '/': ['&#47;', '&#x2f;', r'\/', '%2f'],
    ';': ['&#59;', '&#x3b;', '%3b'],
    '(': ['&#40;', '&#x28;', '%28'],
    ')': ['&#41;', '&#x29;', '%29'],
    '{': ['&#123;', '&#x7b;', '%7b'],
    '}': ['&#125;', '&#x7d;', '%7d'],
    '=': ['&#61;', '&#x3d;', '%3d'],
    '`': ['&#96;', '&#x60;', r'\`', '%60'],
}

def build_matrix_probe(token: str) -> str:
    return "".join(f"{token}{idx}{ch}{token}" for idx, ch in enumerate(PROBE_CHARS))

def analyze_character_matrix(html: str, token: str) -> Dict[str, str]:
    results = {}
    lower_html = html.lower()
    for idx, ch in enumerate(PROBE_CHARS):
        raw_pattern = f"{token}{idx}{ch}{token}"
        stripped_pattern = f"{token}{idx}{token}"
        if raw_pattern in html:
            results[ch] = "allowed"
        elif any(f"{token}{idx}{esc}{token}".lower() in lower_html for esc in ESCAPE_MAP.get(ch, [])):
            results[ch] = "escaped"
        elif stripped_pattern in html:
            results[ch] = "filtered"
        elif f"{token}{idx}" in html:
            results[ch] = "replaced"
        else:
            results[ch] = "absent"
    return results

def format_matrix_summary(matrix: Dict[str, str]) -> Dict[str, List[str]]:
    summary = {
        "allowed": [],
        "escaped": [],
        "filtered": [],
        "replaced": [],
    }
    for ch, status in matrix.items():
        if status in summary:
            summary[status].append(ch)
    return summary
