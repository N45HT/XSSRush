import re
from typing import List, Dict, Any, Optional

URL_ATTR_REGEX = re.compile(r"(href|src|action|formaction|data|poster)\s*=\s*[\"'][^\"']*$", re.IGNORECASE)
ATTR_REGEX = re.compile(r"\w+\s*=\s*[\"'][^\"']*$", re.IGNORECASE)
TAG_REGEX = re.compile(r"<([a-zA-Z0-9]+)([^>]*)")

def detect_all_reflections(html_content: str, value: str) -> List[Dict[str, Any]]:
    reflections = []
    if not value or not html_content:
        return reflections

    index = 0
    val_len = len(value)

    while True:
        pos = html_content.find(value, index)
        if pos == -1:
            break

        before = html_content[:pos]
        tag_matches = list(TAG_REGEX.finditer(before))

        context = "unknown"
        tags = None

        if tag_matches:
            last_tag = tag_matches[-1]
            tag_name = last_tag.group(1).lower()
            tag_attributes = last_tag.group(2) or ""

            tags = tag_name

            if tag_name == "script":
                context = "javascript"
            elif URL_ATTR_REGEX.search(tag_attributes):
                context = "url"
            elif ATTR_REGEX.search(tag_attributes):
                context = "attribute"
            else:
                context = "html"

        reflections.append({
            "context": context,
            "tags": tags,
        })

        index = pos + val_len

    return reflections
