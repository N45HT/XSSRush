import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
from utils.logger import Logger

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".js", ".json", ".xml", ".txt",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".webm", ".wav",
}

def normalize_crawl_url(url: str) -> str:
    parsed = urlparse(url)
    cleaned = parsed._replace(fragment="")
    return cleaned.geturl()

def get_url_signature(url: str) -> Tuple[str, str, str, Tuple[str, ...]]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    param_keys = tuple(sorted(qs.keys()))
    return (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), param_keys)

def get_form_signature(method: str, action_url: str, param_names: List[str]) -> Tuple[str, str, Tuple[str, ...]]:
    parsed = urlparse(action_url)
    norm_action = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path.rstrip('/')}"
    return (method.upper(), norm_action, tuple(sorted(param_names)))

async def run_crawler(
    page,
    seed_url: str,
    max_depth: int = 2,
    max_urls: int = 50,
    logger: Optional[Logger] = None,
) -> List[Dict[str, Any]]:
    clamped_depth = min(max(1, max_depth), 5)
    clamped_max_urls = min(max(1, max_urls), 200)

    if logger:
        logger.action(f"running crawler on {seed_url} (depth={clamped_depth}, max_urls={clamped_max_urls})...")

    visited_urls: Set[str] = set()
    seen_url_signatures: Set[Tuple] = set()
    seen_form_signatures: Set[Tuple] = set()
    discovered_targets: List[Dict[str, Any]] = []

    parsed_seed = urlparse(seed_url)
    seed_netloc = parsed_seed.netloc.lower()

    clean_seed = normalize_crawl_url(seed_url)
    seed_sig = get_url_signature(clean_seed)
    seen_url_signatures.add(seed_sig)

    queue: List[Tuple[str, int]] = [(clean_seed, 0)]

    while queue and len(discovered_targets) < clamped_max_urls:
        current_url, current_depth = queue.pop(0)

        norm_current = normalize_crawl_url(current_url)
        if norm_current in visited_urls:
            continue
        visited_urls.add(norm_current)

        if logger:
            logger.debug(f"crawling page: {current_url} (depth={current_depth})")

        try:
            await page.goto(current_url, wait_until="domcontentloaded", timeout=12000)
            await page.wait_for_timeout(500)
            html = await page.content()
        except Exception as err:
            if logger:
                logger.debug(f"crawl navigation failed on {current_url}: {err}")
            continue

        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            if len(discovered_targets) >= clamped_max_urls:
                break
            raw_action = form.get("action") or ""
            action_url = urljoin(current_url, raw_action)
            parsed_action = urlparse(action_url)
            if parsed_action.netloc.lower() != seed_netloc:
                continue

            method = (form.get("method") or "GET").upper()
            param_names: List[str] = []
            for inp in form.find_all(["input", "textarea", "select"]):
                n = inp.get("name")
                if n and n.strip() and n.strip() not in param_names:
                    param_names.append(n.strip())

            if not param_names:
                continue

            form_sig = get_form_signature(method, action_url, param_names)
            if form_sig in seen_form_signatures:
                if logger:
                    logger.debug(f"duplicate form skipped: [{method}] {action_url} ({', '.join(param_names)})")
                continue
            seen_form_signatures.add(form_sig)

            if method == "POST":
                postfields = {p: "" for p in param_names}
                discovered_targets.append({
                    "url": action_url,
                    "method": "POST",
                    "postfields": postfields,
                    "source_url": current_url,
                    "depth": current_depth,
                })
                if logger:
                    logger.success(f"[crawl] discovered form [POST] {action_url} ({', '.join(param_names)})")
            else:
                get_query = urlencode([(p, "") for p in param_names])
                sep = "&" if "?" in action_url else "?"
                get_url = f"{action_url}{sep}{get_query}"
                url_sig = get_url_signature(get_url)
                if url_sig not in seen_url_signatures:
                    seen_url_signatures.add(url_sig)
                    discovered_targets.append({
                        "url": get_url,
                        "method": "GET",
                        "postfields": None,
                        "source_url": current_url,
                        "depth": current_depth,
                    })
                    if logger:
                        logger.success(f"[crawl] discovered form [GET] {action_url} ({', '.join(param_names)})")

        if current_depth < clamped_depth:
            for a in soup.find_all("a", href=True):
                if len(discovered_targets) >= clamped_max_urls:
                    break
                href = a["href"].strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                abs_url = urljoin(current_url, href)
                parsed_link = urlparse(abs_url)
                if parsed_link.scheme not in ("http", "https"):
                    continue
                if parsed_link.netloc.lower() != seed_netloc:
                    continue
                path_suffix = Path(parsed_link.path).suffix.lower()
                if path_suffix in IGNORED_EXTENSIONS:
                    continue

                clean_link = normalize_crawl_url(abs_url)
                link_sig = get_url_signature(clean_link)
                if link_sig in seen_url_signatures:
                    continue
                seen_url_signatures.add(link_sig)

                discovered_targets.append({
                    "url": clean_link,
                    "method": "GET",
                    "postfields": None,
                    "source_url": current_url,
                    "depth": current_depth + 1,
                })
                if logger:
                    logger.success(f"[crawl] discovered link: {clean_link} (depth={current_depth + 1})")

                if clean_link not in visited_urls:
                    queue.append((clean_link, current_depth + 1))

    if logger:
        logger.action(f"crawler finished: {len(discovered_targets)} unique endpoint(s) collected")

    return discovered_targets
