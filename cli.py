import argparse
import asyncio
import json
from pathlib import Path
import re
import sys
from typing import Optional, Set, List, Dict, Tuple, Any

from constants import VERSION
from models import ScanConfig
from parsers.url import parse_postfields_string
from utils.logger import Logger
from utils.helpers import is_valid_url
from scanner.engine import ScannerEngine
from reporters.console import Reporter
from payloads import get_all_payloads
from config import GENERAL_PARAMS, REDIRECT_PARAMS, XSS_HEADERS
from detection.context import normalize_context_name
from browser.playwright import BrowserManager
from modules.crawler import run_crawler, get_url_signature, get_form_signature
from ai import resolve_ai_key

def strip_ansi(text: str) -> str:
    ansi_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_regex.sub('', text)

def resolve_output_path(user_path: str, base_dir: Path) -> Path:
    raw = user_path.strip()
    is_rooted = (
        raw.startswith(("/", "\\"))
        or bool(re.match(r"^[a-zA-Z]:[/\\]", raw))
        or Path(raw).is_absolute()
    )
    if is_rooted:
        target = Path(raw)
    else:
        target = base_dir / "output" / raw

    target.parent.mkdir(parents=True, exist_ok=True)
    return target

def resolve_wordlist_path(user_path: str, base_dir: Path) -> Path:
    raw = user_path.strip()
    p = Path(raw)
    if p.is_file():
        return p
    alt = base_dir / raw
    if alt.is_file():
        return alt
    return p

def load_wordlist(file_path: Path) -> List[str]:
    if not file_path.is_file():
        return []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return list(dict.fromkeys(lines))

def parse_scan_modules(scan_str: Optional[str]) -> Set[str]:
    if not scan_str:
        return {"get", "post"}

    raw_tokens = [t.strip().lower() for t in scan_str.split(",") if t.strip()]
    if "all" in raw_tokens:
        return {"get", "post", "path", "fragment", "header"}

    valid_mods = {"get", "post", "path", "fragment", "header"}
    selected = set()
    for tok in raw_tokens:
        if tok in valid_mods:
            selected.add(tok)
        elif tok == "dom":
            selected.add("get")
        elif tok in ("paths", "link", "links"):
            selected.add("path")
        elif tok in ("fragments", "hash"):
            selected.add("fragment")
        elif tok in ("headers", "head"):
            selected.add("header")

    return selected if selected else {"get", "post"}

def parse_target_params(param_arg) -> Tuple[List[str], Dict[str, str]]:
    if not param_arg:
        return [], {}
    params = []
    contexts = {}
    if isinstance(param_arg, str):
        param_arg = [param_arg]
    for item in param_arg:
        for piece in item.split(","):
            piece = piece.strip()
            if not piece:
                continue
            if ":" in piece:
                name, raw_ctx = piece.split(":", 1)
                name = name.strip()
                raw_ctx = raw_ctx.strip()
                norm_ctx = normalize_context_name(raw_ctx)
                if name:
                    if name.lower() not in [x.lower() for x in params]:
                        params.append(name)
                    if norm_ctx:
                        contexts[name.lower()] = norm_ctx
            else:
                if piece.lower() not in [x.lower() for x in params]:
                    params.append(piece)
    return params, contexts

def parse_exclude_params(exclude_arg) -> List[str]:
    if not exclude_arg:
        return []
    res = []
    if isinstance(exclude_arg, str):
        exclude_arg = [exclude_arg]
    for item in exclude_arg:
        for p in item.split(","):
            cleaned = p.strip()
            if cleaned and cleaned.lower() not in res:
                res.append(cleaned.lower())
    return res

def parse_header_list(header_arg) -> List[str]:
    if not header_arg:
        return []
    res = []
    if isinstance(header_arg, str):
        header_arg = [header_arg]
    for item in header_arg:
        for h in item.split(","):
            cleaned = h.strip()
            if cleaned and cleaned not in res:
                res.append(cleaned)
    return res

class XSSRHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=34, width=100)

class XSSRArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        formatter = self._get_formatter()
        for action_group in self._action_groups:
            formatter.start_section(action_group.title)
            formatter.add_text(action_group.description)
            formatter.add_arguments(action_group._group_actions)
            formatter.end_section()
        return formatter.format_help()

    def print_help(self, file=None):
        logger = Logger()
        logger.print_banner()
        raw_help = self.format_help()
        clean = strip_ansi(raw_help)
        print(f"\033[97m{clean.strip()}\033[0m\n")

    def error(self, message):
        print(f"\033[97mxssr: error: {message}\033[0m", file=sys.stderr)
        print("\033[90m(use 'xssr -h' or 'xssr --help' to view all available options)\033[0m\n", file=sys.stderr)
        sys.exit(2)

def build_parser() -> argparse.ArgumentParser:
    parser = XSSRArgumentParser(
        prog="xssr",
        add_help=False,
        formatter_class=XSSRHelpFormatter,
    )

    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument(
        "-u", "--url",
        dest="url",
        type=str,
        default=None,
        help="Target URL to scan (e.g. https://example.com/search?q=test)",
    )
    target_group.add_argument(
        "-f", "--file",
        dest="file",
        type=str,
        default=None,
        metavar="FILE",
        help="Load targets from file (one URL per line)",
    )

    browser_group = parser.add_argument_group("Browser & Engine Options")
    browser_group.add_argument(
        "-b", "--browser",
        dest="browser",
        type=str,
        choices=["firefox", "chromium", "webkit", "chrome", "msedge"],
        default="firefox",
        help="Browser engine to use (default: firefox, choices: firefox, chromium, webkit, chrome, msedge)",
    )
    browser_group.add_argument(
        "--headless",
        dest="headless",
        type=str.lower,
        choices=["true", "false"],
        default="true",
        metavar="",
        help="Run browser in headless mode (choices: true, false, default: true)",
    )
    browser_group.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=15000,
        help="Page navigation timeout in milliseconds (default: 15000)",
    )
    browser_group.add_argument(
        "--delay-min",
        dest="delay_min",
        type=int,
        default=3000,
        help="Minimum request delay in ms (default: 3000)",
    )
    browser_group.add_argument(
        "--delay-max",
        dest="delay_max",
        type=int,
        default=5000,
        help="Maximum request delay in ms (default: 5000)",
    )
    browser_group.add_argument(
        "-t", "--threads",
        dest="threads",
        type=int,
        default=1,
        help="Number of concurrent browser tabs/workers (1-5, default: 1)",
    )

    scope_group = parser.add_argument_group("Scan Scope Options")
    scope_group.add_argument(
        "--scan",
        dest="scan",
        type=str,
        default="get,post",
        metavar="MODULES",
        help="Modules to test: get, post, path, fragment, header, or all (default: get,post)",
    )
    scope_group.add_argument(
        "-w", "--wordlist",
        dest="wordlist",
        type=str,
        default=None,
        metavar="FILE",
        help="Custom parameter wordlist file to probe (e.g. 'wordlists/common.txt')",
    )
    scope_group.add_argument(
        "-m", "--mining",
        dest="mining",
        action="store_true",
        default=False,
        help="Perform parameter mining and reflection analysis only (no XSS testing)",
    )
    scope_group.add_argument(
        "-p", "--param",
        dest="param",
        action="append",
        default=None,
        metavar="PARAMS",
        help="Parameters to test (e.g. 'p:js,q:html' or 'name')",
    )
    scope_group.add_argument(
        "-e", "--exclude",
        dest="exclude",
        action="append",
        default=None,
        metavar="PARAMS",
        help="Parameters to skip during testing (comma-separated, e.g. 'name,location')",
    )
    scope_group.add_argument(
        "-d", "--data",
        dest="data",
        type=str,
        default=None,
        metavar="POSTFIELDS",
        help="Custom POST data fields (e.g. 'username=admin&search=keyword')",
    )
    scope_group.add_argument(
        "-c", "--cookie",
        dest="cookie",
        type=str,
        default=None,
        metavar="COOKIE",
        help="Custom cookie string or path to cookie file (e.g. 'session=xyz')",
    )
    scope_group.add_argument(
        "--cookie-file",
        dest="cookie_file",
        type=str,
        default=None,
        metavar="FILE",
        help="Load cookies from file (Netscape, JSON, or key=value format)",
    )
    scope_group.add_argument(
        "-H", "--header",
        dest="headers",
        action="append",
        default=None,
        metavar="HEADER",
        help="Custom HTTP header to send with all requests (e.g. 'Authorization: Bearer token')",
    )
    scope_group.add_argument(
        "--context",
        dest="context",
        type=str,
        default=None,
        metavar="CONTEXT",
        help="Default injection context (choices: js, html, attr, url, dom)",
    )
    scope_group.add_argument(
        "--include-header",
        dest="include_headers",
        action="append",
        default=None,
        metavar="HEADERS",
        help="Custom HTTP headers to add to header scan (comma-separated, e.g. 'X-User-Agent,X-Referer')",
    )
    scope_group.add_argument(
        "--exclude-header",
        dest="exclude_headers",
        action="append",
        default=None,
        metavar="HEADERS",
        help="HTTP headers to skip during header scan (comma-separated, e.g. 'User-Agent,Referer')",
    )

    crawl_group = parser.add_argument_group("Crawler / Spider Options")
    crawl_group.add_argument(
        "--crawl",
        dest="crawl",
        action="store_true",
        default=False,
        help="Enable internal spider/crawler to discover endpoints automatically",
    )
    crawl_group.add_argument(
        "--depth",
        dest="depth",
        type=int,
        default=2,
        help="Maximum crawl depth for internal links (1-5, default: 2)",
    )
    crawl_group.add_argument(
        "--max-urls",
        dest="max_urls",
        type=int,
        default=50,
        help="Maximum total URLs to collect during crawling (1-200, default: 50)",
    )

    parser.add_argument(
        "-l", "--list",
        dest="file",
        type=str,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-q", "--quiet",
        dest="silent",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--cookie-jar",
        dest="cookie_file",
        type=str,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--cookies",
        dest="cookie",
        type=str,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--headers",
        dest="headers",
        action="append",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--parameter-mining",
        dest="mining",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--mine",
        dest="mining",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--params",
        dest="param",
        action="append",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--postfields",
        dest="data",
        type=str,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--include-headers",
        dest="include_headers",
        action="append",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--exclude-headers",
        dest="exclude_headers",
        action="append",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--show-parameters",
        dest="show_params",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    ai_group = parser.add_argument_group("AI Assistant Options")
    ai_group.add_argument(
        "--ai",
        dest="ai",
        action="store_true",
        default=False,
        help="Enable AI fallback analysis when standard payloads fail",
    )
    ai_group.add_argument(
        "--ai-only",
        dest="ai_only",
        action="store_true",
        default=False,
        help="Exclusively test using AI-generated payloads (skip standard payloads)",
    )
    ai_group.add_argument(
        "--ai-model",
        dest="ai_model",
        type=str,
        default="deepseek/deepseek-chat",
        metavar="MODEL",
        help="AI model to use (default: deepseek/deepseek-chat)",
    )
    ai_group.add_argument(
        "--ai-key",
        dest="ai_key",
        type=str,
        default=None,
        metavar="KEY",
        help="AI provider API key (or via environment variable XSSR_AI_KEY)",
    )

    info_group = parser.add_argument_group("Information Options")
    info_group.add_argument(
        "--show-payloads",
        dest="show_payloads",
        action="store_true",
        help="Show all built-in XSS payloads and exit",
    )
    info_group.add_argument(
        "--show-params",
        dest="show_params",
        action="store_true",
        help="Show all built-in known parameters and exit",
    )
    info_group.add_argument(
        "--show-headers",
        dest="show_headers",
        action="store_true",
        help="Show all built-in target HTTP headers and exit",
    )

    output_group = parser.add_argument_group("Output & Reporting Options")
    output_group.add_argument(
        "-o", "--output",
        dest="output",
        type=str,
        default=None,
        metavar="FILE",
        help="Save report JSON (saved to output/ folder unless absolute path is given)",
    )
    output_group.add_argument(
        "-s", "--silent",
        dest="silent",
        action="store_true",
        default=False,
        help="Silent mode (suppress banners and progress, output only findings)",
    )
    output_group.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable verbose debugging output",
    )
    output_group.add_argument(
        "-h", "--help",
        action="help",
        help="Show this help message and exit",
    )
    output_group.add_argument(
        "--version",
        action="version",
        version=f"XSSR/XSSRush {VERSION}",
        help="Show program's version number and exit",
    )

    return parser

def has_stdin_data() -> bool:
    if sys.stdin is None or sys.stdin.isatty():
        return False
    if sys.platform == "win32":
        try:
            import msvcrt
            import ctypes
            from ctypes import wintypes
            handle = msvcrt.get_osfhandle(sys.stdin.fileno())
            avail = wintypes.DWORD()
            res = ctypes.windll.kernel32.PeekNamedPipe(handle, None, 0, None, ctypes.byref(avail), None)
            return bool(res and avail.value > 0)
        except Exception:
            return False
    else:
        try:
            import select
            return bool(select.select([sys.stdin], [], [], 0.0)[0])
        except Exception:
            return False

def load_target_urls(args) -> List[str]:
    raw_list: List[str] = []
    if getattr(args, "url", None) and args.url.strip():
        raw_list.append(args.url.strip())

    file_val = getattr(args, "file", None)
    if file_val:
        p = Path(file_val.strip())
        if not p.is_file():
            print(f"\033[97mxssr: error: target file not found: '{file_val}'\033[0m", file=sys.stderr)
            sys.exit(2)
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                val = line.strip()
                if val and not val.startswith("#"):
                    raw_list.append(val)

    if not raw_list and has_stdin_data():
        try:
            for line in sys.stdin:
                val = line.strip()
                if val and not val.startswith("#"):
                    raw_list.append(val)
        except Exception:
            pass

    return list(dict.fromkeys(raw_list))

def normalize_target_url(raw: str) -> Optional[str]:
    val = raw.strip()
    if not val:
        return None
    if not val.startswith(("http://", "https://")):
        val = f"http://{val}"
    if is_valid_url(val):
        return val
    return None

def parse_custom_headers(raw_headers: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if not raw_headers:
        return headers
    for item in raw_headers:
        for line in item.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
    return headers

def parse_cookie_text(text: str, target_url: str) -> List[Dict[str, Any]]:
    cookies: List[Dict[str, Any]] = []
    text = text.strip()
    if not text:
        return cookies

    if text.startswith("["):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict) and "name" in item and "value" in item:
                        c_dict = {
                            "name": str(item["name"]),
                            "value": str(item["value"]),
                        }
                        if "domain" in item:
                            c_dict["domain"] = item["domain"]
                        if "path" in item:
                            c_dict["path"] = item["path"]
                        if target_url and "domain" not in c_dict:
                            c_dict["url"] = target_url
                        cookies.append(c_dict)
                return cookies
        except Exception:
            pass

    for line in text.splitlines():
        line = line.strip()
        if not line or (line.startswith("#") and not line.startswith("#HttpOnly_")):
            continue
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_"):]
        if "\t" in line:
            parts = line.split("\t")
            if len(parts) >= 7:
                c_dict = {
                    "name": parts[5].strip(),
                    "value": parts[6].strip(),
                }
                dom = parts[0].strip()
                if dom:
                    c_dict["domain"] = dom
                p_path = parts[2].strip()
                if p_path:
                    c_dict["path"] = p_path
                if target_url and "domain" not in c_dict:
                    c_dict["url"] = target_url
                cookies.append(c_dict)
                continue
        for pair in line.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                c_dict = {
                    "name": k.strip(),
                    "value": v.strip(),
                }
                if target_url:
                    c_dict["url"] = target_url
                cookies.append(c_dict)

    return cookies

def load_cookies_config(raw_cookie: Optional[str], cookie_file: Optional[str], base_dir: Path, target_url: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    all_cookies: List[Dict[str, Any]] = []

    if cookie_file:
        p = Path(cookie_file.strip())
        if not p.is_file():
            alt = base_dir / cookie_file.strip()
            if alt.is_file():
                p = alt
            else:
                print(f"\033[97mxssr: error: cookie file not found: '{cookie_file}'\033[0m", file=sys.stderr)
                sys.exit(2)
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            all_cookies.extend(parse_cookie_text(f.read(), target_url))

    if raw_cookie:
        val = raw_cookie.strip()
        p = Path(val)
        alt = base_dir / val
        if p.is_file():
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                all_cookies.extend(parse_cookie_text(f.read(), target_url))
        elif alt.is_file():
            with open(alt, "r", encoding="utf-8", errors="ignore") as f:
                all_cookies.extend(parse_cookie_text(f.read(), target_url))
        else:
            all_cookies.extend(parse_cookie_text(val, target_url))

    dedup: Dict[str, Dict[str, Any]] = {}
    for c in all_cookies:
        dedup[c["name"]] = c
    final_cookies = list(dedup.values())

    cookie_header_str = "; ".join(f"{c['name']}={c['value']}" for c in final_cookies) if final_cookies else None
    return final_cookies, cookie_header_str

async def main_async(args, raw_targets: List[str]):
    is_silent = getattr(args, "silent", False)
    logger = Logger(verbose=args.verbose, silent=is_silent)
    logger.print_banner()

    valid_targets: List[str] = []
    for raw in raw_targets:
        norm = normalize_target_url(raw)
        if norm:
            valid_targets.append(norm)
        elif not is_silent:
            logger.warning(f"skipping invalid URL: '{raw}'")

    if not valid_targets:
        if not is_silent:
            logger.error("no valid target URLs found to scan")
        sys.exit(1)

    custom_headers = parse_custom_headers(getattr(args, "headers", None))
    raw_data = getattr(args, "data", None)
    custom_postfields = parse_postfields_string(raw_data) if raw_data else None
    is_headless = str(args.headless).strip().lower() in ("true", "1", "yes")
    scan_modules = parse_scan_modules(args.scan)
    target_params, target_param_contexts = parse_target_params(getattr(args, "param", None))
    default_context = normalize_context_name(getattr(args, "context", None))
    exclude_params = parse_exclude_params(args.exclude)
    include_headers = parse_header_list(args.include_headers)
    exclude_headers = parse_header_list(args.exclude_headers)

    base_dir = Path(__file__).resolve().parent

    resolved_output = None
    if args.output:
        resolved_output = str(resolve_output_path(args.output, base_dir))

    resolved_wordlist = None
    wordlist_params = []
    if getattr(args, "wordlist", None):
        wl_path = resolve_wordlist_path(args.wordlist, base_dir)
        if not wl_path.is_file():
            logger.error(f"wordlist file not found: '{args.wordlist}'")
            sys.exit(1)
        wordlist_params = load_wordlist(wl_path)
        resolved_wordlist = str(wl_path)
        logger.info(f"loaded {len(wordlist_params)} parameter(s) from wordlist: '{args.wordlist}'")

    total_targets = len(valid_targets)
    all_findings = []
    all_parameters = []

    req_threads = getattr(args, "threads", 1) or 1
    threads = min(max(1, req_threads), 5)
    if req_threads > 5 and not is_silent:
        logger.warning(f"thread count clamped to maximum 5 (requested: {req_threads})")

    req_depth = getattr(args, "depth", 2) or 2
    depth = min(max(1, req_depth), 5)
    if req_depth > 5 and not is_silent:
        logger.warning(f"crawl depth clamped to maximum 5 (requested: {req_depth})")

    req_max_urls = getattr(args, "max_urls", 50) or 50
    max_urls = min(max(1, req_max_urls), 200)
    if req_max_urls > 200 and not is_silent:
        logger.warning(f"max-urls clamped to maximum 200 (requested: {req_max_urls})")

    enable_crawl = getattr(args, "crawl", False)

    enable_ai_only = getattr(args, "ai_only", False)
    enable_ai = getattr(args, "ai", False) or enable_ai_only
    ai_key = None
    if enable_ai:
        ai_key = resolve_ai_key(getattr(args, "ai_key", None), base_dir)
        if not ai_key:
            enable_ai = False
            enable_ai_only = False
            if not is_silent:
                logger.warning("AI features disabled: no API key found (provide --ai-key or set XSSR_AI_KEY in .env/environment)")
        else:
            if not is_silent:
                if enable_ai_only:
                    logger.info(f"AI-only testing active: provider=openrouter, model={args.ai_model} (skipping standard payloads)")
                else:
                    logger.info(f"AI fallback active: provider=openrouter, model={args.ai_model}")

    scan_queue: List[Dict[str, Any]] = []
    seen_url_signatures: Set[Tuple] = set()
    seen_form_signatures: Set[Tuple] = set()

    for u in valid_targets:
        u_sig = get_url_signature(u)
        seen_url_signatures.add(u_sig)
        scan_queue.append({
            "url": u,
            "method": "POST" if custom_postfields else "GET",
            "postfields": custom_postfields,
        })

    if enable_crawl:
        crawl_bm = BrowserManager(
            browser_type=args.browser,
            headless=is_headless,
            timeout_ms=args.timeout,
            headers=custom_headers,
        )
        try:
            await crawl_bm.start()
            crawl_page = await crawl_bm.create_page()
            for seed in valid_targets:
                discovered = await run_crawler(
                    page=crawl_page,
                    seed_url=seed,
                    max_depth=depth,
                    max_urls=max_urls,
                    logger=logger if not is_silent else None,
                )
                for item in discovered:
                    if item["method"] == "POST":
                        form_sig = get_form_signature("POST", item["url"], list((item.get("postfields") or {}).keys()))
                        if form_sig not in seen_form_signatures:
                            seen_form_signatures.add(form_sig)
                            scan_queue.append(item)
                    else:
                        u_sig = get_url_signature(item["url"])
                        if u_sig not in seen_url_signatures:
                            seen_url_signatures.add(u_sig)
                            scan_queue.append(item)
        finally:
            await crawl_bm.close()

    total_targets = len(scan_queue)

    if threads > 1 and total_targets > 1:
        if not is_silent:
            logger.info(f"concurrency active: running {threads} parallel browser worker(s) across {total_targets} target(s)")

        shared_bm = BrowserManager(
            browser_type=args.browser,
            headless=is_headless,
            timeout_ms=args.timeout,
            headers=custom_headers,
        )
        await shared_bm.start()
        sem = asyncio.Semaphore(threads)

        async def scan_item(idx: int, item: Dict[str, Any]):
            target_url = item["url"]
            t_postfields = item.get("postfields") or custom_postfields

            target_cookies, cookie_hdr = load_cookies_config(
                raw_cookie=getattr(args, "cookie", None),
                cookie_file=getattr(args, "cookie_file", None),
                base_dir=base_dir,
                target_url=target_url,
            )
            target_headers = dict(custom_headers)
            if cookie_hdr and "Cookie" not in target_headers and "cookie" not in target_headers:
                target_headers["Cookie"] = cookie_hdr

            cfg = ScanConfig(
                target_url=target_url,
                postfields=t_postfields,
                browser_type=args.browser,
                headless=is_headless,
                timeout_ms=args.timeout,
                delay_min=args.delay_min,
                delay_max=args.delay_max,
                verbose=args.verbose,
                output_file=resolved_output,
                scan_modules=scan_modules,
                target_params=target_params,
                target_param_contexts=target_param_contexts,
                default_context=default_context,
                exclude_params=exclude_params,
                include_headers=include_headers,
                exclude_headers=exclude_headers,
                wordlist_path=resolved_wordlist,
                wordlist_params=wordlist_params,
                mining_only=getattr(args, "mining", False),
                headers=target_headers,
                cookies=target_cookies,
                cookie_string=cookie_hdr,
                threads=threads,
                crawl=enable_crawl,
                depth=depth,
                max_urls=max_urls,
                ai_enabled=enable_ai,
                ai_only=enable_ai_only,
                ai_model=args.ai_model,
                ai_key=ai_key,
            )

            async with sem:
                if not is_silent:
                    print(f"\n\033[1m\033[36m[*] target [{idx}/{total_targets}]: {target_url}\033[0m")
                worker_engine = ScannerEngine(config=cfg, logger=logger, browser_manager=shared_bm)
                findings, parameters = await worker_engine.run()
                all_findings.extend(findings)
                all_parameters.extend(parameters)
                if is_silent and cfg.mining_only:
                    for p in parameters:
                        for r in p.reflections:
                            if r.reflected:
                                tag_str = f", tag: <{r.tags}>" if r.tags else ""
                                print(f"\033[1m\033[32m[REFLECTED]\033[0m [{p.location}] {p.action_url} -> '{p.param_name}' ({r.context.upper()}{tag_str})")

        try:
            tasks = [scan_item(idx, item) for idx, item in enumerate(scan_queue, 1)]
            await asyncio.gather(*tasks)
        finally:
            await shared_bm.close()
    else:
        for idx, item in enumerate(scan_queue, 1):
            target_url = item["url"]
            t_postfields = item.get("postfields") or custom_postfields
            if not is_silent and total_targets > 1:
                print(f"\n\033[1m\033[36m[*] target [{idx}/{total_targets}]: {target_url}\033[0m")

            target_cookies, cookie_hdr = load_cookies_config(
                raw_cookie=getattr(args, "cookie", None),
                cookie_file=getattr(args, "cookie_file", None),
                base_dir=base_dir,
                target_url=target_url,
            )
            target_headers = dict(custom_headers)
            if cookie_hdr and "Cookie" not in target_headers and "cookie" not in target_headers:
                target_headers["Cookie"] = cookie_hdr

            config = ScanConfig(
                target_url=target_url,
                postfields=t_postfields,
                browser_type=args.browser,
                headless=is_headless,
                timeout_ms=args.timeout,
                delay_min=args.delay_min,
                delay_max=args.delay_max,
                verbose=args.verbose,
                output_file=resolved_output,
                scan_modules=scan_modules,
                target_params=target_params,
                target_param_contexts=target_param_contexts,
                default_context=default_context,
                exclude_params=exclude_params,
                include_headers=include_headers,
                exclude_headers=exclude_headers,
                wordlist_path=resolved_wordlist,
                wordlist_params=wordlist_params,
                mining_only=getattr(args, "mining", False),
                headers=target_headers,
                cookies=target_cookies,
                cookie_string=cookie_hdr,
                threads=threads,
                crawl=enable_crawl,
                depth=depth,
                max_urls=max_urls,
                ai_enabled=enable_ai,
                ai_only=enable_ai_only,
                ai_model=args.ai_model,
                ai_key=ai_key,
            )

            engine = ScannerEngine(config=config, logger=logger)
            findings, parameters = await engine.run()
            all_findings.extend(findings)
            all_parameters.extend(parameters)

            if not is_silent and total_targets == 1:
                reporter = Reporter(findings=findings, parameters=parameters, logger=logger, mining_only=config.mining_only, silent=is_silent)
                reporter.render_console()
            elif is_silent and config.mining_only:
                for p in parameters:
                    for r in p.reflections:
                        if r.reflected:
                            tag_str = f", tag: <{r.tags}>" if r.tags else ""
                            print(f"\033[1m\033[32m[REFLECTED]\033[0m [{p.location}] {p.action_url} -> '{p.param_name}' ({r.context.upper()}{tag_str})")

    if not is_silent and total_targets > 1:
        print(f"\n\033[1m\033[36m[*] multi-target scan summary ({total_targets} targets scanned):\033[0m")
        reporter = Reporter(findings=all_findings, parameters=all_parameters, logger=logger, mining_only=getattr(args, "mining", False), silent=is_silent)
        reporter.render_console()

    if resolved_output:
        reporter = Reporter(findings=all_findings, parameters=all_parameters, logger=logger, mining_only=getattr(args, "mining", False), silent=is_silent)
        reporter.export_json(resolved_output)

def handle_show_options(args) -> bool:
    has_show = False
    if getattr(args, "show_payloads", False):
        has_show = True
        for p in get_all_payloads():
            print(p.payload)
    if getattr(args, "show_headers", False):
        has_show = True
        for h in XSS_HEADERS.keys():
            print(h)
    if getattr(args, "show_params", False):
        has_show = True
        all_params = list(dict.fromkeys(GENERAL_PARAMS + REDIRECT_PARAMS))
        print(", ".join(all_params))
    return has_show

def main():
    parser = build_parser()
    args = parser.parse_args()

    if handle_show_options(args):
        sys.exit(0)

    raw_targets = load_target_urls(args)
    if not raw_targets:
        parser.error("target URL is required via -u/--url, -f/--file, or standard input pipe")

    try:
        asyncio.run(main_async(args, raw_targets))
    except KeyboardInterrupt:
        print("\n\033[1m\033[31m[!]\033[0m Scan interrupted by user.")
        sys.exit(130)

if __name__ == "__main__":
    main()
