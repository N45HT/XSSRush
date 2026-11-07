from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional, Set
import random
import re
import time

from models import Parameter
from config import GENERAL_PARAMS, REDIRECT_PARAMS, EXCLUDED_VARS, EXCLUDED_VARS_REGEX
from utils.helpers import is_excluded_param, generate_random_string
from parsers.url import resolve_action_url, extract_query_dict
from utils.logger import Logger

JS_RESERVED_WORDS = {
    "abstract", "arguments", "await", "boolean", "break", "byte", "case", "catch",
    "char", "class", "const", "continue", "debugger", "default", "delete", "do",
    "double", "else", "enum", "eval", "export", "extends", "false", "final",
    "finally", "float", "for", "function", "goto", "if", "implements", "import",
    "in", "instanceof", "int", "interface", "let", "long", "native", "new",
    "null", "package", "private", "protected", "public", "return", "short",
    "static", "super", "switch", "synchronized", "this", "throw", "throws",
    "transient", "true", "try", "typeof", "var", "void", "volatile", "while",
    "with", "yield", "undefined", "nan", "infinity"
}

def extract_script_variables(script_content: str) -> Set[str]:
    found: Set[str] = set()
    if not script_content:
        return found

    decl_matches = re.finditer(r"\b(?:let|const|var)\s+([^;{\n]+)", script_content)
    for m in decl_matches:
        clause = m.group(1)
        for part in clause.split(","):
            id_m = re.match(r"^\s*([a-zA-Z_$][a-zA-Z0-9_$]*)", part)
            if id_m:
                var_name = id_m.group(1)
                if var_name.lower() not in JS_RESERVED_WORDS and len(var_name) >= 1:
                    found.add(var_name)

    win_matches = re.finditer(r"\bwindow\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=", script_content)
    for m in win_matches:
        var_name = m.group(1)
        if var_name.lower() not in JS_RESERVED_WORDS and len(var_name) >= 1:
            found.add(var_name)

    param_matches = re.finditer(r"\b(?:get|has|getParameter)\s*\(\s*['\"]([a-zA-Z0-9_$-]+)['\"]\s*\)", script_content)
    for m in param_matches:
        p_name = m.group(1)
        if p_name.lower() not in JS_RESERVED_WORDS and len(p_name) >= 1:
            found.add(p_name)

    return found

def generate_probe_map(param_list: List[str]) -> Dict[str, str]:
    probe_map = {}
    used = set()
    for p in param_list:
        while True:
            token = generate_random_string(9)
            if token not in used:
                used.add(token)
                probe_map[p] = token
                break
    return probe_map

async def probe_param_reflection_get(
    page,
    endpoint: str,
    param_list: List[str],
    label: str = "general",
    logger: Optional[Logger] = None,
) -> Dict[str, str]:
    if not param_list:
        return {}

    t0 = time.perf_counter()
    probe_map = generate_probe_map(param_list)
    parsed = urlparse(endpoint)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for p, val in probe_map.items():
        qs[p] = [val]
    flat = [(k, v_item) for k, v_list in qs.items() for v_item in v_list]
    new_query = urlencode(flat)
    port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    probe_url = f"{parsed.scheme}://{parsed.hostname}{port_part}{parsed.path or '/'}?{new_query}"

    html = ""
    try:
        await page.goto(probe_url, wait_until="domcontentloaded", timeout=12000)
        html = await page.content()
    except Exception:
        try:
            resp = await page.request.get(probe_url, timeout=10000)
            html = await resp.text()
        except Exception:
            pass

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    if not html:
        if logger:
            logger.debug(f"GET {label}: probed {len(param_list)} parameter(s) in {elapsed_ms}ms -> no response")
        return {}

    reflected = {p: token for p, token in probe_map.items() if token in html}

    if logger:
        logger.debug(f"GET {label}: probed {len(param_list)} parameter(s) in {elapsed_ms}ms -> {len(reflected)} reflected")

    if len(reflected) > 5 or len(reflected) >= max(4, int(len(probe_map) * 0.4)):
        sampled_keys = random.sample(list(reflected.keys()), min(3, len(reflected)))
        if logger:
            logger.debug(f"echo suppression triggered on {label} GET ({len(reflected)} reflected) -> downsampled to: {sampled_keys}")
        return {k: reflected[k] for k in sampled_keys}

    return reflected

async def probe_wordlist_reflection_get(
    page,
    endpoint: str,
    param_list: List[str],
    chunk_size: int = 20,
    logger: Optional[Logger] = None,
) -> Dict[str, str]:
    if not param_list:
        return {}

    t0 = time.perf_counter()
    chunks = [param_list[i:i + chunk_size] for i in range(0, len(param_list), chunk_size)]
    if logger:
        logger.debug(f"probing {len(param_list)} wordlist parameter(s) on GET in {len(chunks)} request(s) ({chunk_size} params/req)...")

    all_reflected: Dict[str, str] = {}
    parsed = urlparse(endpoint)
    port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    base_probe_url = f"{parsed.scheme}://{parsed.hostname}{port_part}{parsed.path or '/'}"

    for idx, chunk in enumerate(chunks, 1):
        probe_map = generate_probe_map(chunk)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for p, val in probe_map.items():
            qs[p] = [val]
        flat = [(k, v_item) for k, v_list in qs.items() for v_item in v_list]
        new_query = urlencode(flat)
        probe_url = f"{base_probe_url}?{new_query}"

        html = ""
        try:
            await page.goto(probe_url, wait_until="domcontentloaded", timeout=12000)
            html = await page.content()
        except Exception:
            try:
                resp = await page.request.get(probe_url, timeout=10000)
                html = await resp.text()
            except Exception:
                pass

        if html:
            for p, token in probe_map.items():
                if token in html:
                    all_reflected[p] = token

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    if logger:
        logger.debug(f"GET wordlist: probed {len(param_list)} parameter(s) in {elapsed_ms}ms -> {len(all_reflected)} reflected")

    if len(all_reflected) > 6:
        total_probed = len(param_list)
        if len(all_reflected) >= max(6, int(total_probed * 0.4)) or len(all_reflected) >= 15:
            sampled_keys = random.sample(list(all_reflected.keys()), 6)
            if logger:
                logger.debug(f"echo suppression triggered on wordlist GET ({len(all_reflected)} reflected) -> downsampled to: {sampled_keys}")
            all_reflected = {k: all_reflected[k] for k in sampled_keys}

    return all_reflected

async def probe_wordlist_reflection_post(
    page,
    endpoint: str,
    param_list: List[str],
    chunk_size: int = 20,
    logger: Optional[Logger] = None,
) -> Dict[str, str]:
    if not param_list:
        return {}

    t0 = time.perf_counter()
    chunks = [param_list[i:i + chunk_size] for i in range(0, len(param_list), chunk_size)]
    if logger:
        logger.debug(f"probing {len(param_list)} wordlist parameter(s) on POST in {len(chunks)} request(s) ({chunk_size} params/req)...")

    all_reflected: Dict[str, str] = {}
    parsed = urlparse(endpoint)
    port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    query_part = f"?{parsed.query}" if parsed.query else ""
    post_url = f"{parsed.scheme}://{parsed.hostname}{port_part}{parsed.path or '/'}{query_part}"

    for idx, chunk in enumerate(chunks, 1):
        probe_map = generate_probe_map(chunk)
        html = ""
        try:
            resp = await page.request.post(post_url, form=probe_map, timeout=12000)
            html = await resp.text()
        except Exception:
            pass

        if html:
            for p, token in probe_map.items():
                if token in html:
                    all_reflected[p] = token

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    if logger:
        logger.debug(f"POST wordlist: probed {len(param_list)} parameter(s) in {elapsed_ms}ms -> {len(all_reflected)} reflected")

    if len(all_reflected) > 6:
        total_probed = len(param_list)
        if len(all_reflected) >= max(6, int(total_probed * 0.4)) or len(all_reflected) >= 15:
            sampled_keys = random.sample(list(all_reflected.keys()), 6)
            if logger:
                logger.debug(f"echo suppression triggered on wordlist POST ({len(all_reflected)} reflected) -> downsampled to: {sampled_keys}")
            all_reflected = {k: all_reflected[k] for k in sampled_keys}

    return all_reflected

async def probe_param_reflection_post(
    page,
    endpoint: str,
    param_list: List[str],
    label: str = "general",
    logger: Optional[Logger] = None,
) -> Dict[str, str]:
    if not param_list:
        return {}

    t0 = time.perf_counter()
    probe_map = generate_probe_map(param_list)
    parsed = urlparse(endpoint)
    port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    query_part = f"?{parsed.query}" if parsed.query else ""
    post_url = f"{parsed.scheme}://{parsed.hostname}{port_part}{parsed.path or '/'}{query_part}"

    html = ""
    try:
        resp = await page.request.post(post_url, form=probe_map, timeout=12000)
        html = await resp.text()
    except Exception:
        pass

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    if not html:
        if logger:
            logger.debug(f"POST {label}: probed {len(param_list)} parameter(s) in {elapsed_ms}ms -> no response")
        return {}

    reflected = {p: token for p, token in probe_map.items() if token in html}

    if logger:
        logger.debug(f"POST {label}: probed {len(param_list)} parameter(s) in {elapsed_ms}ms -> {len(reflected)} reflected")

    if len(reflected) > 5 or len(reflected) >= max(4, int(len(probe_map) * 0.4)):
        sampled_keys = random.sample(list(reflected.keys()), min(3, len(reflected)))
        if logger:
            logger.debug(f"echo suppression triggered on {label} POST ({len(reflected)} reflected) -> downsampled to: {sampled_keys}")
        return {k: reflected[k] for k in sampled_keys}

    return reflected

async def run_parameter_mining(
    page,
    target_url: str,
    custom_postfields: Optional[Dict[str, str]] = None,
    exclude_params: Optional[List[str]] = None,
    wordlist_params: Optional[List[str]] = None,
    logger: Optional[Logger] = None,
) -> List[Parameter]:
    if logger:
        logger.action(f"starting parameter discovery on target: {target_url}")

    user_exclude_set = set(p.lower() for p in exclude_params) if exclude_params else set()
    active_excluded_dom = list(EXCLUDED_VARS)
    if user_exclude_set:
        active_excluded_dom.extend(list(user_exclude_set))

    t0 = time.perf_counter()
    await page.goto(target_url, wait_until="commit", timeout=15000)

    try:
        await page.wait_for_load_state("domcontentloaded", timeout=4000)
    except Exception:
        pass

    html_content = await page.content()
    soup = BeautifulSoup(html_content, "html.parser")
    nav_ms = int((time.perf_counter() - t0) * 1000)

    if logger:
        logger.debug(f"target page loaded in {nav_ms}ms (DOM size: {len(html_content)} bytes)")

    parameters: List[Parameter] = []
    seen: Set[tuple] = set()

    parsed_base = urlparse(target_url)
    origin_path = f"{parsed_base.scheme}://{parsed_base.netloc}{parsed_base.path}"
    if not origin_path.endswith("/") and not parsed_base.path:
        origin_path += "/"

    query_dict = extract_query_dict(target_url)
    for name, val in query_dict.items():
        if name.lower() in user_exclude_set:
            continue
        dedup_key = ("GET", origin_path.lower(), name.lower())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        parameters.append(Parameter(
            param_name=name,
            param_value=val or generate_random_string(9),
            action_url=origin_path,
            location="GET",
        ))

    if logger:
        logger.debug(f"extracted {len(query_dict)} query parameter(s) directly from URL")

    forms = soup.find_all("form")
    for form in forms:
        method = (form.get("method") or "GET").upper()
        raw_action = form.get("action")
        action_url = resolve_action_url(raw_action, target_url)

        for input_tag in form.find_all(["input", "textarea", "select"]):
            name = input_tag.get("name")
            if not name or name.lower() in user_exclude_set:
                continue

            loc = "POST" if method == "POST" else "GET"
            dedup_key = (loc, action_url.lower(), name.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            parameters.append(Parameter(
                param_name=name,
                param_value=input_tag.get("value") or generate_random_string(9),
                action_url=action_url,
                location=loc,
            ))

    if logger:
        logger.debug(f"scanned {len(forms)} HTML form(s)")

    script_vars: Set[str] = set()
    for s_tag in soup.find_all("script"):
        content = s_tag.string or s_tag.get_text() or ""
        if content.strip():
            script_vars.update(extract_script_variables(content))

    for v in sorted(script_vars):
        if is_excluded_param(v, active_excluded_dom, EXCLUDED_VARS_REGEX):
            continue
        dedup_key = ("DOM", origin_path.lower(), v.lower())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        parameters.append(Parameter(
            param_name=v,
            param_value=generate_random_string(9),
            action_url=origin_path,
            location="DOM",
        ))

    if logger:
        logger.debug(f"extracted {len(script_vars)} DOM variable(s) from script tags: {sorted(list(script_vars))}")

    try:
        js_vars = await page.evaluate("() => Object.keys(window)")
        filtered_js_vars = [
            v for v in js_vars
            if not is_excluded_param(v, active_excluded_dom, EXCLUDED_VARS_REGEX)
            and v.lower() not in JS_RESERVED_WORDS
        ]

        random_slice = random.randint(10, 15)
        for v in filtered_js_vars[:random_slice]:
            dedup_key = ("DOM", origin_path.lower(), v.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            parameters.append(Parameter(
                param_name=v,
                param_value=generate_random_string(9),
                action_url=origin_path,
                location="DOM",
            ))
        if logger:
            logger.debug(f"window inspect: sampled {len(filtered_js_vars[:random_slice])} global properties from {len(js_vars)} keys")
    except Exception as err:
        if logger:
            logger.debug(f"could not inspect window variables: {err}")

    user_exclude_set = set(p.lower() for p in exclude_params) if exclude_params else set()
    if wordlist_params:
        active_wordlist = [
            p for p in wordlist_params
            if p.lower() not in user_exclude_set
        ]
        reflected_wl_get = await probe_wordlist_reflection_get(page, target_url, active_wordlist, 20, logger)
        for p, val in reflected_wl_get.items():
            dedup_key = ("GET", origin_path.lower(), p.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            parameters.append(Parameter(
                param_name=p,
                param_value=val,
                action_url=origin_path,
                location="GET",
            ))

        reflected_wl_post = await probe_wordlist_reflection_post(page, target_url, active_wordlist, 20, logger)
        for p, val in reflected_wl_post.items():
            dedup_key = ("POST", origin_path.lower(), p.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            parameters.append(Parameter(
                param_name=p,
                param_value=val,
                action_url=origin_path,
                location="POST",
            ))
    else:
        active_general = [
            p for p in GENERAL_PARAMS
            if p.lower() not in user_exclude_set
        ]
        active_redirect = [
            p for p in REDIRECT_PARAMS
            if p.lower() not in user_exclude_set
        ]

        reflected_gen_get = await probe_param_reflection_get(page, target_url, active_general, "GENERAL_PARAMS", logger)
        for p, val in reflected_gen_get.items():
            dedup_key = ("GET", origin_path.lower(), p.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            parameters.append(Parameter(
                param_name=p,
                param_value=val,
                action_url=origin_path,
                location="GET",
            ))

        reflected_gen_post = await probe_param_reflection_post(page, target_url, active_general, "GENERAL_PARAMS", logger)
        for p, val in reflected_gen_post.items():
            dedup_key = ("POST", origin_path.lower(), p.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            parameters.append(Parameter(
                param_name=p,
                param_value=val,
                action_url=origin_path,
                location="POST",
            ))

        reflected_redir_get = await probe_param_reflection_get(page, target_url, active_redirect, "REDIRECT_PARAMS", logger)
        for p, val in reflected_redir_get.items():
            dedup_key = ("GET", origin_path.lower(), p.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            parameters.append(Parameter(
                param_name=p,
                param_value=val,
                action_url=origin_path,
                location="GET",
            ))

        reflected_redir_post = await probe_param_reflection_post(page, target_url, active_redirect, "REDIRECT_PARAMS", logger)
        for p, val in reflected_redir_post.items():
            dedup_key = ("POST", origin_path.lower(), p.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            parameters.append(Parameter(
                param_name=p,
                param_value=val,
                action_url=origin_path,
                location="POST",
            ))

    if custom_postfields:
        for name, val in custom_postfields.items():
            if name.lower() in user_exclude_set:
                continue
            dedup_key = ("POST", origin_path.lower(), name.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            parameters.append(Parameter(
                param_name=name,
                param_value=val or generate_random_string(9),
                action_url=origin_path,
                location="POST",
            ))

    if exclude_params:
        user_exclude_set = set(p.lower() for p in exclude_params)
        parameters = [p for p in parameters if p.param_name.lower() not in user_exclude_set]

    if logger and not getattr(logger, "silent", False):
        logger.info(f"parameter discovery completed: found {len(parameters)} parameter(s)")
        for p in parameters:
            loc_tag = f"[{p.location}]"
            colored_param = f"\033[38;5;116m'{p.param_name}'\033[0m"
            colored_url = f"\033[38;5;110m{p.action_url}\033[0m"
            print(f"\033[1m\033[32m[+]\033[0m {loc_tag} {colored_param} -> {colored_url}")

    return parameters
