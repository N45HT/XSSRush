from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional
import asyncio
import time

from models import Parameter, ReflectionResult
from detection.reflection import detect_all_reflections
from detection.matrix import build_matrix_probe, analyze_character_matrix
from utils.helpers import generate_random_string, clean_error_text
from utils.logger import Logger

def build_get_url(base_url: str, params: List[Parameter]) -> str:
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for p in params:
        qs[p.param_name] = [p.param_value or ""]

    flat = [(k, v_item) for k, v_list in qs.items() for v_item in v_list]
    new_query = urlencode(flat)
    port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    return f"{parsed.scheme}://{parsed.hostname}{port_part}{parsed.path or '/'}?{new_query}"

def build_post_data(params: List[Parameter]) -> str:
    items = [(p.param_name, p.param_value or "") for p in params]
    return urlencode(items)

async def _probe_get_matrix(page, endpoint, reflected_params, logger, waf_manager, config):
    matrix_tokens = {p.param_name: f"m{generate_random_string(4)}" for p in reflected_params}
    probe_params = [
        Parameter(
            param_name=p.param_name,
            param_value=build_matrix_probe(matrix_tokens[p.param_name]),
            location=p.location,
            action_url=p.action_url,
        )
        for p in reflected_params
    ]
    matrix_url = build_get_url(endpoint, probe_params)
    try:
        m_resp = await page.goto(matrix_url, wait_until="domcontentloaded", timeout=15000)
        await page.wait_for_timeout(1000)
        m_raw = ""
        try:
            m_raw = await m_resp.text() if m_resp else ""
        except Exception:
            pass
        m_dom = await page.evaluate("() => document.documentElement.outerHTML")
        m_combined = f"{m_raw}\n{m_dom}"
        if waf_manager and m_resp and config:
            m_headers = await m_resp.all_headers()
            await waf_manager.handle_response(m_resp.status, m_headers, m_combined, config)
        for p in reflected_params:
            tok = matrix_tokens.get(p.param_name)
            if tok:
                p.char_matrix = analyze_character_matrix(m_combined, tok)
                if logger:
                    logger.char_matrix(p.param_name, p.char_matrix)
    except Exception as err:
        if logger:
            logger.debug(f"GET matrix probe failed on {endpoint}: {clean_error_text(str(err))}")

async def _probe_post_matrix(page, endpoint, post_params, reflected_params, form_index, logger, waf_manager, config):
    matrix_tokens = {p.param_name: f"m{generate_random_string(4)}" for p in reflected_params}
    matrix_params_payload = [
        {
            "param_name": p.param_name,
            "param_value": build_matrix_probe(matrix_tokens[p.param_name]) if p.param_name in matrix_tokens else (p.param_value or ""),
        }
        for p in post_params
    ]
    try:
        if form_index != -1:
            await page.evaluate("""({ formIndex, params }) => {
                const form = document.querySelectorAll('form')[formIndex];
                for (const p of params) {
                    let input = form.querySelector(`[name="${p.param_name}"]`);
                    if (!input) {
                        input = document.createElement('input');
                        input.name = p.param_name;
                        form.appendChild(input);
                    }
                    input.value = p.param_value;
                }
            }""", {
                "formIndex": form_index,
                "params": matrix_params_payload,
            })
            try:
                async with page.expect_navigation(wait_until="domcontentloaded", timeout=15000) as m_nav:
                    await page.evaluate("""(formIndex) => {
                        document.querySelectorAll('form')[formIndex].requestSubmit();
                    }""", form_index)
                m_nav_resp = await m_nav.value
                if waf_manager and m_nav_resp and config:
                    m_headers = await m_nav_resp.all_headers()
                    m_body = await page.content()
                    await waf_manager.handle_response(m_nav_resp.status, m_headers, m_body, config)
            except Exception:
                await page.wait_for_timeout(2000)
        else:
            try:
                async with page.expect_navigation(wait_until="domcontentloaded", timeout=15000) as m_nav:
                    await page.evaluate("""({ action, params }) => {
                        const form = document.createElement('form');
                        form.method = 'POST';
                        form.action = action;
                        for (const p of params) {
                            const input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = p.param_name;
                            input.value = p.param_value;
                            form.appendChild(input);
                        }
                        document.body.appendChild(form);
                        form.submit();
                    }""", {
                        "action": endpoint,
                        "params": matrix_params_payload,
                    })
                m_nav_resp = await m_nav.value
                if waf_manager and m_nav_resp and config:
                    m_headers = await m_nav_resp.all_headers()
                    m_body = await page.content()
                    await waf_manager.handle_response(m_nav_resp.status, m_headers, m_body, config)
            except Exception:
                await page.wait_for_timeout(2000)

        await page.wait_for_timeout(1000)
        m_html = await page.content()
        for p in reflected_params:
            tok = matrix_tokens.get(p.param_name)
            if tok:
                p.char_matrix = analyze_character_matrix(m_html, tok)
                if logger:
                    logger.char_matrix(p.param_name, p.char_matrix)
    except Exception as err:
        if logger:
            logger.debug(f"POST matrix probe failed on {endpoint}: {clean_error_text(str(err))}")

async def _probe_dom_matrix(page, endpoint, dom_param, logger, waf_manager, config):
    tok = f"m{generate_random_string(4)}"
    m_param = Parameter(
        param_name=dom_param.param_name,
        param_value=build_matrix_probe(tok),
        location="DOM",
        action_url=endpoint,
    )
    m_url = build_get_url(endpoint, [m_param])
    try:
        m_resp = await page.goto(m_url, wait_until="domcontentloaded", timeout=15000)
        await page.wait_for_timeout(1000)
        m_dom = await page.evaluate("() => document.documentElement.outerHTML")
        if waf_manager and m_resp and config:
            m_headers = await m_resp.all_headers()
            await waf_manager.handle_response(m_resp.status, m_headers, m_dom, config)
        dom_param.char_matrix = analyze_character_matrix(m_dom, tok)
        if logger:
            logger.char_matrix(dom_param.param_name, dom_param.char_matrix)
    except Exception as err:
        if logger:
            logger.debug(f"DOM matrix probe failed: {clean_error_text(str(err))}")

async def run_reflection_engine(
    page,
    parameters: List[Parameter],
    logger: Optional[Logger] = None,
    waf_manager: Optional[Any] = None,
    config: Optional[Any] = None,
) -> List[Parameter]:
    if logger:
        logger.action(f"analyzing reflection and injection contexts for {len(parameters)} parameter(s)...")

    if not parameters:
        return []

    session_id = generate_random_string(8)

    for idx, param in enumerate(parameters):
        param.param_value = f"{session_id}{idx}"

    grouped: Dict[str, List[Parameter]] = {}
    for p in parameters:
        grouped.setdefault(p.action_url, []).append(p)

    for endpoint, params in grouped.items():
        get_params = [p for p in params if p.location == "GET"]
        post_params = [p for p in params if p.location == "POST"]
        dom_params = [p for p in params if p.location == "DOM"]

        if get_params:
            manual_get = [p for p in get_params if p.custom_context]
            probe_get = [p for p in get_params if not p.custom_context]

            for p in manual_get:
                p.reflections.append(ReflectionResult(
                    parameter_name=p.param_name,
                    reflected=True,
                    context=p.custom_context,
                    request_url=endpoint,
                    request_method="GET",
                ))
                p.tested = True
                if logger:
                    colored_name = f"\033[38;5;116m'{p.param_name}'\033[0m"
                    logger.success(f"[{p.location}] {colored_name} set to {p.custom_context.upper()} context (manual)")

            if probe_get:
                probe_url = build_get_url(endpoint, probe_get)
                if logger:
                    logger.debug(f"probing {len(probe_get)} GET param(s) on {endpoint} in single request")
                t0 = time.perf_counter()
                try:
                    response = await page.goto(probe_url, wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(2000)
                    html = await page.evaluate("() => document.documentElement.outerHTML")
                    elapsed_ms = int((time.perf_counter() - t0) * 1000)
                    status_code = response.status if response else 200
                    if logger:
                        logger.debug(f"GET reflection probe returned HTTP {status_code} ({len(html)} chars) in {elapsed_ms}ms")

                    if waf_manager and response and config:
                        m_headers = await response.all_headers()
                        await waf_manager.handle_response(status_code, m_headers, html, config)

                    status_text = f"HTTP {status_code}"
                    for p in probe_get:
                        reflections = detect_all_reflections(html, p.param_value)
                        p.tested = True
                        colored_name = f"\033[38;5;116m'{p.param_name}'\033[0m"

                        if reflections:
                            for ref in reflections:
                                p.reflections.append(ReflectionResult(
                                    parameter_name=p.param_name,
                                    reflected=True,
                                    context=ref["context"],
                                    tags=ref["tags"],
                                    request_url=probe_url,
                                    request_method="GET",
                                    text=status_text,
                                ))
                                if logger:
                                    tag_info = f" (tag: <{ref['tags']}>)" if ref['tags'] else ""
                                    logger.success(f"[{p.location}] {colored_name} reflects in {ref['context'].upper()} context{tag_info}")
                                    logger.debug(f"reflection detected: param='{p.param_name}' token='{p.param_value}' context={ref['context']} tag={ref['tags']}")
                        else:
                            p.reflections.append(ReflectionResult(
                                parameter_name=p.param_name,
                                reflected=False,
                                context="html",
                                request_url=probe_url,
                                request_method="GET",
                                text=status_text,
                            ))
                            if logger:
                                logger.neutral(f"[{p.location}] {colored_name} no reflection detected (default: HTML)")
                                logger.debug(f"reflection negative: param='{p.param_name}' token='{p.param_value}'")

                    reflected_get = [p for p in get_params if any(r.reflected for r in p.reflections)]
                    if reflected_get:
                        await _probe_get_matrix(page, endpoint, reflected_get, logger, waf_manager, config)
                except Exception as err:
                    if logger:
                        logger.debug(f"GET probe failed on {endpoint}: {clean_error_text(str(err))}")
                    for p in probe_get:
                        if not p.reflections:
                            p.reflections.append(ReflectionResult(
                                parameter_name=p.param_name,
                                reflected=False,
                                context="html",
                                request_url=endpoint,
                                request_method="GET",
                            ))
                            if logger:
                                colored_name = f"\033[38;5;116m'{p.param_name}'\033[0m"
                                logger.neutral(f"[{p.location}] {colored_name} no reflection detected (default: HTML)")

        if post_params:
            manual_post = [p for p in post_params if p.custom_context]
            probe_post = [p for p in post_params if not p.custom_context]

            for p in manual_post:
                p.reflections.append(ReflectionResult(
                    parameter_name=p.param_name,
                    reflected=True,
                    context=p.custom_context,
                    request_url=endpoint,
                    request_body=build_post_data(post_params),
                    request_method="POST",
                ))
                p.tested = True
                if logger:
                    colored_name = f"\033[38;5;116m'{p.param_name}'\033[0m"
                    logger.success(f"[{p.location}] {colored_name} set to {p.custom_context.upper()} context (manual)")

            if probe_post:
                if logger:
                    logger.debug(f"probing {len(probe_post)} POST param(s) on {endpoint}...")
                t0 = time.perf_counter()
                status_text = "HTTP 200"
                try:
                    try:
                        await page.goto(endpoint, wait_until="domcontentloaded", timeout=15000)
                    except Exception:
                        try:
                            await page.goto("about:blank", timeout=5000)
                        except Exception:
                            pass

                    form_index = -1
                    try:
                        form_index = await page.evaluate("""(params) => {
                            const forms = [...document.querySelectorAll('form')];
                            for (let i = 0; i < forms.length; i++) {
                                for (const p of params) {
                                    if (forms[i].querySelector(`[name="${p.param_name}"]`)) return i;
                                }
                            }
                            return -1;
                        }""", [{"param_name": p.param_name} for p in probe_post])
                    except Exception:
                        form_index = -1

                    if form_index != -1:
                        if logger:
                            logger.debug(f"found POST form at index {form_index} matching parameters")
                        await page.evaluate("""({ formIndex, params }) => {
                            const form = document.querySelectorAll('form')[formIndex];
                            for (const p of params) {
                                let input = form.querySelector(`[name="${p.param_name}"]`);
                                if (!input) {
                                    input = document.createElement('input');
                                    input.name = p.param_name;
                                    form.appendChild(input);
                                }
                                input.value = p.param_value;
                            }
                        }""", {
                            "formIndex": form_index,
                            "params": [{"param_name": p.param_name, "param_value": p.param_value} for p in probe_post],
                        })

                        try:
                            async with page.expect_navigation(wait_until="domcontentloaded", timeout=15000) as nav_info:
                                await page.evaluate("""(formIndex) => {
                                    document.querySelectorAll('form')[formIndex].requestSubmit();
                                }""", form_index)
                            nav_resp = await nav_info.value
                            if nav_resp:
                                status_text = f"HTTP {nav_resp.status}"
                        except Exception:
                            await page.wait_for_timeout(2000)
                    else:
                        if logger:
                            logger.debug(f"no physical HTML form on {endpoint}; submitting via synthetic dynamic form")
                        try:
                            async with page.expect_navigation(wait_until="domcontentloaded", timeout=15000) as nav_info:
                                await page.evaluate("""({ action, params }) => {
                                    const form = document.createElement('form');
                                    form.method = 'POST';
                                    form.action = action;
                                    for (const p of params) {
                                        const input = document.createElement('input');
                                        input.type = 'hidden';
                                        input.name = p.param_name;
                                        input.value = p.param_value;
                                        form.appendChild(input);
                                    }
                                    document.body.appendChild(form);
                                    form.submit();
                                }""", {
                                    "action": endpoint,
                                    "params": [{"param_name": p.param_name, "param_value": p.param_value} for p in probe_post],
                                })
                            nav_resp = await nav_info.value
                            if nav_resp:
                                status_text = f"HTTP {nav_resp.status}"
                        except Exception:
                            await page.wait_for_timeout(2000)

                    await page.wait_for_timeout(1000)
                    html = await page.content()
                    elapsed_ms = int((time.perf_counter() - t0) * 1000)
                    if logger:
                        logger.debug(f"POST reflection probe returned {status_text} ({len(html)} chars) in {elapsed_ms}ms")

                    if waf_manager and nav_resp and config:
                        m_headers = await nav_resp.all_headers()
                        await waf_manager.handle_response(nav_resp.status, m_headers, html, config)

                    for p in probe_post:
                        reflections = detect_all_reflections(html, p.param_value)
                        p.tested = True
                        colored_name = f"\033[38;5;116m'{p.param_name}'\033[0m"

                        if reflections:
                            for ref in reflections:
                                p.reflections.append(ReflectionResult(
                                    parameter_name=p.param_name,
                                    reflected=True,
                                    context=ref["context"],
                                    tags=ref["tags"],
                                    request_url=endpoint,
                                    request_body=build_post_data(probe_post),
                                    request_method="POST",
                                    text=status_text,
                                ))
                                if logger:
                                    tag_info = f" (tag: <{ref['tags']}>)" if ref['tags'] else ""
                                    logger.success(f"[{p.location}] {colored_name} reflects in {ref['context'].upper()} context{tag_info}")
                                    logger.debug(f"reflection detected: param='{p.param_name}' token='{p.param_value}' context={ref['context']} tag={ref['tags']}")
                        else:
                            p.reflections.append(ReflectionResult(
                                parameter_name=p.param_name,
                                reflected=False,
                                context="html",
                                request_url=endpoint,
                                request_body=build_post_data(probe_post),
                                request_method="POST",
                                text=status_text,
                            ))
                            if logger:
                                logger.neutral(f"[{p.location}] {colored_name} no reflection detected (default: HTML)")
                                logger.debug(f"reflection negative: param='{p.param_name}' token='{p.param_value}'")

                    reflected_post = [p for p in post_params if any(r.reflected for r in p.reflections)]
                    if reflected_post:
                        await _probe_post_matrix(page, endpoint, post_params, reflected_post, form_index, logger, waf_manager, config)
                except Exception as err:
                    if logger:
                        logger.debug(f"POST probe failed on {endpoint}: {clean_error_text(str(err))}")
                    for p in probe_post:
                        if not p.reflections:
                            p.reflections.append(ReflectionResult(
                                parameter_name=p.param_name,
                                reflected=False,
                                context="html",
                                request_url=endpoint,
                                request_method="POST",
                            ))
                            if logger:
                                colored_name = f"\033[38;5;116m'{p.param_name}'\033[0m"
                                logger.neutral(f"[{p.location}] {colored_name} no reflection detected (default: HTML)")

        for dom_param in dom_params:
            if dom_param.custom_context:
                dom_param.reflections.append(ReflectionResult(
                    parameter_name=dom_param.param_name,
                    reflected=True,
                    context=dom_param.custom_context,
                    request_url=endpoint,
                    request_method="GET",
                ))
                dom_param.tested = True
                if logger:
                    colored_name = f"\033[38;5;116m'{dom_param.param_name}'\033[0m"
                    logger.success(f"[{dom_param.location}] {colored_name} set to {dom_param.custom_context.upper()} context (manual)")
                continue

            probe_url = build_get_url(endpoint, [dom_param])
            if logger:
                logger.debug(f"probing DOM param '{dom_param.param_name}' on {probe_url}...")
            t0 = time.perf_counter()
            try:
                response = await page.goto(probe_url, wait_until="domcontentloaded", timeout=15000)
                await page.wait_for_timeout(2000)
                html = await page.evaluate("() => document.documentElement.outerHTML")
                elapsed_ms = int((time.perf_counter() - t0) * 1000)
                status_code = response.status if response else 200
                if logger:
                    logger.debug(f"DOM probe returned HTTP {status_code} ({len(html)} chars) in {elapsed_ms}ms")

                if waf_manager and response and config:
                    m_headers = await response.all_headers()
                    await waf_manager.handle_response(status_code, m_headers, html, config)

                reflections = detect_all_reflections(html, dom_param.param_value)
                dom_param.tested = True
                colored_name = f"\033[38;5;116m'{dom_param.param_name}'\033[0m"

                if reflections:
                    for ref in reflections:
                        dom_param.reflections.append(ReflectionResult(
                            parameter_name=dom_param.param_name,
                            reflected=True,
                            context=ref["context"],
                            tags=ref["tags"],
                            request_url=probe_url,
                            request_method="GET",
                        ))
                        if logger:
                            tag_info = f" (tag: <{ref['tags']}>)" if ref['tags'] else ""
                            logger.success(f"[{dom_param.location}] {colored_name} reflects in {ref['context'].upper()} context{tag_info}")
                            logger.debug(f"reflection detected: param='{dom_param.param_name}' token='{dom_param.param_value}' context={ref['context']} tag={ref['tags']}")
                    await _probe_dom_matrix(page, endpoint, dom_param, logger, waf_manager, config)
                else:
                    dom_param.reflections.append(ReflectionResult(
                        parameter_name=dom_param.param_name,
                        reflected=False,
                        context="dom_js_html",
                        request_url=probe_url,
                        request_method="GET",
                    ))
                    if logger:
                        logger.neutral(f"[{dom_param.location}] {colored_name} no reflection detected (default: DOM_JS_HTML)")
                        logger.debug(f"reflection negative: param='{dom_param.param_name}' token='{dom_param.param_value}'")
            except Exception as err:
                if logger:
                    logger.debug(f"DOM probe failed: {clean_error_text(str(err))}")
                dom_param.reflections.append(ReflectionResult(
                    parameter_name=dom_param.param_name,
                    reflected=False,
                    context="dom_js_html",
                    request_url=probe_url,
                    request_method="GET",
                ))
                if logger:
                    colored_name = f"\033[38;5;116m'{dom_param.param_name}'\033[0m"
                    logger.neutral(f"[{dom_param.location}] {colored_name} no reflection detected (default: DOM_JS_HTML)")

    return parameters
