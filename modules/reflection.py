from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional
import asyncio
import time

from models import Parameter, ReflectionResult
from detection.reflection import detect_all_reflections
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

async def run_reflection_engine(
    page,
    parameters: List[Parameter],
    logger: Optional[Logger] = None,
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
