from typing import List, Optional, Set
import asyncio
import time

from models import Parameter, XSSFinding, ScanConfig
from payloads.xss import get_payload_data
from detection.context import resolve_context_name, get_payload_keys_for_context
from detection.confidence import calculate_confidence
from utils.helpers import build_payloaded_url, detect_match, async_delay, clean_error_text, get_current_time
from utils.logger import Logger

async def run_get_dom_xss(
    page,
    parameters: List[Parameter],
    config: ScanConfig,
    logger: Optional[Logger] = None,
    waf_manager: Optional[Any] = None,
    ai_analyzer: Optional[Any] = None,
) -> List[XSSFinding]:
    if logger:
        logger.action("testing for reflected XSS vulnerabilities (GET & DOM)...")

    findings: List[XSSFinding] = []
    tested_payloads: Set[tuple] = set()
    tested_params: Set[tuple] = set()

    target_params = [p for p in parameters if p.location in ("GET", "DOM")]

    for param in target_params:
        param_dedup_key = (param.action_url.lower(), param.param_name.lower())
        if param_dedup_key in tested_params:
            continue
        tested_params.add(param_dedup_key)

        if param.custom_context:
            context_name = param.custom_context
        elif param.reflections:
            reflected_ctx = [r.context for r in param.reflections if r.reflected and r.context != "unknown"]
            if reflected_ctx:
                context_name = resolve_context_name(reflected_ctx[0], param.location)
            else:
                context_name = "dom_js_html" if param.location == "DOM" else "html"
        else:
            context_name = "dom_js_html" if param.location == "DOM" else "html"

        is_ai_only = getattr(config, "ai_only", False) and getattr(config, "ai_enabled", False) and bool(ai_analyzer)
        payload_keys = [] if is_ai_only else get_payload_keys_for_context(context_name)
        if not payload_keys and not is_ai_only:
            continue

        if logger:
            logger.start_param_test(param.param_name, param.location, context_name)
            if is_ai_only:
                logger.debug(f"AI-only mode: skipping standard payload list for '{param.param_name}' [{param.location}]")
            else:
                logger.debug(f"queueing {len(payload_keys)} payload(s) for '{param.param_name}' [{param.location}] in {context_name} context")

        for payload_key in payload_keys:
            test_key = (param.action_url.lower(), param.param_name.lower(), payload_key)
            if test_key in tested_payloads:
                continue
            tested_payloads.add(test_key)

            payload_data = get_payload_data(payload_key)
            if not payload_data:
                continue

            await async_delay(config.delay_min, config.delay_max)

            poc_url = build_payloaded_url(
                param.action_url,
                param.param_name,
                payload_data.payload,
            )

            xs_scan = 0
            xs_match = 0
            text = ""
            response_url = None
            response_headers = None

            async def handle_dialog(dialog):
                nonlocal xs_scan
                d_type = dialog.type
                d_msg = dialog.message.strip()

                if logger:
                    logger.debug(f"dialog event intercepted: {d_type}('{d_msg}')")

                if (
                    d_type.lower() == payload_data.dialog_type.lower()
                    and d_msg == str(payload_data.expected_value).strip()
                ):
                    xs_scan = 1
                    if logger:
                        logger.debug(f"dialog confirmed matching signature: {d_type}('{d_msg}')")

                try:
                    await dialog.accept()
                except Exception:
                    pass

            page.on("dialog", handle_dialog)
            t0 = time.perf_counter()

            try:
                response = await page.goto(
                    poc_url,
                    wait_until="domcontentloaded",
                    timeout=config.timeout_ms,
                )

                try:
                    await page.wait_for_load_state("networkidle", timeout=3000)
                except Exception:
                    pass

                elapsed_ms = int((time.perf_counter() - t0) * 1000)
                response_url = page.url
                status_code = response.status if response else 0
                if response:
                    response_headers = await response.all_headers()
                    text = f"HTTP {response.status} {response.status_text}"

                rendered_html = await page.content()
                if logger:
                    logger.debug(f"probe '{payload_data.name}' returned HTTP {status_code} ({len(rendered_html)} chars) in {elapsed_ms}ms")

                if waf_manager and response:
                    await waf_manager.handle_response(status_code, response_headers, rendered_html, config)

                if not xs_scan and getattr(payload_data, "check_for_match", 1) == 1:
                    if detect_match(rendered_html, payload_data):
                        xs_match = 1
                        if logger:
                            logger.debug(f"DOM match confirmed for payload '{payload_data.name}'")

            except Exception as err:
                text = clean_error_text(str(err))
                if logger:
                    logger.debug(f"request error for '{payload_data.name}': {text}")
            finally:
                page.remove_listener("dialog", handle_dialog)

            final_xss = 1 if xs_scan else 0
            final_confidence = calculate_confidence(xs_scan, xs_match)

            finding = XSSFinding(
                endpoint=param.action_url,
                param_name=param.param_name,
                context=context_name,
                payload_name=payload_data.name,
                payload_key=payload_key,
                payload_value=payload_data.payload,
                request_method=param.location,
                request_url=poc_url,
                xss=final_xss,
                confidence=final_confidence,
                xs_scan=xs_scan,
                xs_match=xs_match,
                response_url=response_url,
                response_headers=response_headers,
                text=text,
                created_at=get_current_time(),
                proof_of_concept=poc_url,
            )

            executed_dialog = (
                f"{payload_data.dialog_type}('{payload_data.expected_value}')"
                if xs_scan
                else None
            )

            if logger:
                logger.test_block(
                    method=param.location,
                    param_name=param.param_name,
                    context=context_name,
                    payload_name=payload_data.name,
                    payload_str=payload_data.payload,
                    request_desc=f"GET {poc_url}",
                    confidence=final_confidence,
                    dialog=executed_dialog,
                    is_xss=bool(final_xss),
                    is_match=bool(xs_match and not final_xss),
                )

            if final_xss:
                findings.append(finding)
                if logger:
                    logger.debug(f"verified XSS found for '{param.param_name}', halting further tests for this param")
                break
            elif xs_match:
                findings.append(finding)

            await async_delay(config.delay_min, config.delay_max)

        has_verified_xss = any(f.param_name == param.param_name and f.xss == 1 for f in findings)
        should_run_ai = (not has_verified_xss or is_ai_only) and ai_analyzer and getattr(config, "ai_enabled", False)
        if should_run_ai:
            if any(r.reflected for r in param.reflections):
                if "rendered_html" in locals() and rendered_html:
                    last_html = rendered_html
                else:
                    try:
                        resp = await page.goto(param.action_url, wait_until="domcontentloaded", timeout=config.timeout_ms)
                        last_html = await page.content()
                    except Exception:
                        last_html = ""
                last_token = payload_data.payload if "payload_data" in locals() and payload_data else (param.param_value or param.param_name)
                ai_payloads = await ai_analyzer.generate_bypass_payloads(
                    endpoint=param.action_url,
                    param_name=param.param_name,
                    location=param.location,
                    context=context_name,
                    char_matrix=param.char_matrix,
                    html=last_html,
                    reflected_token=last_token,
                )
                for ai_idx, ai_p in enumerate(ai_payloads, 1):
                    await async_delay(config.delay_min, config.delay_max)
                    poc_url = build_payloaded_url(
                        param.action_url,
                        param.param_name,
                        ai_p,
                    )
                    xs_scan = 0
                    text = ""
                    response_url = None
                    response_headers = None

                    async def handle_ai_dialog(dialog):
                        nonlocal xs_scan
                        xs_scan = 1
                        try:
                            await dialog.accept()
                        except Exception:
                            pass

                    page.on("dialog", handle_ai_dialog)
                    try:
                        resp = await page.goto(
                            poc_url,
                            wait_until="domcontentloaded",
                            timeout=config.timeout_ms,
                        )
                        try:
                            await page.wait_for_load_state("networkidle", timeout=3000)
                        except Exception:
                            pass
                        response_url = page.url
                        status_code = resp.status if resp else 0
                        if resp:
                            response_headers = await resp.all_headers()
                            text = f"HTTP {resp.status} {resp.status_text}"
                        r_html = await page.content()
                        if waf_manager and resp:
                            await waf_manager.handle_response(status_code, response_headers, r_html, config)
                    except Exception as err:
                        text = clean_error_text(str(err))
                    finally:
                        page.remove_listener("dialog", handle_ai_dialog)

                    final_xss = 1 if xs_scan else 0
                    final_conf = 10.0 if xs_scan else 0.0

                    p_label = f"AI Payload #{ai_idx} [{ai_analyzer.model}]" if is_ai_only else f"AI Bypass #{ai_idx} [{ai_analyzer.model}]"
                    if logger:
                        logger.test_block(
                            method=param.location,
                            param_name=param.param_name,
                            context=context_name,
                            payload_name=p_label,
                            payload_str=ai_p,
                            request_desc=f"GET {poc_url}",
                            confidence=final_conf,
                            dialog="alert('1')" if xs_scan else None,
                            is_xss=bool(final_xss),
                            is_match=False,
                        )

                    if final_xss:
                        p_find_label = f"AI Payload #{ai_idx} [{ai_analyzer.model}]" if is_ai_only else f"AI Bypass #{ai_idx} [{ai_analyzer.model}]"
                        ai_finding = XSSFinding(
                            endpoint=param.action_url,
                            param_name=param.param_name,
                            context=context_name,
                            payload_name=p_find_label,
                            payload_key=f"ai_assisted_{ai_idx}",
                            payload_value=ai_p,
                            request_method=param.location,
                            request_url=poc_url,
                            xss=1,
                            confidence=10.0,
                            xs_scan=1,
                            xs_match=0,
                            response_url=response_url,
                            response_headers=response_headers,
                            text=text,
                            created_at=get_current_time(),
                            proof_of_concept=poc_url,
                        )
                        findings.append(ai_finding)

    return findings
