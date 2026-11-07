from typing import List, Optional, Set, Dict
import asyncio
import time

from models import XSSFinding, ScanConfig
from config import XSS_HEADERS
from payloads.xss import get_payload_data, XSSR_CONTEXT_MAP
from detection.confidence import calculate_confidence
from browser.playwright import BrowserManager
from utils.helpers import detect_match, async_delay, clean_error_text, get_current_time
from utils.logger import Logger

def build_target_headers(
    base_headers: Dict[str, List[str]],
    include_headers: List[str],
    exclude_headers: List[str],
) -> Dict[str, List[str]]:
    headers_dict = dict(base_headers)

    for inc in include_headers:
        cleaned = inc.strip()
        if not cleaned:
            continue
        exists = next((k for k in headers_dict if k.lower() == cleaned.lower()), None)
        if not exists:
            c_low = cleaned.lower()
            if "user-agent" in c_low or "useragent" in c_low:
                ctx = ["header_based_useragent"]
            elif "cookie" in c_low:
                ctx = ["header_based_cookie"]
            elif any(k in c_low for k in ("referer", "url", "uri")):
                ctx = ["header_based_url"]
            else:
                ctx = ["header_based_host", "header_based_basic"]
            headers_dict[cleaned] = ctx

    if exclude_headers:
        exclude_set = set(h.strip().lower() for h in exclude_headers if h.strip())
        headers_dict = {
            k: v for k, v in headers_dict.items()
            if k.lower() not in exclude_set
        }

    return headers_dict

async def run_header_based_xss(
    browser_manager: BrowserManager,
    target_url: str,
    config: ScanConfig,
    logger: Optional[Logger] = None,
    waf_manager: Optional[Any] = None,
) -> List[XSSFinding]:
    active_headers = build_target_headers(
        base_headers=XSS_HEADERS,
        include_headers=config.include_headers,
        exclude_headers=config.exclude_headers,
    )

    if logger:
        logger.action(f"testing HTTP header injection points ({len(active_headers)} headers)...")
        if config.include_headers:
            logger.debug(f"custom included headers: {', '.join(config.include_headers)}")
        if config.exclude_headers:
            logger.debug(f"custom excluded headers: {', '.join(config.exclude_headers)}")

    findings: List[XSSFinding] = []
    tested_headers: Set[tuple] = set()

    for header_name, contexts in active_headers.items():
        payload_keys = []
        for ctx in contexts:
            payload_keys.extend(XSSR_CONTEXT_MAP.get(ctx, []))

        if logger and payload_keys:
            logger.start_param_test(header_name, "HEADER", "http_header")
            logger.debug(f"queueing {len(payload_keys)} payload(s) for header '{header_name}'")

        for payload_key in payload_keys:
            test_key = (header_name.lower(), target_url.lower(), payload_key)
            if test_key in tested_headers:
                continue
            tested_headers.add(test_key)

            payload_data = get_payload_data(payload_key)
            if not payload_data:
                continue

            await async_delay(config.delay_min, config.delay_max)

            extra_headers = {}
            custom_ua = None

            if header_name.lower() == "user-agent":
                custom_ua = payload_data.payload
            else:
                extra_headers[header_name] = payload_data.payload

            try:
                context = await browser_manager.create_context(
                    extra_headers=extra_headers,
                    custom_user_agent=custom_ua,
                )
            except Exception as err:
                if logger:
                    logger.debug(f"header context error for '{header_name}': {err}")
                continue

            page = await context.new_page()

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
                    logger.debug(f"header dialog intercepted: {d_type}('{d_msg}')")

                if (
                    d_type.lower() == payload_data.dialog_type.lower()
                    and d_msg == str(payload_data.expected_value).strip()
                ):
                    xs_scan = 1
                    if logger:
                        logger.debug(f"header dialog matched signature: {d_type}('{d_msg}')")

                try:
                    await dialog.accept()
                except Exception:
                    pass

            page.on("dialog", handle_dialog)
            t0 = time.perf_counter()

            try:
                response = await page.goto(
                    target_url,
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
                    logger.debug(f"header probe '{header_name}' returned HTTP {status_code} ({len(rendered_html)} chars) in {elapsed_ms}ms")

                if waf_manager and response:
                    await waf_manager.handle_response(status_code, response_headers, rendered_html, config)

                if not xs_scan and getattr(payload_data, "check_for_match", 1) == 1:
                    if detect_match(rendered_html, payload_data):
                        xs_match = 1
                        if logger:
                            logger.debug(f"DOM match confirmed for header '{header_name}' payload '{payload_data.name}'")

            except Exception as err:
                text = clean_error_text(str(err))
                if logger:
                    logger.debug(f"header test error: {text}")
            finally:
                page.remove_listener("dialog", handle_dialog)
                try:
                    await context.close()
                except Exception:
                    pass

            final_xss = 1 if xs_scan else 0
            final_confidence = calculate_confidence(xs_scan, xs_match)

            finding = XSSFinding(
                endpoint=target_url,
                param_name=f"Header: {header_name}",
                context="header_based",
                payload_name=payload_data.name,
                payload_key=payload_key,
                payload_value=payload_data.payload,
                request_method="HEADER",
                request_url=target_url,
                xss=final_xss,
                confidence=final_confidence,
                xs_scan=xs_scan,
                xs_match=xs_match,
                response_url=response_url,
                response_headers=response_headers,
                text=text,
                created_at=get_current_time(),
                proof_of_concept=f"{header_name}: {payload_data.payload}",
            )

            executed_dialog = (
                f"{payload_data.dialog_type}('{payload_data.expected_value}')"
                if xs_scan
                else None
            )

            if logger:
                logger.test_block(
                    method="HEADER",
                    param_name=header_name,
                    context="http_header",
                    payload_name=payload_data.name,
                    payload_str=payload_data.payload,
                    request_desc=f"GET {target_url}",
                    header_info=f"{header_name}: {payload_data.payload}",
                    confidence=final_confidence,
                    dialog=executed_dialog,
                    is_xss=bool(final_xss),
                    is_match=bool(xs_match and not final_xss),
                )

            if final_xss:
                findings.append(finding)
                if logger:
                    logger.debug(f"verified header XSS found for '{header_name}', halting further tests for this header")
                break
            elif xs_match:
                findings.append(finding)

            await async_delay(config.delay_min, config.delay_max)

    return findings
