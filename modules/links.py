from typing import List, Optional, Set
import asyncio
import time

from models import XSSFinding, ScanConfig
from payloads.xss import get_payload_data, XSSR_CONTEXT_MAP
from detection.confidence import calculate_confidence
from parsers.url import build_test_paths
from utils.helpers import (
    build_path_payload_url,
    detect_match,
    async_delay,
    clean_error_text,
    get_current_time,
)
from utils.logger import Logger

async def run_path_based_xss(
    page,
    target_url: str,
    config: ScanConfig,
    logger: Optional[Logger] = None,
) -> List[XSSFinding]:
    test_paths = build_test_paths(target_url)
    if not test_paths:
        return []

    if logger:
        logger.action(f"testing path-based injection points across {len(test_paths)} path segment(s)...")

    findings: List[XSSFinding] = []
    payload_keys = XSSR_CONTEXT_MAP.get("path_based", [])
    tested_paths: Set[tuple] = set()

    for test_path in test_paths:
        if logger:
            logger.start_param_test(test_path, "PATH", "path")
            logger.debug(f"queueing {len(payload_keys)} payload(s) for path '{test_path}'")

        for payload_key in payload_keys:
            test_key = (test_path.lower(), payload_key)
            if test_key in tested_paths:
                continue
            tested_paths.add(test_key)

            payload_data = get_payload_data(payload_key)
            if not payload_data:
                continue

            await async_delay(config.delay_min, config.delay_max)

            poc_url = build_path_payload_url(test_path, payload_data.payload)

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
                    logger.debug(f"path dialog intercepted: {d_type}('{d_msg}')")

                if (
                    d_type.lower() == payload_data.dialog_type.lower()
                    and d_msg == str(payload_data.expected_value).strip()
                ):
                    xs_scan = 1
                    if logger:
                        logger.debug(f"path dialog matched signature: {d_type}('{d_msg}')")

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
                    logger.debug(f"path probe '{payload_data.name}' returned HTTP {status_code} ({len(rendered_html)} chars) in {elapsed_ms}ms")

                if not xs_scan and getattr(payload_data, "check_for_match", 1) == 1:
                    if detect_match(rendered_html, payload_data):
                        xs_match = 1
                        if logger:
                            logger.debug(f"DOM match confirmed for path payload '{payload_data.name}'")

            except Exception as err:
                text = clean_error_text(str(err))
                if logger:
                    logger.debug(f"path test error: {text}")
            finally:
                page.remove_listener("dialog", handle_dialog)

            final_xss = 1 if xs_scan else 0
            final_confidence = calculate_confidence(xs_scan, xs_match)

            finding = XSSFinding(
                endpoint=test_path,
                param_name=None,
                context="path_based",
                payload_name=payload_data.name,
                payload_key=payload_key,
                payload_value=payload_data.payload,
                request_method="PATH",
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
                    method="PATH",
                    param_name=None,
                    context="path",
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
                    logger.debug(f"verified path XSS found for '{test_path}', halting further tests for this path")
                break
            elif xs_match:
                findings.append(finding)

            await async_delay(config.delay_min, config.delay_max)

    return findings
