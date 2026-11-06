from typing import Tuple, List, Optional
from urllib.parse import urlparse
import asyncio

from models import ScanConfig, Parameter, XSSFinding
from browser.playwright import BrowserManager
from utils.logger import Logger
from utils.helpers import is_valid_url, generate_random_string
from scanner.state import ScanState

from modules.parameter_mining import run_parameter_mining
from modules.reflection import run_reflection_engine
from modules.get_dom import run_get_dom_xss
from modules.forms import run_post_based_xss
from modules.links import run_path_based_xss
from modules.dom import run_fragment_based_xss
from modules.headers import run_header_based_xss

class ScannerEngine:
    def __init__(self, config: ScanConfig, logger: Optional[Logger] = None):
        self.config = config
        self.logger = logger or Logger(verbose=config.verbose)
        self.state = ScanState(target_url=config.target_url)
        self.browser_manager = BrowserManager(
            browser_type=config.browser_type,
            headless=config.headless,
            timeout_ms=config.timeout_ms,
        )

    async def run(self) -> Tuple[List[XSSFinding], List[Parameter]]:
        if not is_valid_url(self.config.target_url):
            self.logger.error(f"Invalid target URL: {self.config.target_url}")
            return [], []

        self.logger.info(f"target URL: {self.config.target_url}")
        self.logger.info(f"browser engine: {self.config.browser_type} (headless={self.config.headless})")
        if self.config.target_params:
            self.logger.info(f"target parameter(s): {', '.join(self.config.target_params)}")
        if self.config.exclude_params:
            self.logger.info(f"excluding parameter(s): {', '.join(self.config.exclude_params)}")
        if self.config.wordlist_path:
            self.logger.info(f"probing wordlist parameter(s): {self.config.wordlist_path} ({len(self.config.wordlist_params)} params)")
        self.logger.debug(f"scan scope modules: {', '.join(self.config.scan_modules)}")

        all_findings: List[XSSFinding] = []
        parameters: List[Parameter] = []

        try:
            self.logger.debug(f"launching {self.config.browser_type} browser instance...")
            await self.browser_manager.start()
            page = await self.browser_manager.create_page()
            self.logger.debug("browser instance ready, beginning Step 0 (parameter discovery)...")

            self.state.current_step = 0
            parameters = await run_parameter_mining(
                page=page,
                target_url=self.config.target_url,
                custom_postfields=self.config.postfields,
                exclude_params=self.config.exclude_params,
                wordlist_params=self.config.wordlist_params,
                logger=self.logger,
            )

            if self.config.exclude_params:
                exclude_set = set(p.lower() for p in self.config.exclude_params)
                parameters = [p for p in parameters if p.param_name.lower() not in exclude_set]

            if self.config.target_params:
                target_set = set(p.lower() for p in self.config.target_params)
                filtered = [p for p in parameters if p.param_name.lower() in target_set]
                existing_names = {p.param_name.lower() for p in filtered}
                exclude_set = set(p.lower() for p in self.config.exclude_params) if self.config.exclude_params else set()
                for tp in self.config.target_params:
                    if tp.lower() not in existing_names and tp.lower() not in exclude_set:
                        parsed_base = urlparse(self.config.target_url)
                        origin_path = f"{parsed_base.scheme}://{parsed_base.netloc}{parsed_base.path}"
                        if not origin_path.endswith("/") and not parsed_base.path:
                            origin_path += "/"
                        filtered.append(Parameter(
                            param_name=tp,
                            param_value=generate_random_string(9),
                            action_url=origin_path,
                            location="GET",
                        ))
                parameters = filtered

            self.state.parameters = parameters
            self.logger.debug(f"Step 0 complete: total {len(parameters)} parameter(s) registered")

            if not parameters:
                self.logger.warning("no parameters discovered; checking path, fragment, and header vectors...")
            else:
                self.state.current_step = 1
                self.logger.debug("beginning Step 1 (reflection analysis)...")
                parameters = await run_reflection_engine(
                    page=page,
                    parameters=parameters,
                    logger=self.logger,
                )
                self.logger.debug(f"Step 1 complete: reflections evaluated for {len(parameters)} parameter(s)")

                if "get" in self.config.scan_modules:
                    self.state.current_step = 2
                    self.logger.debug("beginning Step 2 (reflected & DOM XSS testing)...")
                    step2_findings = await run_get_dom_xss(
                        page=page,
                        parameters=parameters,
                        config=self.config,
                        logger=self.logger,
                    )
                    all_findings.extend(step2_findings)
                    self.logger.debug(f"Step 2 complete: {len(step2_findings)} finding(s)")

                if "post" in self.config.scan_modules:
                    self.state.current_step = 3
                    self.logger.debug("beginning Step 3 (POST form-based XSS testing)...")
                    step3_findings = await run_post_based_xss(
                        page=page,
                        parameters=parameters,
                        config=self.config,
                        logger=self.logger,
                    )
                    all_findings.extend(step3_findings)
                    self.logger.debug(f"Step 3 complete: {len(step3_findings)} finding(s)")

            if "path" in self.config.scan_modules:
                self.state.current_step = 4
                self.logger.debug("beginning Step 4 (path-based XSS testing)...")
                step4_findings = await run_path_based_xss(
                    page=page,
                    target_url=self.config.target_url,
                    config=self.config,
                    logger=self.logger,
                )
                all_findings.extend(step4_findings)
                self.logger.debug(f"Step 4 complete: {len(step4_findings)} finding(s)")

            if "fragment" in self.config.scan_modules:
                self.state.current_step = 5
                self.logger.debug("beginning Step 5 (fragment-based XSS testing)...")
                step5_findings = await run_fragment_based_xss(
                    page=page,
                    target_url=self.config.target_url,
                    config=self.config,
                    logger=self.logger,
                )
                all_findings.extend(step5_findings)
                self.logger.debug(f"Step 5 complete: {len(step5_findings)} finding(s)")

            if "header" in self.config.scan_modules:
                self.state.current_step = 6
                self.logger.debug("beginning Step 6 (header-based XSS testing)...")
                step6_findings = await run_header_based_xss(
                    browser_manager=self.browser_manager,
                    target_url=self.config.target_url,
                    config=self.config,
                    logger=self.logger,
                )
                all_findings.extend(step6_findings)
                self.logger.debug(f"Step 6 complete: {len(step6_findings)} finding(s)")

            self.state.findings = all_findings
            self.state.mark_completed()

            self.logger.info(f"scan finished in {self.state.elapsed_seconds}s")

        except Exception as err:
            self.logger.error(f"scanner engine encountered an unexpected error: {err}")
        finally:
            self.logger.debug("closing browser resources...")
            await self.browser_manager.close()

        return all_findings, parameters
