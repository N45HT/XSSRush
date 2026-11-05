import asyncio
from typing import Optional, Dict, Any, Callable
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright
from config import DEFAULT_USER_AGENT
from utils.helpers import clean_error_text

class BrowserManager:

    def __init__(
        self,
        browser_type: str = "firefox",
        headless: bool = True,
        timeout_ms: int = 15000,
    ):
        self.browser_type_name = browser_type.lower()
        self.headless = headless
        self.timeout_ms = timeout_ms

        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None

    async def start(self):
        self.playwright = await async_playwright().start()

        if self.browser_type_name == "chromium":
            engine = self.playwright.chromium
        elif self.browser_type_name == "webkit":
            engine = self.playwright.webkit
        else:
            engine = self.playwright.firefox

        self.browser = await engine.launch(
            headless=self.headless,
        )

    async def create_context(
        self,
        extra_headers: Optional[Dict[str, str]] = None,
        custom_user_agent: Optional[str] = None,
    ) -> BrowserContext:
        if not self.browser:
            raise RuntimeError("Browser is not started. Call start() first.")

        context_kwargs: Dict[str, Any] = {
            "user_agent": custom_user_agent or DEFAULT_USER_AGENT,
            "ignore_https_errors": True,
        }

        if extra_headers:
            context_kwargs["extra_http_headers"] = extra_headers

        return await self.browser.new_context(**context_kwargs)

    async def create_page(
        self,
        context: Optional[BrowserContext] = None,
        on_dialog: Optional[Callable] = None,
    ) -> Page:
        ctx = context or await self.create_context()
        page = await ctx.new_page()

        if on_dialog:
            page.on("dialog", on_dialog)

        return page

    async def close(self):
        if self.browser:
            try:
                await self.browser.close()
            except Exception:
                pass
            self.browser = None

        if self.playwright:
            try:
                await self.playwright.stop()
            except Exception:
                pass
            self.playwright = None
