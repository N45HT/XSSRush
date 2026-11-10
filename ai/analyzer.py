import os
import re
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from utils.logger import Logger, format_payload_display
from .client import create_ai_client
from .prompt import build_system_prompt, build_user_prompt, parse_ai_response

def resolve_ai_key(cli_key: Optional[str] = None, base_dir: Optional[Path] = None) -> Optional[str]:
    if cli_key and str(cli_key).strip():
        return str(cli_key).strip()

    env_val = os.environ.get("XSSR_AI_KEY") or os.environ.get("OPENROUTER_API_KEY")
    if env_val and env_val.strip():
        return env_val.strip()

    if base_dir:
        dotenv_path = base_dir / ".env"
        if dotenv_path.is_file():
            try:
                with open(dotenv_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k in ("XSSR_AI_KEY", "OPENROUTER_API_KEY") and v:
                            return v
            except Exception:
                pass

    return None

class AIAnalyzer:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "deepseek/deepseek-chat",
        logger: Optional[Logger] = None,
        provider: str = "openrouter",
        user_context: Optional[str] = None,
    ):
        self.api_key = api_key
        self.model = model
        self.logger = logger
        self.provider = provider
        self.user_context = user_context
        self.client = create_ai_client(provider, api_key, model) if api_key else None
        self._cache: Dict[str, Tuple[str, List[str]]] = {}

    @staticmethod
    def detect_subcontext(html: str, marker: str = "[REFLECTED_INJECTION_POINT]") -> str:
        pos = html.find(marker)
        if pos == -1:
            return "unknown"

        before = html[:pos]
        last_script_open = before.rfind("<script")
        last_script_close = before.rfind("</script")
        is_in_script = last_script_open != -1 and last_script_open > last_script_close

        if is_in_script:
            script_body_before = before[last_script_open:]

            last_block_open = script_body_before.rfind("/*")
            last_block_close = script_body_before.rfind("*/")
            if last_block_open != -1 and last_block_open > last_block_close:
                return "block_comment (enclosed in /* ... */)"

            last_nl = script_body_before.rfind("\n")
            current_line_before = script_body_before[last_nl + 1:] if last_nl != -1 else script_body_before

            if "//" in current_line_before:
                return "single_line_comment (preceded by //)"

            single_quotes = len(re.findall(r"(?<!\\)'", current_line_before))
            if single_quotes % 2 == 1:
                return "single_quoted_string (enclosed in '...')"

            double_quotes = len(re.findall(r'(?<!\\)"', current_line_before))
            if double_quotes % 2 == 1:
                return 'double_quoted_string (enclosed in "...")'

            backticks = len(re.findall(r"(?<!\\)`", script_body_before))
            if backticks % 2 == 1:
                return "template_literal (enclosed in `...`)"

            open_parens = current_line_before.count("(")
            close_parens = current_line_before.count(")")
            trimmed_line = current_line_before.rstrip()
            if open_parens > close_parens or trimmed_line.endswith("(") or re.search(r"\b[a-zA-Z0-9_$]+\s*\(\s*$", current_line_before):
                return "javascript_function_argument (inside function call argument)"

            if re.search(r"[{,]\s*['\"]?[a-zA-Z0-9_$-]+['\"]?\s*:\s*$", current_line_before):
                return "javascript_json_or_object (inside object literal / JSON)"

            return "javascript_statement (raw script block)"

        for rcdata_tag in ("textarea", "title", "style", "noscript"):
            open_tag = f"<{rcdata_tag}"
            close_tag = f"</{rcdata_tag}"
            last_o = before.lower().rfind(open_tag)
            last_c = before.lower().rfind(close_tag)
            if last_o != -1 and last_o > last_c:
                return f"rcdata_content (inside <{rcdata_tag}>)"

        last_comment_open = before.rfind("<!--")
        last_comment_close = before.rfind("-->")
        if last_comment_open != -1 and last_comment_open > last_comment_close:
            return "html_comment (enclosed in <!-- ... -->)"

        last_tag_open = before.rfind("<")
        last_tag_close = before.rfind(">")
        if last_tag_open != -1 and last_tag_open > last_tag_close:
            tag_content = before[last_tag_open:]
            matches = list(re.finditer(r"\b([a-zA-Z0-9_-]+)\s*=\s*(['\"]?)", tag_content))
            if not matches:
                return "html_tag_content"

            last_match = matches[-1]
            attr_name = last_match.group(1).lower()
            quote = last_match.group(2)
            val_after = tag_content[last_match.end():]

            if quote:
                if quote in val_after:
                    return "html_tag_content"
                if attr_name.startswith("on"):
                    return f"html_event_handler_attribute (inside {attr_name}= handler, quoted with {quote})"
                if attr_name in ("href", "src", "action", "formaction") and val_after.strip().lower().startswith("javascript:"):
                    return "html_javascript_uri_attribute (inside javascript: URI)"
                q_name = "single_quoted" if quote == "'" else "double_quoted"
                return f"html_attribute_value ({q_name} inside {attr_name}={quote}...{quote})"

            if re.search(r"\s", val_after):
                return "html_tag_content"
            return f"html_unquoted_attribute (inside {attr_name} attribute without quotes)"

        return "html_tag_content"

    @classmethod
    def extract_snippet(
        cls,
        html: str,
        needle: str,
        window_chars: int = 350,
        marker: str = "[REFLECTED_INJECTION_POINT]",
    ) -> Tuple[str, str]:
        if not html:
            return "", "unknown"

        pos = -1
        match_len = 0
        if needle:
            pos = html.find(needle)
            match_len = len(needle)
            if pos == -1:
                pos = html.lower().find(needle.lower())

        if pos == -1:
            marked_html = f"{html[:window_chars]} {marker} {html[window_chars:window_chars*2]}"
            subcontext = cls.detect_subcontext(marked_html, marker=marker)
            return marked_html[: window_chars * 2], subcontext

        start = max(0, pos - window_chars)
        end = min(len(html), pos + match_len + window_chars)
        before_match = html[start:pos]
        after_match = html[pos + match_len:end]
        marked_snippet = f"{before_match}{marker}{after_match}"
        subcontext = cls.detect_subcontext(marked_snippet, marker=marker)
        return marked_snippet, subcontext

    async def generate_bypass_payloads(
        self,
        endpoint: str,
        param_name: str,
        location: str,
        context: str,
        char_matrix: Dict[str, str],
        html: str,
        reflected_token: Optional[str] = None,
        user_context: Optional[str] = None,
    ) -> List[str]:
        if not self.client or not self.api_key:
            return []

        active_context_hint = user_context if user_context is not None else self.user_context
        needle = reflected_token or param_name
        snippet, subcontext = self.extract_snippet(html, needle)
        sorted_matrix = ",".join(f"{k}:{v}" for k, v in sorted(char_matrix.items()))
        cache_key = f"{context}|{subcontext}|{sorted_matrix}|{active_context_hint or ''}"

        if cache_key in self._cache:
            cached_analysis, cached_payloads = self._cache[cache_key]
            if self.logger:
                self.logger.action(
                    f"reusing cached AI bypass payloads for '{param_name}' [{location}] (fingerprint match)"
                )
                if cached_analysis:
                    self.logger.info(f"AI analysis (cached): {cached_analysis}")
                for idx, p in enumerate(cached_payloads, 1):
                    clean_p = format_payload_display(p)
                    self.logger.debug(f"AI candidate #{idx} (cached): {clean_p}")
            return list(cached_payloads)

        system_prompt = build_system_prompt()
        user_prompt = build_user_prompt(
            endpoint=endpoint,
            param_name=param_name,
            location=location,
            context=context,
            subcontext=subcontext,
            char_matrix=char_matrix,
            snippet=snippet,
            user_context=active_context_hint,
        )

        if self.logger:
            self.logger.action(
                f"querying AI fallback ({self.model}) for '{param_name}' [{location}]..."
            )
            self.logger.debug(f"AI request subcontext: {subcontext} | snippet length: {len(snippet)} chars")
            if active_context_hint:
                self.logger.debug(f"AI user-defined context hint: {active_context_hint}")

        raw_resp, err_msg = await self.client.chat_completion(system_prompt, user_prompt)
        if err_msg:
            if self.logger:
                self.logger.warning(f"AI fallback failed: {err_msg}")
            return []

        if not raw_resp:
            if self.logger:
                self.logger.warning(f"AI fallback returned empty response for '{param_name}'")
            return []

        if self.logger:
            self.logger.debug(f"AI raw response received: {raw_resp[:200]}...")

        parsed = parse_ai_response(raw_resp)
        payloads = parsed.get("payloads", [])
        analysis = parsed.get("analysis", "")

        if payloads:
            self._cache[cache_key] = (analysis, payloads)

        if self.logger:
            if analysis:
                self.logger.info(f"AI analysis: {analysis}")
            if payloads:
                self.logger.info(f"AI generated {len(payloads)} tailored candidate payload(s)")
                for idx, p in enumerate(payloads, 1):
                    clean_p = format_payload_display(p)
                    self.logger.debug(f"AI candidate #{idx}: {clean_p}")
            else:
                self.logger.warning(f"AI generated zero candidate payloads for '{param_name}'")

        return payloads
