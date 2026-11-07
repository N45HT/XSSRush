import sys
from typing import Any, Optional
from constants import BANNER, APP, DESCRIPTION, HOMEPAGE, EMAIL, VERSION

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
WHITE = "\033[37m"
GREY = "\033[90m"

DARK_RED = "\033[38;5;124m"
BRIGHT_RED = "\033[1;31m"
BRIGHT_WHITE = "\033[1;97m"
PURE_WHITE = "\033[97m"
SOFT_TEAL = "\033[38;5;116m"
SOFT_SLATE = "\033[38;5;110m"
SOFT_ORANGE = "\033[38;5;208m"

def format_confidence(conf: float) -> str:
    if conf < 1.0:
        color = GREY
    elif conf < 4.0:
        color = YELLOW
    elif conf < 7.0:
        color = SOFT_ORANGE
    else:
        color = BRIGHT_RED

    return f"{color}{conf:.2f}{RESET}"

class Logger:
    def __init__(self, verbose: bool = False, silent: bool = False):
        self.verbose = verbose
        self.silent = silent
        self.current_param_group = None

    def print_banner(self):
        if self.silent:
            return
        banner_lines = BANNER.strip("\r\n").split("\n")
        indent_banner = " " * 18
        indent_sub = " " * 22

        for line in banner_lines:
            print(f"{DARK_RED}{indent_banner}{line}{RESET}")
        print()
        print(f"{PURE_WHITE}{indent_sub}{APP} - {DESCRIPTION}{RESET}")
        print(f"{PURE_WHITE}{indent_sub}n45ht.or.id   security@n45ht.or.id{RESET}")
        print("\n\n")

    def info(self, message: str):
        if self.silent:
            return
        print(f"[*] {message}")

    def action(self, message: str):
        if self.silent:
            return
        self.current_param_group = None
        print(f"[*] {message}")

    def success(self, message: str):
        if self.silent:
            return
        print(f"{BOLD}{GREEN}[+]{RESET} {message}")

    def neutral(self, message: str):
        if self.silent:
            return
        print(f"{DIM}[-]{RESET} {message}")

    def warning(self, message: str):
        if self.silent:
            return
        print(f"{BOLD}{YELLOW}[!]{RESET} {message}")

    def error(self, message: str):
        print(f"{BOLD}{RED}[-]{RESET} {message}", file=sys.stderr)

    def critical(self, message: str):
        print(f"{BOLD}{RED}[CRITICAL]{RESET}")

    def char_matrix(self, param_name: str, matrix: Dict[str, str]):
        if self.silent:
            return
        allowed = [ch for ch, s in matrix.items() if s == "allowed"]
        escaped = [ch for ch, s in matrix.items() if s == "escaped"]
        filtered = [ch for ch, s in matrix.items() if s == "filtered"]

        parts = []
        if allowed:
            parts.append(f"{GREEN}allowed: [ {' '.join(allowed)} ]{RESET}")
        if escaped:
            parts.append(f"{YELLOW}escaped: [ {' '.join(escaped)} ]{RESET}")
        if filtered:
            parts.append(f"{RED}filtered: [ {' '.join(filtered)} ]{RESET}")

        if not parts:
            parts.append(f"{DIM}no reflection detected{RESET}")

        print(f"  {SOFT_SLATE}[*] character matrix for '{param_name}': {' | '.join(parts)}{RESET}")

    def start_param_test(
        self,
        param_name: Optional[str],
        method: str,
        context: Optional[str] = None,
    ):
        if self.silent:
            return
        group_key = (param_name, method)
        if group_key == self.current_param_group:
            return

        self.current_param_group = group_key
        param_display = f"'{param_name}'" if param_name else "[URL/Path]"
        ctx_str = f" (context: {context})" if context else ""
        print(f"[*] testing parameter {SOFT_TEAL}{param_display}{RESET} [{method}]{ctx_str}\n")

    def test_block(
        self,
        method: str,
        param_name: Optional[str],
        context: Optional[str],
        payload_name: str,
        payload_str: str,
        request_desc: str,
        confidence: float,
        dialog: Optional[str] = None,
        is_xss: bool = False,
        is_match: bool = False,
        postfields: Optional[str] = None,
        header_info: Optional[str] = None,
    ):
        if self.silent:
            if not is_xss and not is_match:
                return

            tag = f"{BOLD}{RED}[CRITICAL]{RESET}" if is_xss else f"{BOLD}{SOFT_ORANGE}[POTENTIAL]{RESET}"
            extra = ""
            if postfields:
                extra = f" | Postfields: {postfields}"
            elif header_info:
                extra = f" | Header: {header_info}"

            print(f"{tag} {request_desc}{extra}")
            return

        if (param_name, method) != self.current_param_group:
            self.start_param_test(param_name, method, context)

        conf_str = format_confidence(confidence)

        if is_xss:
            print(f"{BOLD}{RED}[CRITICAL]{RESET}")
            tag = f"{BOLD}{RED}[+]{RESET}"
        elif is_match:
            print(f"{BOLD}{SOFT_ORANGE}[POTENTIAL]{RESET}")
            tag = f"{BOLD}{SOFT_ORANGE}[+]{RESET}"
        else:
            tag = f"{PURE_WHITE}[+]{RESET}"

        print(f"  {tag} Payload    : {payload_name} ({YELLOW}{payload_str}{RESET})")
        print(f"  {tag} Request    : {SOFT_SLATE}{request_desc}{RESET}")
        if postfields:
            print(f"  {tag} Postfields : {SOFT_SLATE}{postfields}{RESET}")
        if header_info:
            print(f"  {tag} Header     : {SOFT_SLATE}{header_info}{RESET}")
        print(f"  {tag} Confidence : {conf_str}\n")

    def test_log(
        self,
        method: str,
        param_name: Optional[str],
        request_desc: str,
        confidence: float,
        is_xss: bool = False,
        is_match: bool = False,
        context: Optional[str] = None,
        payload_name: str = "XSS Payload",
        payload_str: str = "",
        dialog: Optional[str] = None,
        postfields: Optional[str] = None,
        header_info: Optional[str] = None,
    ):
        clean_req = request_desc.replace("Request: ", "") if request_desc.startswith("Request: ") else request_desc
        self.test_block(
            method=method,
            param_name=param_name,
            context=context,
            payload_name=payload_name,
            payload_str=payload_str,
            request_desc=clean_req,
            confidence=confidence,
            dialog=dialog,
            is_xss=is_xss,
            is_match=is_match,
            postfields=postfields,
            header_info=header_info,
        )

    def debug(self, message: str):
        if self.silent:
            return
        if self.verbose:
            print(f"{DIM}[DEBUG] {message}{RESET}")
