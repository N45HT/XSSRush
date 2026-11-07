import json
from datetime import datetime
from typing import List, Optional, Any
from models import XSSFinding, Parameter
from utils.logger import format_confidence
from constants import VERSION, GITHUB
from config import DEFAULT_USER_AGENT
from utils.helpers import build_raw_http_request

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
WHITE = "\033[37m"
DIM = "\033[2m"

class Reporter:
    def __init__(
        self,
        findings: List[XSSFinding],
        parameters: List[Parameter],
        logger: Optional[Any] = None,
        user_agent: Optional[str] = None,
        mining_only: bool = False,
        silent: bool = False,
    ):
        self.findings = findings
        self.parameters = parameters
        self.logger = logger
        self.user_agent = user_agent or DEFAULT_USER_AGENT
        self.mining_only = mining_only
        self.silent = silent

    def _print_finding_item(self, idx: int, f: XSSFinding):
        param_str = f.param_name or "[Path/Hash]"
        print(f"  ({idx}) {BOLD}{WHITE}{param_str}{RESET} [{f.request_method}]")
        target_url = f.request_url or f.endpoint
        print(f"      url        : {target_url}")
        if f.request_method.upper() == "POST" and f.request_body:
            print(f"      postfields : {f.request_body}")
        print(f"      context    : {f.context}")
        print(f"      payload    : {BOLD}{WHITE}{f.payload_value}{RESET}")
        print(f"      confidence : {format_confidence(f.confidence)}")
        if f.proof_of_concept:
            print(f"      poc        : {CYAN}{f.proof_of_concept}{RESET}")

    def print_mining_summary(self):
        if self.silent:
            return

        reflected_params = []
        for p in self.parameters:
            active_refs = [r for r in p.reflections if r.reflected]
            if active_refs:
                reflected_params.append((p, active_refs))

        print(f"\n{BOLD}[*] parameter mining summary:{RESET}")
        print(f"  total parameters discovered : {BOLD}{len(self.parameters)}{RESET}")
        print(f"  reflected parameters        : {BOLD}{GREEN if reflected_params else RESET}{len(reflected_params)}{RESET}")

        if not reflected_params:
            print(f"\n[{BOLD}{YELLOW}!{RESET}] no reflected parameters found.\n")
            return

        print(f"\n{BOLD}{GREEN}[+] REFLECTED PARAMETERS:{RESET}")
        for idx, (p, refs) in enumerate(reflected_params, 1):
            print(f"  ({idx}) {BOLD}{WHITE}{p.param_name}{RESET} [{p.location}]")
            print(f"      endpoint   : {p.action_url}")
            contexts_str = []
            for r in refs:
                tag_str = f" (tag: <{r.tags}>)" if r.tags else ""
                contexts_str.append(f"{r.context.upper()}{tag_str}")
            print(f"      context    : {', '.join(contexts_str)}")
            if p.char_matrix:
                allowed = [ch for ch, s in p.char_matrix.items() if s == "allowed"]
                escaped = [ch for ch, s in p.char_matrix.items() if s == "escaped"]
                filtered = [ch for ch, s in p.char_matrix.items() if s == "filtered"]
                parts = []
                if allowed:
                    parts.append(f"{GREEN}allowed: [ {' '.join(allowed)} ]{RESET}")
                if escaped:
                    parts.append(f"{YELLOW}escaped: [ {' '.join(escaped)} ]{RESET}")
                if filtered:
                    parts.append(f"{RED}filtered: [ {' '.join(filtered)} ]{RESET}")
                if parts:
                    print(f"      characters : {' | '.join(parts)}")
        print()

    def print_summary(self):
        if self.silent:
            return

        if self.mining_only:
            self.print_mining_summary()
            return

        verified = [f for f in self.findings if f.xss == 1]
        matches = [f for f in self.findings if f.xss == 0 and f.xs_match == 1]

        print(f"\n{BOLD}[*] scan report summary:{RESET}")
        print(f"  total parameters audited : {BOLD}{len(self.parameters)}{RESET}")
        print(f"  verified vulnerabilities : {BOLD}{RED if verified else GREEN}{len(verified)}{RESET}")
        print(f"  reflection matches       : {BOLD}{YELLOW if matches else RESET}{len(matches)}{RESET}")

        if not self.findings:
            print(f"\n[{BOLD}{GREEN}+{RESET}] all tested parameters appear to be safe from XSS.\n")
            return

        if verified:
            print(f"\n{BOLD}{RED}[!] VERIFIED CROSS-SITE SCRIPTING (XSS) VULNERABILITIES:{RESET}")
            for idx, f in enumerate(verified, 1):
                self._print_finding_item(idx, f)

        if matches:
            print(f"\n{BOLD}{YELLOW}[*] UNESCAPED REFLECTION MATCHES (POTENTIAL SINKS):{RESET}")
            for idx, f in enumerate(matches, 1):
                self._print_finding_item(idx, f)

        print()

    def render_console(self):
        if self.silent:
            return
        if self.mining_only:
            self.print_mining_summary()
        else:
            self.print_summary()

    @staticmethod
    def _format_created_at(val: Any) -> str:
        if isinstance(val, str) and val:
            if len(val) == 19 and val[4] == "-" and val[7] == "-" and val[10] == " ":
                return val
            try:
                dt = datetime.fromisoformat(val)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return val
        elif isinstance(val, (int, float)) and val > 0:
            ts = val / 1000.0 if val > 10_000_000_000 else val
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def export_json(self, filepath: str):
        if self.mining_only:
            reflected_data = []
            for p in self.parameters:
                active_refs = [r for r in p.reflections if r.reflected]
                if not active_refs:
                    continue
                contexts = []
                for r in active_refs:
                    ctx_item = {
                        "context": r.context,
                        "method": r.request_method,
                    }
                    if r.tags:
                        ctx_item["tag"] = r.tags
                    contexts.append(ctx_item)
                ref_item = {
                    "parameter": p.param_name,
                    "location": p.location,
                    "endpoint": p.action_url,
                    "contexts": contexts,
                }
                if p.char_matrix:
                    ref_item["char_matrix"] = p.char_matrix
                reflected_data.append(ref_item)

            report = {
                "scanner": "XSSR (XSSRush)",
                "version": VERSION,
                "github": GITHUB,
                "mode": "parameter_mining",
                "total_parameters_discovered": len(self.parameters),
                "total_reflected_parameters": len(reflected_data),
                "reflected_parameters": reflected_data,
            }

            with open(filepath, "w", encoding="utf-8") as file:
                json.dump(report, file, indent=2)
            return

        findings_data = []
        for f in self.findings:
            item = {
                "finding_uuid": f.finding_uuid,
                "endpoint": f.endpoint,
                "parameter": f.param_name,
                "location": f.request_method,
                "context": f.context,
                "payload_name": f.payload_name,
                "payload_key": f.payload_key,
                "payload_value": f.payload_value,
                "xss": f.xss,
                "confidence": f.confidence,
                "request_url": f.request_url,
            }
            if f.request_method.upper() == "POST":
                item["postfields"] = f.request_body or ""
            item["http"] = build_raw_http_request(f, user_agent=self.user_agent)
            item["proof_of_concept"] = f.proof_of_concept
            item["created_at"] = self._format_created_at(f.created_at)
            findings_data.append(item)

        report = {
            "scanner": "XSSR (XSSRush)",
            "version": VERSION,
            "github": GITHUB,
            "total_parameters": len(self.parameters),
            "total_findings": len(self.findings),
            "total_xss": sum(1 for f in self.findings if f.xss == 1),
            "parameters": [
                {
                    "parameter": p.param_name,
                    "location": p.location,
                    "endpoint": p.action_url,
                    **({"char_matrix": p.char_matrix} if p.char_matrix else {}),
                }
                for p in self.parameters
            ],
            "findings": findings_data,
        }

        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
