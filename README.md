<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://xssr.n45ht.or.id/assets/img/xssr-banner-light-34px.png">
    <source media="(prefers-color-scheme: light)" srcset="https://xssr.n45ht.or.id/assets/img/xssr-banner-dark-34px.png">
    <img alt="XSSR / XSSRush Logo" src="https://xssr.n45ht.or.id/assets/img/xssr-banner-light-34px.png" height="42">
  </picture>
</p>

<h3 align="center">Automated Multi-Vector Cross-Site Scripting (XSS) Scanner &amp; Auditor</h3>

<p align="center">
  <b>Powered by Playwright Headless Browser Automation &bull; Zero Backend &bull; Standalone Python CLI</b>
</p>

<p align="center">
  <a href="https://github.com/N45HT/XSSRush/releases"><img src="https://img.shields.io/badge/version-v2.0.0-crimson.svg?style=flat-square" alt="Version"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat-square&logo=python&logoColor=white" alt="Python Version"></a>
  <a href="https://playwright.dev/"><img src="https://img.shields.io/badge/Engine-Playwright-2EAD33.svg?style=flat-square&logo=playwright&logoColor=white" alt="Playwright"></a>
  <a href="https://github.com/N45HT/XSSRush/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="License"></a>
  <a href="https://xssr.n45ht.or.id"><img src="https://img.shields.io/badge/website-xssr.n45ht.or.id-ad1a37.svg?style=flat-square" alt="Website"></a>
  <a href="https://github.com/N45HT/XSSRush/stargazers"><img src="https://img.shields.io/github/stars/N45HT/XSSRush?style=flat-square&color=yellow" alt="GitHub Stars"></a>
</p>

---

<p align="center">
  <img src="https://xssr.n45ht.or.id/assets/img/xssr-cli-terminal.png" alt="XSSR CLI Execution Preview" width="880">
</p>

**XSSR (XSSRush)** is an automated Cross-Site Scripting (XSS) vulnerability scanner and security auditor developed by **[N45HT](https://github.com/N45HT)**.

By driving real headless browser instances via **Playwright**, XSSR hooks into the browser event loop to intercept genuine JavaScript execution (`alert`, `confirm`, `prompt`). It eliminates false positives common to static regex scanners by confirming payload execution directly inside the DOM.

---

## Audit Pipeline

XSSR executes a structured 7-phase auditing sequence:

```text
[Step 0: Mining]  ──>  [Step 1: Canary Probing]  ──>  [Step 2: GET & DOM XSS]
                                                               │
[Step 5: Fragment] <──  [Step 4: Path XSS]  <──  [Step 3: POST Form XSS]
        │
        └───> [Step 6: Header XSS]  ───> [Verification & Reporting]
```

| Step | Module | Attack Vector & Description |
|:---:|---|---|
| **0** | `modules/parameter_mining.py` | **Parameter Mining**: Extracts query params, form controls, global `window` JS variables, and probes hidden parameters using wordlists. |
| **1** | `modules/reflection.py` | **Reflection Analysis**: Injects unique canary probe tokens to discover reflection points and maps syntactic contexts (`html`, `attribute`, `javascript`, `url`). |
| **2** | `modules/get_dom.py` | **Reflected GET & DOM XSS**: Tests context-tuned payloads into query/DOM parameters and intercepts browser dialogs. |
| **3** | `modules/forms.py` | **POST-Based Form XSS**: Automates DOM form submission (`requestSubmit()`) and generates base64 HTML reproduction PoCs. |
| **4** | `modules/links.py` | **Path-Based XSS**: Injects payloads into URL path segments and directory rewrites. |
| **5** | `modules/dom.py` | **Fragment-Based XSS**: Tests URL hash fragments (`#payload`) against client-side SPA routers and DOM sinks. |
| **6** | `modules/headers.py` | **Header-Based XSS**: Injects payloads into HTTP request headers (`User-Agent`, `Referer`, `Origin`, `Cookie`, `X-Forwarded-*`). |

---

## Installation

### Prerequisites
* Python **3.10** or newer
* `pip` package manager

```bash
# 1. Clone repository
git clone https://github.com/N45HT/XSSRush.git
cd XSSRush

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install Playwright browser engine (Firefox default)
playwright install firefox
```

*(Optional) If you plan to test with Chromium or WebKit engines:*
```bash
playwright install chromium webkit
```

---

## Usage Examples

### 1. Basic Single Target Scan (GET & POST)
```bash
python xssr.py -u "https://target.com/page?id=12"
```

### 2. Testing Custom POST Data Fields
```bash
python xssr.py -u "https://target.com/login" --scan post -d "username=admin&search=keyword"
```

### 3. Full Multi-Vector Audit
Test all vectors (GET, POST, Path, Fragment, Header) and export report:
```bash
python xssr.py -u "https://target.com/app" --scan all -o scan_report.json
```

### 4. Selecting Browser Engine
Switch to Chromium or WebKit:
```bash
python xssr.py -u "https://target.com/app" -b chromium --scan all
```

### 5. Visible GUI Browser Mode (Debugging)
Disable headless mode to visually monitor browser interactions:
```bash
python xssr.py -u "https://target.com/search?q=test" --headless false -v
```

### 6. Fine-Tuning Request Delays
Adjust delay ranges (in milliseconds) to avoid WAF rate-limiting:
```bash
python xssr.py -u "https://target.com" --scan all --delay-min 1500 --delay-max 3000
```

### 7. Custom Wordlist Parameter Mining
Probe hidden parameters using custom wordlists:
```bash
python xssr.py -u "https://target.com/view" -w "wordlists/common.txt" --scan get,post
```

### 8. Custom HTTP Headers Injection
Audit specific HTTP headers alongside default targets:
```bash
python xssr.py -u "https://target.com" --scan header --include-header "X-Client-IP,X-Custom-Auth"
```

### 9. Inspect Built-in Knowledge Bases
Inspect payloads, known parameter lists, or targeted headers and exit:
```bash
python xssr.py --show-payloads
python xssr.py --show-params
python xssr.py --show-headers
```

---

## Command Line Options

```text
Target Options:
  -u, --url URL                   Target URL to scan (e.g. https://example.com/search?q=test)

Browser & Engine Options:
  -b, --browser {firefox,chromium,webkit}
                                  Browser engine to use (default: firefox)
  --headless                      Run browser in headless mode (choices: true, false, default: true)
  --timeout TIMEOUT               Page navigation timeout in milliseconds (default: 15000)
  --delay-min DELAY_MIN           Minimum request delay in ms (default: 3000)
  --delay-max DELAY_MAX           Maximum request delay in ms (default: 5000)

Scan Scope Options:
  --scan MODULES                  Modules to test: get, post, path, fragment, header, or all
                                  (default: get,post)
  -w, --wordlist FILE             Custom parameter wordlist file to probe (e.g.
                                  'wordlists/common.txt')
  -p, --param PARAMS              Parameters to test (comma-separated, e.g. 'firstname,lastname')
  -e, --exclude PARAMS            Parameters to skip during testing (comma-separated, e.g.
                                  'name,location')
  -d, --data POSTFIELDS           Custom POST data fields (e.g. 'username=admin&search=keyword')
  --include-header HEADERS        Custom HTTP headers to add to header scan (comma-separated, e.g.
                                  'X-User-Agent,X-Referer')
  --exclude-header HEADERS        HTTP headers to skip during header scan (comma-separated, e.g.
                                  'User-Agent,Referer')

Information Options:
  --show-payloads                 Show all built-in XSS payloads and exit
  --show-params                   Show all built-in known parameters and exit
  --show-headers                  Show all built-in target HTTP headers and exit

Output & Reporting Options:
  -o, --output FILE               Save report JSON (saved to output/ folder unless absolute path is
                                  given)
  -v, --verbose                   Enable verbose debugging output
  -h, --help                      Show this help message and exit
  --version                       Show program's version number and exit
```

---

## Legal Disclaimer

> **Responsible Security Research Only:**  
> **XSSR (XSSRush)** is developed strictly for authorized penetration testing, security auditing, educational purposes, and responsible vulnerability research. 
> 
> Testing targets without prior mutual written consent is illegal in most jurisdictions. The developer accepts no liability and is not responsible for any misuse, damage, or legal consequences caused by this software. Use responsibly.

---

## Support & Donation

If you find this project useful and want to support its ongoing development:

<p align="center">
  <a href="https://buymeacoffee.com/n45htofficial" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me A Coffee">
  </a>
  &nbsp;&nbsp;
  <a href="https://trakteer.id/n45htofficial" target="_blank" rel="noopener noreferrer">
    <img src="https://img.shields.io/badge/Trakteer-be1e2d?style=for-the-badge&logo=trakteer&logoColor=white" alt="Trakteer">
  </a>
</p>

---

## Author & License

* **Author:** **[N45HT](https://github.com/N45HT)**
* **Official Website:** [https://n45ht.or.id](https://n45ht.or.id)
* **XSSRush Landing Page:** [https://xssr.n45ht.or.id](https://xssr.n45ht.or.id)
* **Security Contact:** [security@n45ht.or.id](mailto:security@n45ht.or.id)
* **License:** Released under the [MIT License](LICENSE).
