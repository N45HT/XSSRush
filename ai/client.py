from typing import Optional, Tuple, Dict, Any
import httpx

class OpenRouterClient:
    def __init__(
        self,
        api_key: str,
        model: str = "deepseek/deepseek-chat",
        timeout: float = 60.0,
    ):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.endpoint = "https://openrouter.ai/api/v1/chat/completions"

    async def chat_completion(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/N45HT/XSSRush",
            "X-Title": "XSSRush XSS Scanner",
        }
        is_reasoning_model = "r1" in self.model.lower() or "reasoning" in self.model.lower()
        max_tokens = 4000 if is_reasoning_model else 1000
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": max_tokens,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.endpoint, headers=headers, json=body)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        choice = choices[0]
                        finish = choice.get("finish_reason")
                        msg = choice.get("message", {})
                        refusal = msg.get("refusal")
                        if refusal:
                            return None, f"Model refused request: {refusal}"
                        content = msg.get("content")
                        if not content and msg.get("reasoning"):
                            content = msg.get("reasoning")
                        if content:
                            return content, None
                        if finish == "length":
                            return None, "Token limit reached during model reasoning phase"
                        return None, "Model returned empty content"
                    return None, "No choices returned by AI provider"

                err_msg = ""
                try:
                    err_data = resp.json()
                    err_msg = err_data.get("error", {}).get("message", "")
                except Exception:
                    pass
                if not err_msg:
                    err_msg = resp.text.strip()[:200]
                return None, f"HTTP {resp.status_code}: {err_msg}"
        except Exception as e:
            return None, f"Network/Connection error: {str(e)}"

def create_ai_client(
    provider: str,
    api_key: str,
    model: str = "deepseek/deepseek-chat",
    timeout: float = 60.0,
):
    prov = provider.lower()
    if prov in ("openrouter", "default"):
        return OpenRouterClient(api_key=api_key, model=model, timeout=timeout)
    return OpenRouterClient(api_key=api_key, model=model, timeout=timeout)
