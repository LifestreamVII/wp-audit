from openai import OpenAI

class LLMClient:
    def __init__(self, api_key: str, base_url: str):
        self.client = OpenAI(
            base_url=base_url,
            api_key=api_key
        )
        self.model = "qwen-3b"  # Default model
        
    def set_model(self, model: str):
        self.model = model
    
    def set_sysprompt(self, system_prompt: str):
        self.sysprompt = system_prompt

    def generate(self, prompt, max_tokens: int = 4096) -> str:
        if isinstance(prompt, list):
            prompt = "\n".join(prompt)
        messages=[
                {'role': 'system', 'content': self.sysprompt},
                {'role': 'user', 'content': prompt}
        ]
        response = self.client.chat.completions.create(
            messages=messages,
            model=self.model,
            max_tokens=max_tokens
        )
        message = response.choices[0].message
        content = message.content or ""
        if not content.strip() and getattr(message, 'reasoning', None):
            content = message.reasoning
        return content.strip()