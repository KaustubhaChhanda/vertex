import os
import json
import requests
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"

class CloudLLMClient:
    """
    Centralized Cloud LLM client for high-context semantic reasoning,
    evaluating persuasion intent (LLMPEA framework), and XAI narrative generation.
    Primary: Groq (openai/gpt-oss-20b / qwen/qwen3.8-27b)
    Secondary: Google Gemini (gemini-flash-latest)
    """

    @classmethod
    def get_groq_key(cls) -> str:
        return os.getenv("GROQ_API_KEY", "").strip()

    @classmethod
    def get_gemini_key(cls) -> str:
        return os.getenv("GEMINI_API_KEY", "").strip()

    @classmethod
    def call_groq(cls, prompt: str, system_prompt: str = "You are an elite autonomous cybersecurity AI analyst.") -> Optional[Dict[str, Any]]:
        groq_key = cls.get_groq_key()
        if not groq_key or groq_key == "your_groq_api_key_here":
            return None

        headers = {
            "Authorization": f"Bearer {groq_key}",
            "Content-Type": "application/json"
        }

        # Try active Groq models in order
        candidate_models = ["openai/gpt-oss-20b", "qwen/qwen3.8-27b", "openai/gpt-oss-120b"]

        for model in candidate_models:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt + " Return valid JSON only, without markdown wrapping."},
                    {"role": "user", "content": prompt}
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.2
            }
            try:
                resp = requests.post(GROQ_ENDPOINT, headers=headers, json=payload, timeout=12)
                if resp.status_code == 200:
                    raw_content = resp.json()["choices"][0]["message"]["content"]
                    # Clean any accidental markdown wrappers
                    clean_json = raw_content.strip()
                    if clean_json.startswith("```json"):
                        clean_json = clean_json[7:]
                    if clean_json.startswith("```"):
                        clean_json = clean_json[3:]
                    if clean_json.endswith("```"):
                        clean_json = clean_json[:-3]
                    return json.loads(clean_json.strip())
                elif resp.status_code in [400, 404]:
                    continue # Try next model
            except Exception as e:
                print(f"[CloudLLM] Groq {model} request failed: {e}")
                continue

        return None

    @classmethod
    def call_gemini(cls, prompt: str) -> Optional[Dict[str, Any]]:
        gemini_key = cls.get_gemini_key()
        if not gemini_key or gemini_key == "your_gemini_api_key_here":
            return None

        for model in ["gemini-flash-latest", "gemini-pro-latest", "gemini-2.5-flash"]:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{
                    "parts": [{"text": prompt + "\nStrictly output valid JSON object only."}]
                }],
                "generationConfig": {
                    "response_mime_type": "application/json",
                    "temperature": 0.2
                }
            }
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=12)
                if resp.status_code == 200:
                    candidates = resp.json().get("candidates", [])
                    if candidates:
                        text_out = candidates[0]["content"]["parts"][0]["text"].strip()
                        return json.loads(text_out)
            except Exception as e:
                print(f"[CloudLLM] Gemini {model} call failed: {e}")
                continue

        return None
