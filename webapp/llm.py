"""LLM backends for the demo. Keys come from the env; errors become strings, never details."""

from __future__ import annotations

import os
from typing import Any

SYSTEM_PROMPT = "You are a helpful assistant in a data-security demo. Reply briefly, in two or three sentences."
CLAUDE_DEFAULT = "claude-opus-5-5"
GEMINI_DEFAULT = "gemini-2.5-flash"
_KEYS = {"claude": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY"}


def available(name: str) -> bool:
    return name == "mock" or bool(os.environ.get(_KEYS.get(name, "")))


class MockLLM:
    name = "mock"

    def complete(self, prompt: str) -> str:
        return "Echo: " + prompt


class ClaudeLLM:
    name = "claude"

    def __init__(self, client: Any = None, model: str | None = None) -> None:
        self._client = client
        self._model = model

    def complete(self, prompt: str) -> str:
        if self._client is None:
            if not os.environ.get("ANTHROPIC_API_KEY"):
                return "[claude unavailable: missing ANTHROPIC_API_KEY]"
            import anthropic

            self._client = anthropic.Anthropic(timeout=30.0)
        try:
            response = self._client.beta.messages.create(
                model=self._model or os.environ.get("CLAUDE_MODEL", CLAUDE_DEFAULT),
                max_tokens=4096,  # deliberately short replies for a demo
                system=SYSTEM_PROMPT,
                output_config={"effort": "low"},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:  # report the type only: messages can echo request data
            return f"[claude error: {type(exc).__name__}]"
        if response.stop_reason == "refusal":
            return "[claude declined to answer]"
        text = "".join(b.text for b in response.content if b.type == "text")
        return text or "[claude returned no text]"


class GeminiLLM:
    name = "gemini"

    def __init__(self, client: Any = None, model: str | None = None) -> None:
        self._client = client
        self._model = model

    def complete(self, prompt: str) -> str:
        if self._client is None:
            key = os.environ.get("GEMINI_API_KEY")
            if not key:
                return "[gemini unavailable: missing GEMINI_API_KEY]"
            from google import genai

            self._client = genai.Client(api_key=key, http_options={"timeout": 30_000})  # ms
        try:
            response = self._client.models.generate_content(
                model=self._model or os.environ.get("GEMINI_MODEL", GEMINI_DEFAULT),
                contents=prompt,
                config={"system_instruction": SYSTEM_PROMPT, "max_output_tokens": 1024},
            )
        except Exception as exc:
            return f"[gemini error: {type(exc).__name__}]"
        return response.text or "[gemini returned no text]"


def make_llm(name: str) -> MockLLM | ClaudeLLM | GeminiLLM:
    if name == "mock":
        return MockLLM()
    if name == "claude":
        return ClaudeLLM()
    if name == "gemini":
        return GeminiLLM()
    raise ValueError(f"unknown llm {name!r}")
