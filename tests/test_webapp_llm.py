from types import SimpleNamespace

import pytest

from webapp.llm import ClaudeLLM, GeminiLLM, MockLLM, available, make_llm


class FakeAnthropic:
    def __init__(self, response=None, error=None):
        self.kwargs = None
        self._response, self._error = response, error
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.kwargs = kwargs
        if self._error:
            raise self._error
        return self._response


def claude_response(*blocks, stop_reason="end_turn"):
    return SimpleNamespace(stop_reason=stop_reason, content=list(blocks))


class FakeGemini:
    def __init__(self, text="hello from gemini", error=None):
        self.kwargs = None
        self._text, self._error = text, error
        self.models = SimpleNamespace(generate_content=self._gen)

    def _gen(self, **kwargs):
        self.kwargs = kwargs
        if self._error:
            raise self._error
        return SimpleNamespace(text=self._text)


def test_mock_echoes():
    assert MockLLM().complete("hi") == "Echo: hi"


def test_claude_request_shape_and_text_only():
    fake = FakeAnthropic(claude_response(
        SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text="Hi there."),
    ))
    assert ClaudeLLM(client=fake).complete("hello") == "Hi there."
    k = fake.kwargs
    assert k["model"] == "claude-opus-5-5"
    assert k["betas"] == ["server-side-fallback-2026-07-01"] and k["fallbacks"] == "default"
    assert k["output_config"] == {"effort": "low"}
    assert k["messages"] == [{"role": "user", "content": "hello"}]
    assert "thinking" not in k


def test_claude_model_override(monkeypatch):
    monkeypatch.setenv("CLAUDE_MODEL", "claude-sonnet-5-5")
    fake = FakeAnthropic(claude_response(SimpleNamespace(type="text", text="x")))
    ClaudeLLM(client=fake).complete("hi")
    assert fake.kwargs["model"] == "claude-sonnet-5-5"


def test_claude_refusal_and_errors():
    refused = FakeAnthropic(claude_response(stop_reason="refusal"))
    assert ClaudeLLM(client=refused).complete("x") == "[claude declined to answer]"
    broken = FakeAnthropic(error=RuntimeError("sk-ant-SECRET in message"))
    out = ClaudeLLM(client=broken).complete("x")
    assert out == "[claude error: RuntimeError]" and "SECRET" not in out


def test_claude_missing_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert ClaudeLLM().complete("x") == "[claude unavailable: missing ANTHROPIC_API_KEY]"


def test_gemini_request_shape_and_errors(monkeypatch):
    fake = FakeGemini()
    assert GeminiLLM(client=fake).complete("hello") == "hello from gemini"
    assert fake.kwargs["model"] == "gemini-2.5-flash" and fake.kwargs["contents"] == "hello"
    assert "system_instruction" in fake.kwargs["config"]
    assert GeminiLLM(client=FakeGemini(error=ValueError("boom"))).complete("x") == "[gemini error: ValueError]"
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert GeminiLLM().complete("x") == "[gemini unavailable: missing GEMINI_API_KEY]"


def test_available_and_factory(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert available("mock") and available("claude") and not available("gemini")
    assert isinstance(make_llm("mock"), MockLLM)
    with pytest.raises(ValueError):
        make_llm("gpt")


@pytest.mark.live
def test_live_claude():
    if not available("claude"):
        pytest.skip("no ANTHROPIC_API_KEY")
    out = ClaudeLLM().complete("Say 'ok'.")
    assert out and not out.startswith("[claude")


@pytest.mark.live
def test_live_gemini():
    if not available("gemini"):
        pytest.skip("no GEMINI_API_KEY")
    out = GeminiLLM().complete("Say 'ok'.")
    assert out and not out.startswith("[gemini")


def test_gemini_client_gets_a_timeout(monkeypatch):
    from google import genai

    seen = {}

    class FakeClient:
        def __init__(self, **kwargs):
            seen.update(kwargs)
            self.models = SimpleNamespace(generate_content=lambda **kw: SimpleNamespace(text="ok"))

    monkeypatch.setattr(genai, "Client", FakeClient)
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    assert GeminiLLM().complete("hi") == "ok"
    assert seen["http_options"] == {"timeout": 30_000}
