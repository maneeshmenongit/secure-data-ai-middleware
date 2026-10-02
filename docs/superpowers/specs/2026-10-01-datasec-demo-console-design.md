# DataSec Demo Console — Design

**Date:** 2026-10-01 · **Status:** awaiting review · **Parents:** DESIGN.md §8 (test web app), `docs_to_claude/datasec/datasec-asgi-testrig-spec.md` §2–§4

## 1. Purpose

A local web page for **seeing the middleware work**. You pick a scenario, flip **Protection ON/OFF**, and compare what the user sent with what actually reached the LLM or tool, the model's reply, and the audit log.

This is v1. The full test rig from the test-rig spec (login, notes, admin, black-box A/B suite) is v2, with its own cycle.

## 2. Scope and constraints

- A `webapp/` package at the repo root, outside `src/datasec`, following the test-rig spec §0.
- It uses the real `SecurityPipeline`, with `PresidioRedactor` when it's installed and the regex `Redactor` otherwise. The audit log lives in memory for each server run.
- An optional uv dependency group `webapp`: `fastapi`, `uvicorn`, `anthropic`, `google-genai`, `python-dotenv`, `httpx`. The `datasec` package stays dependency-free.
- `uv run --group webapp python -m webapp` serves on `127.0.0.1:8000`. Startup refuses any host that isn't loopback (`127.0.0.1`, `::1`, `localhost`).
- Only synthetic data. The payment tool and the third-party service are in-process mocks that record calls; nothing leaves the machine except, when chosen, the request to Claude or Gemini.
- API keys come from `.env` (`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) on the server only. They never appear in a response, a log or the page.

## 3. Components

```
webapp/
  __main__.py     # parse --host/--port, enforce loopback, run uvicorn
  app.py          # create_app(llm_factory=...) -> FastAPI; routes below
  scenarios.py    # Scenario dataclass + the preset list
  sinks.py        # MockPaymentTool, MockThirdParty: record what they received
  llm.py          # LLM interface; MockLLM (echo), ClaudeLLM, GeminiLLM; keys via env
  rig.py          # run_scenario(): provenance tagging, guard() calls, protection switch
  static/index.html  # the console (plain HTML/JS/CSS, no build step)
```

### 3.1 Scenarios (`scenarios.py`)

A `Scenario(id, title, origin, sink, text, explain)`, where `origin` is one of `user`, `web`, `tool` or `vault`. `origin` maps to provenance exactly as test-rig spec §2 lays out:

| origin | provenance |
|---|---|
| `user` | `from_user(text, source="user:demo")` |
| `web` | `untrusted(text, source="web:demo-page")` |
| `tool` | `Provenance(EXTERNAL, "api:weather")` |
| `vault` | `internal(text, source="vault:demo", labels="secret")` |

The presets (all synthetic):

1. `pii-chat`: `user` → `llm`. A chat message with a name, city, card and email.
2. `injected-page`: `web` → `tool:privileged`. A web page's summary carrying an instruction to call the payment tool.
3. `tool-reply`: `tool` → `tool:privileged`. A weather-tool reply carrying the same kind of instruction.
4. `secret-response`: `vault` → `http:response`. A fake `sk-test-FAKE-…` key.
5. `csv-rows`: `user` → `llm`. CSV rows of names, emails and phones.

Custom runs supply `text`, `origin` and `sink` directly. `sink` is one of `llm`, `tool:privileged` or `http:response`.

### 3.2 Run flow (`rig.py`)

`run_scenario(pipeline, sinks, llm, *, text, origin, sink, protection) -> RunResult`:

1. Tag `text` with provenance from `origin`.
2. **Protection ON:** `guard(Action(sink, name, prov), text)`. DENY means nothing reaches the sink. ALLOW or REDACT delivers `result.payload`.
   **Protection OFF:** deliver the raw text, and append an audit entry with effect `bypass` and reason `protection off`, through a small `audit_bypass()` helper on the rig that redacts metadata the same way the pipeline does.
3. Deliver:
   - `tool:privileged`: `MockPaymentTool.call(delivered)`.
   - `http:response`: the delivered text is the response body.
   - `llm`: `llm.complete(delivered)`. The reply goes through `guard(Action("http:response", "llm-reply", combine(prov)), reply)` when protection is ON, so output-side redaction is visible.
4. Return `RunResult(sent, decision {effect, reason, rule}, delivered, reached_sink: bool, llm_reply, audit_entry)`.

### 3.3 LLM backends (`llm.py`)

`LLM.complete(prompt: str) -> str`.
- **`MockLLM`:** returns `"Echo: " + prompt`, so leaks are obvious with protection OFF.
- **`ClaudeLLM`:** the Anthropic Messages API. The model comes from `CLAUDE_MODEL`, defaulting to the current recommended model.
- **`GeminiLLM`:** `google-genai`. The model comes from `GEMINI_MODEL`, defaulting to the current recommended model.
- Both real backends have a short system prompt ("You are a helpful assistant in a security demo. Reply briefly."), `max_tokens` around 300, and a 30 s timeout.
- **Errors:** a missing key, network failure or API error returns a clear error string such as `"[claude unavailable: missing ANTHROPIC_API_KEY]"`. It never falls back to sending the text somewhere else, and never includes the key.

`create_app(llm_factory=...)` lets tests inject fakes.

### 3.4 HTTP API (`app.py`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | the console page |
| GET | `/api/scenarios` | the presets |
| GET | `/api/llms` | `[{id, available}]`; `available` means a key is set (the key itself is never returned) |
| POST | `/api/run` | `{scenario_id?, text?, origin?, sink?, protection: bool, llm: "mock"\|"claude"\|"gemini"}` → `RunResult` JSON |
| GET | `/api/audit` | entries |
| POST | `/api/audit/verify` | `{ok: bool, entries: n}` |
| POST | `/api/audit/tamper-demo` | copies the log, flips one entry's effect in the copy, returns `{original_ok, tampered_ok}`. The live log is untouched. |
| POST | `/api/reset` | clears the in-memory audit log and the mock sinks |

Request validation uses pydantic. An unknown `origin`, `sink`, `llm` or `scenario_id` gets a 422. Text is capped at 20 KB.

### 3.5 Console (`static/index.html`)

One page in three columns:
- **Left:** the Protection switch, the LLM picker (unavailable backends are disabled), the presets and a custom form.
- **Middle:** for the last run, "Sent" → a decision badge (ALLOW, REDACT, DENY or BYPASS, with the reason) → "Reached the LLM or tool" → the LLM reply.
- **Right:** the live audit table, with Verify and Tamper demo buttons.

It uses no external scripts or fonts. It works in both light and dark mode.

## 4. Testing

`tests/test_webapp.py`, using FastAPI `TestClient` with the mock LLM and no network. The module is skipped when the `webapp` group isn't installed.

- **Every preset, protection ON:** the defended outcome holds. `pii-chat` and `csv-rows` reach the LLM with no raw synthetic PII; `injected-page` and `tool-reply` record no payment call; `secret-response` doesn't contain the key.
- **Every preset, protection OFF:** the raw value reaches the mock sink or response, and the audit has a `bypass` entry.
- `/api/audit/verify` returns true after runs. `tamper-demo` reports `{original_ok: true, tampered_ok: false}`, and the live log still verifies.
- **No key leaks:** with fake keys set in the env, no response body from any endpoint contains them, and `/api/llms` reports availability only.
- **LLM errors:** a failing fake LLM gives an error string in `llm_reply` and the run is still audited.
- **Loopback:** the `__main__` host check rejects `0.0.0.0` and accepts `127.0.0.1`.
- **Validation:** bad inputs get a 422.
- One `@pytest.mark.live` test per real backend runs only when `-m live` is passed and the key is present.

## 5. Done

- `uv run --group webapp pytest` passes. The base `uv run pytest` still passes, with the webapp tests skipped when the group is missing.
- `uv run --group webapp python -m webapp` opens a working console. Every preset shows a visible difference between ON and OFF.
- The README has a "See it work" section with the run command.
