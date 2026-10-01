import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from datasec.pipeline import SecurityPipeline  # noqa: E402
from webapp.__main__ import check_host  # noqa: E402
from webapp.app import create_app  # noqa: E402
from webapp.llm import MockLLM  # noqa: E402
from webapp.scenarios import SCENARIOS  # noqa: E402


@pytest.fixture
def client():
    app = create_app(pipeline_factory=SecurityPipeline, llm_factory=lambda name: MockLLM())
    return TestClient(app, base_url="http://127.0.0.1")


def test_page_and_lists(client):
    assert "DataSec Demo Console" in client.get("/").text
    assert [s["id"] for s in client.get("/api/scenarios").json()] == [s.id for s in SCENARIOS]
    assert client.get("/api/info").json() == {"redactor": "regex"}
    llms = {x["id"]: x["available"] for x in client.get("/api/llms").json()}
    assert llms["mock"] is True and set(llms) == {"mock", "claude", "gemini"}


@pytest.mark.parametrize("s", SCENARIOS, ids=[s.id for s in SCENARIOS])
def test_every_preset_defends_when_on_and_leaks_when_off(client, s):
    on = client.post("/api/run", json={"scenario_id": s.id, "protection": True}).json()
    off = client.post("/api/run", json={"scenario_id": s.id, "protection": False}).json()
    assert on["decision"]["effect"] in {"redact", "deny"}
    assert off["decision"]["effect"] == "bypass" and off["delivered"] == s.text
    assert on["delivered"] != s.text


def test_injection_payment_calls(client):
    client.post("/api/run", json={"scenario_id": "injected-page", "protection": True})
    assert client.app.state.sinks.payment.calls == []
    client.post("/api/run", json={"scenario_id": "injected-page", "protection": False})
    assert len(client.app.state.sinks.payment.calls) == 1


def test_custom_run(client):
    r = client.post("/api/run", json={
        "text": "mail jane@example.com", "origin": "user", "sink": "llm", "protection": True,
    }).json()
    assert r["delivered"] == "mail [EMAIL]" and r["llm_reply"] == "Echo: mail [EMAIL]"


@pytest.mark.parametrize("body", [
    {"scenario_id": "nope"},
    {"text": "x", "origin": "martian", "sink": "llm"},
    {"text": "x", "origin": "user", "sink": "exfil"},
    {"text": "x", "origin": "user"},
    {"scenario_id": "pii-chat", "llm": "gpt"},
    {"text": "x" * 20_001, "origin": "user", "sink": "llm"},
])
def test_bad_requests_are_422(client, body):
    assert client.post("/api/run", json=body).status_code == 422


def test_audit_verify_and_reset(client):
    client.post("/api/run", json={"scenario_id": "pii-chat", "protection": True})
    client.post("/api/run", json={"scenario_id": "pii-chat", "protection": False})
    assert len(client.get("/api/audit").json()) >= 2
    assert client.post("/api/audit/verify", json={}).json()["ok"] is True
    client.post("/api/reset", json={})
    assert client.get("/api/audit").json() == []


def test_tamper_demo_leaves_live_log_intact(client):
    assert client.post("/api/audit/tamper-demo", json={}).status_code == 400  # nothing to tamper yet
    client.post("/api/run", json={"scenario_id": "injected-page", "protection": True})
    result = client.post("/api/audit/tamper-demo", json={}).json()
    assert result == {"original_ok": True, "tampered_ok": False}
    assert client.post("/api/audit/verify", json={}).json()["ok"] is True
    assert client.get("/api/audit").json()[0]["effect"] == "deny"


def test_no_endpoint_leaks_api_keys(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-LEAKCHECK-1")
    monkeypatch.setenv("GEMINI_API_KEY", "gm-LEAKCHECK-2")

    class Failing:
        def complete(self, prompt):
            raise RuntimeError("auth failed for sk-ant-LEAKCHECK-1")

    client = TestClient(
        create_app(pipeline_factory=SecurityPipeline, llm_factory=lambda name: Failing()),
        base_url="http://127.0.0.1",
    )
    bodies = [client.get(p).text for p in ("/", "/api/scenarios", "/api/llms", "/api/info", "/api/audit")]
    for llm in ("mock", "claude", "gemini"):
        bodies.append(client.post("/api/run", json={"scenario_id": "pii-chat", "llm": llm}).text)
    bodies.append(client.post("/api/audit/verify", json={}).text)
    joined = "\n".join(bodies)
    assert "LEAKCHECK" not in joined
    assert json.loads(bodies[2]) == [
        {"id": "mock", "available": True}, {"id": "claude", "available": True}, {"id": "gemini", "available": True},
    ]


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_loopback_hosts_allowed(host):
    check_host(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "example.com", "::"])
def test_non_loopback_hosts_refused(host):
    with pytest.raises(SystemExit):
        check_host(host)


def test_page_never_uses_innerhtml():
    from pathlib import Path

    page = Path("webapp/static/index.html").read_text()
    assert "innerHTML" not in page and "outerHTML" not in page and "insertAdjacentHTML" not in page
    assert "textContent" in page  # model output is rendered as text, never as HTML
    assert "<script src=" not in page  # no external scripts


def test_rebinding_host_rejected(client):
    assert client.get("/api/audit", headers={"Host": "attacker.example:8000"}).status_code == 400
    assert client.get("/api/audit", headers={"Host": "localhost:8000"}).status_code == 200
    assert client.get("/api/audit", headers={"Host": "[::1]:8000"}).status_code == 200


@pytest.mark.parametrize("headers", [
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
    {"Sec-Fetch-Site": "cross-site"},
])
def test_cross_site_post_rejected(client, headers):
    client.post("/api/run", json={"scenario_id": "pii-chat"})
    assert client.post("/api/reset", json={}, headers=headers).status_code == 403
    assert len(client.get("/api/audit").json()) >= 1


def test_non_json_post_rejected(client):
    r = client.post("/api/reset", content=b"x", headers={"Content-Type": "text/plain"})
    assert r.status_code == 415


def test_same_origin_post_allowed(client):
    headers = {"Origin": "http://127.0.0.1:8000", "Sec-Fetch-Site": "same-origin"}
    assert client.post("/api/reset", json={}, headers=headers).status_code == 200
