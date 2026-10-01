"""FastAPI app for the demo console. Local only; see webapp/__main__.py."""

from __future__ import annotations

import json
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from datasec.audit import AuditLog
from datasec.errors import DataSecError
from datasec.pipeline import SecurityPipeline

from .llm import available, make_llm
from .rig import run
from .scenarios import BY_ID, SCENARIOS
from .sinks import Sinks

STATIC = Path(__file__).with_name("static")
LOCAL_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})


def _hostname(netloc: str) -> str | None:
    try:
        return urlsplit("//" + netloc).hostname
    except ValueError:
        return None


def default_pipeline() -> SecurityPipeline:
    try:
        from datasec.presidio import PresidioRedactor

        return SecurityPipeline(redactor=PresidioRedactor())
    except DataSecError:
        return SecurityPipeline()


class RunRequest(BaseModel):
    scenario_id: str | None = None
    text: str | None = Field(default=None, max_length=20_000)
    origin: Literal["user", "web", "tool", "vault"] | None = None
    sink: Literal["llm", "tool:privileged", "http:response"] | None = None
    protection: bool = True
    llm: Literal["mock", "claude", "gemini"] = "mock"


def create_app(
    *, pipeline_factory: Callable[[], SecurityPipeline] | None = None, llm_factory: Callable | None = None,
) -> FastAPI:
    app = FastAPI(title="DataSec Demo Console", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        # Host check stops DNS rebinding (a remote page re-pointed at 127.0.0.1 would
        # otherwise become same-origin and could spend the user's API keys).
        if _hostname(request.headers.get("host", "")) not in LOCAL_HOSTNAMES:
            return JSONResponse({"detail": "host not allowed"}, status_code=400)
        if request.method == "POST":
            # No cross-site writes: any page the user visits could otherwise POST here.
            origin = request.headers.get("origin")
            if origin is not None and urlsplit(origin).hostname not in LOCAL_HOSTNAMES:
                return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
            if request.headers.get("sec-fetch-site") not in (None, "same-origin", "none"):
                return JSONResponse({"detail": "cross-site request refused"}, status_code=403)
            # JSON only: simple (no-preflight) form/text POSTs can't reach the API.
            if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
                return JSONResponse({"detail": "application/json required"}, status_code=415)
        return await call_next(request)
    make_pipeline = pipeline_factory or default_pipeline
    llms = llm_factory or make_llm
    app.state.pipeline = make_pipeline()
    app.state.sinks = Sinks()

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/scenarios")
    def scenarios() -> list[dict]:
        return [asdict(s) for s in SCENARIOS]

    @app.get("/api/llms")
    def list_llms() -> list[dict]:
        return [{"id": n, "available": available(n)} for n in ("mock", "claude", "gemini")]

    @app.get("/api/info")
    def info() -> dict:
        redactor = app.state.pipeline.redactor
        return {"redactor": "presidio" if getattr(redactor, "ner_capable", False) else "regex"}

    @app.post("/api/run")
    def run_scenario(req: RunRequest) -> dict:
        if req.scenario_id is not None:
            s = BY_ID.get(req.scenario_id)
            if s is None:
                raise HTTPException(422, "unknown scenario")
            text, origin, sink = s.text, s.origin, s.sink
        elif req.text is not None and req.origin and req.sink:
            text, origin, sink = req.text, req.origin, req.sink
        else:
            raise HTTPException(422, "give scenario_id, or text + origin + sink")
        result = run(
            app.state.pipeline, app.state.sinks, llms(req.llm),
            text=text, origin=origin, sink=sink, protection=req.protection,
        )
        return asdict(result)

    @app.get("/api/audit")
    def audit() -> list[dict]:
        return [asdict(e) for e in app.state.pipeline.audit]

    @app.post("/api/audit/verify")
    def verify() -> dict:
        log = app.state.pipeline.audit
        return {"ok": log.verify(), "entries": len(log)}

    @app.post("/api/audit/tamper-demo")
    def tamper_demo() -> dict:
        entries = [asdict(e) for e in app.state.pipeline.audit]
        if not entries:
            raise HTTPException(400, "run a scenario first")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "copy.jsonl"
            path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))
            original_ok = AuditLog.load(path).verify()
            entries[0]["effect"] = "allow" if entries[0]["effect"] != "allow" else "deny"
            path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))
            tampered_ok = AuditLog.load(path).verify()
        return {"original_ok": original_ok, "tampered_ok": tampered_ok}

    @app.post("/api/reset")
    def reset() -> dict:
        app.state.pipeline = make_pipeline()
        app.state.sinks.reset()
        return {"ok": True}

    return app
