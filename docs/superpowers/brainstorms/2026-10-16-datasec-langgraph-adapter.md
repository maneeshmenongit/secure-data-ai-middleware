# [2026-10-16] Phase 3B brainstorm — paused state (LangGraph adapter, paper-trader pilot)

**Status:** PAUSED at brainstorming checklist step 3 (clarifying questions). Two decisions made. No spec, no plan, no code yet.
**Path:** architectural (new adapter module here + an external pilot) — full spec → plan → Native execution → whole-branch review.
**Branch:** `feat/langgraph-adapter` (no commits of its own yet; same as `master` when paused).
**ON HOLD.** The two conditions below are now **both met**; 3B waits only for the provenance-gate cycle (see the status update). Originally on hold (user, 2026-10-17) until **both** of these were true:
1. **The Via 3A handoff has been run.** The user runs `docs/handoffs/2026-10-05-PROMPT_via_datasec_3A.md` in a via-skelton thread.
2. **The design thread's 3B doc is in `docs_to_claude/`.** The design thread wrote a 3B design after reading `reports/2026-10-16-phase3-progress-report.md`, and the user will drop it there.

Work resumes in a **new thread**.

**When resuming:**
- **The design thread's 3B doc becomes the parent of the spec** (`datasec-new-feature` §1). Read it fully first.
- The doc may already answer some of the questions below, so check them against it and don't ask anything it settles. These questions are the likeliest to be covered:
  - Q5 (are observability stores `memory:write`?)
  - Q7 (prompt-injection stance)
  - Q8 (who owns the pipeline under Via)
- **If the doc contradicts D1 or D2,** don't silently pick one side. Show the user both and let them decide, because D1 and D2 were their decisions.
- **Check what the 3A Via thread handed back** (`git -C ~/PycharmProjects/via-skelton log`, read-only). It affects Q8.

Then invoke `superpowers:brainstorming` and resume at the first question the doc leaves open. If the doc answers none, that is **Q3**. Do **not** re-ask D1 or D2.

## Status update, 2026-10-25
- **3A is closed on DataSec's side.**
  - Via has run it twice.
  - The egress false-positive fix is merged (`a8baacc`).
  - Via is re-pinned to `1a1eb54`.
  - Still open, on Via's side and the principal's: flipping `tool:privileged` and `memory:write` from shadow to enforce once the shadow data has been reviewed.
- **Design-thread input for 3B has arrived:** `docs_to_claude/design/phase3/2026-10-17-design-thread-input-3B.md`. It is the 3B spec's parent, so read it fully. Its answers:
  - **Q5 (observability stores):** out of scope **only if they are never read back** into a prompt or a decision. Define this by behaviour, not by name, and put that test in the design.
  - **Q7 (prompt injection):** taint on the output is enough. No delimiting of untrusted spans now; record it as a future option.
  - **Q8 (pipeline ownership):** **inject** the pipeline and audit log from Via's 3A profile, one of each per project. Build a default only when running standalone.
  - **New design goal:** the adapter is the **only** place trust is assigned, which closes R1g.1. Add a test that a node cannot raise a field's trust.
  - It also says to defer 3C, keep the external harness out of this repo, and keep the audit anchor deferred.
- **3B now comes after the provenance-gated egress cycle** (user, 2026-10-25). That cycle changes what the `llm` sink means for every adapter.
  - It is expected to add per-part provenance on egress payloads. The 3B per-field labels should reuse that mechanism.
  - When 3B resumes, start from that cycle's spec, then this file, then the design doc. Q3 (where labels travel) may already be answered by it.

## Decisions made (user, 2026-10-15/16)

- **D1 — Scope: a framework-neutral agent adapter plus a thin LangGraph layer.**
  - The reusable core is built here: per-field trust labels that travel with agent state, a guarded node wrapper, a guarded LLM router, and a guarded tool client.
  - The LangGraph layer adapts the node wrapper to `StateGraph.add_node`. It is tested here against real `langgraph` (an optional extra or dev group, never a core dependency) on a small sample graph.
  - `paper-trader` pilots the neutral core through the hooks it already has. It is **not** ported to `StateGraph`.
  - Rejected:
    - B: LangGraph only, with the pilot deferred.
    - C: port paper-trader to `StateGraph` first, because that is the largest external change and couples the pilot to a refactor.
- **D2 — What may drive a trade: the existing per-source allowlist.**
  - Market data is EXTERNAL with fixed source names (`market:yfinance`, `market:coingecko`), and the pilot's `privileged_source_allowlist` names them for `tool:privileged`.
  - Headlines, and anything an LLM wrote from them, are UNTRUSTED and are never allowlisted.
  - The core needs no change.
  - Known cost: `combine()` defaults the source to `"derived"` (`src/datasec/provenance.py:73`). A View built from **two** allowlisted feeds is therefore denied. The adapter needs a narrow, tested helper for "derived only from allowlisted sources". That helper must never apply when any input is UNTRUSTED.
  - Rejected:
    - B: a validator that "endorses" data to INTERNAL. This would be a new declassification path in the core, open to laundering.
    - C: treat paper trades as `tool:readonly`. That leaves no guard on the very sink the pilot exists to protect.

## paper-trader facts (read-only survey, 2026-10-08)

The repo is `~/PycharmProjects/paper-trader`. **Never edit it from here. Never run it: it spends LLM budget and trades.** All paper-trader-side work goes into a self-contained handoff prompt, `docs/handoffs/YYYY-MM-DD-PROMPT_paper-trader_datasec_3B.md`, pinned to a datasec commit. Paths below are relative to `src/paper_trader/`. Re-check them before pinning, because that repo moves.

- **LangGraph is declared but unused.** `pyproject.toml` lists `langgraph>=0.2.0` (the lock pins 1.2.8), but nothing imports it.
- **The "graph" is a hand-rolled async loop.**
  - `graph/supervisor.py:79-99` (`Supervisor.run_cycle`) with deterministic routing in `graph/decisions.py`.
  - Flow: start → [postmortem] → filter → research → predict → execute → end, then a read-only observer.
  - It is assembled in `harness/assembly.py:58` and run from `harness/runner.py:134`, called by `scripts/run_live.py:112`.
- **State.** `graph/state.py:31` defines `CycleState` (pydantic). `research_bundles`, `predictions` and `trade_decisions` are dicts keyed by **symbol**.
- **Nodes.** Each agent has `name`, a `writes` whitelist and `async run(state)`. `agents/enforce.py:29` checks the write-set by diffing `model_dump()`. `ALWAYS_WRITABLE` is in `agents/base.py:38`, which is a **frozen** file synced from another project.
- **LLM.** Every call goes through `router.call(purpose, system, user, …)` (`llm/configurable_router.py:62`). `backtest/attesting_router.py:30` already wraps that same `call` surface, so a DataSec router can follow the same pattern.
  - Call sites: research `:91`, `:103`; postmortem `:153`.
  - Clients: Claude, Gemini, Groq, Ollama, OpenRouter.
- **Untrusted inputs.**
  - Finnhub headlines (`data/live/finnhub_client.py:74`) become `ResearchBundle.news` and go into the LLM prompt as `str(news)` with no escaping (`agents/research.py:92,104`).
  - The LLM output becomes `bundle.narrative` and `bundle.keywords`.
  - GDELT is used only by scripts.
- **External inputs.** yfinance OHLCV (`data/live/yfinance_client.py:94`) and CoinGecko. The closes alone drive Predict (`agents/predict.py:123`) and then Execute. **No headline-derived data reaches Execute today.**
- **Privileged sinks.**
  - `trading_client.submit_paper_trade` (`agents/execute.py:126`). This is a simulated ledger (`live/trading.py:38`), not a broker.
  - Portfolio changes: `agents/postmortem.py:76` and `harness/runner.py:181`.
  - App-db writes: `persistence/cycle_writer.py`.
  - Memory/provenance store: `agents/memory.py:93`, used by scripts only.
  - Store A snapshots: `graph/emit_boundary.py`. These contain headlines and LLM narrative.
- **Injection seam.** `DataProviders` (`live/providers.py:35`) bundles the trading client and the data clients. Offline fakes are the default.
- **Tests.** Run with `uv run pytest` (asyncio auto). About 570 tests. `tests/fixtures/fakes.py` has `FakeLLMRouter`, `FakeTradingClient`, `FakeMarketData` and `FakeCompanyNews`.

## Questions still to ask (one at a time, in this order)

- **Q3 — Where do labels travel?**
  - (a) A side table held by the wrapper, keyed by `(cycle_id, field[, symbol])`, outside the state. The write guard and the frozen files are untouched.
  - (b) A new `CycleState.labels` field. This needs `ALWAYS_WRITABLE` (in frozen `base.py`) or every agent's `writes` to change.
  - Lean: (a), because the LangGraph layer can keep labels in its own state channel instead.
- **Q4 — How does a node declare its trust?** Each wrapped node declares which sinks it calls and the trust/source of each field it writes. Undeclared fields fail closed and get the weakest trust of the node's inputs.
- **Q5 — Which paper-trader sinks does the pilot cover?**
  - Candidates:
    - `submit_paper_trade` → `tool:privileged`
    - `router.call` → `llm`, with the provider host as destination
    - portfolio changes
    - the memory store → `memory:write`
  - **Trap:** Store A / emission snapshots hold UNTRUSTED headlines, and `memory:write` is privileged, so a strict rule would deny every snapshot. Decide whether observability and audit stores are a `memory:write` sink at all, or are out of scope.
- **Q6 — Rollout.** Follow 3A: shadow `tool:privileged` and `memory:write` first, read `python -m datasec.report`, then enforce. Egress (`llm`) is always enforced.
- **Q7 — Prompt-injection stance on the `llm` sink.** UNTRUSTED data going to `llm` is allowed today; only PII is redacted. The control is that LLM *outputs* inherit UNTRUSTED. Decide whether to keep that (YAGNI) or add delimiting/spotlighting of untrusted spans.
- **Q8 — Who owns the pipeline when Via runs paper-trader?** If Via (3A) builds the pipeline and profile, the 3B adapter should accept a pipeline built elsewhere rather than build its own. Check `via-skelton` read-only for how it launches paper-trader.
- **Q9 — The LangGraph layer's surface.** Sync and async node functions; where labels live in graph state (a reserved channel); the supported `langgraph` version range; a test-only sample graph.

## Candidate shape (NOT approved; for orientation only)

- `datasec.adapters.agent`: a label store, `guard_node(...)` (wraps `run(state)`), `GuardedRouter` (the `call` surface), and `guarded_tool(...)`. All of them go through `adapters.gate.check`.
- `datasec.adapters.langgraph`: `node(fn, …)` for `add_node`.
- Evidence:
  - Red-team attacks: headline text driving a trade is denied; an LLM narrative mixed into a View is denied; a mislabelled "derived" source is not allowlisted; shadow on egress is refused.
  - Unit tests against fakes. No network.
