# DataSec Middleware — Progress Report (Phase 3A → 3B started)

**Date:** 2026-10-16 · **Since:** [2026-10-02 progress report](2026-10-02-progress-report.md) · **Repo:** `master`, 22+ commits ahead of `origin` (**not pushed yet**) · Via integration pinned at `cf62c48`

## TL;DR

- **Phase 3 is split into three parts:**
  - **3A:** Via as host
  - **3B:** an agent / LangGraph adapter
  - **3C:** an ASGI adapter
- **3A, DataSec side: done and merged** (`c350788`). Via can now:
  - run tool and memory guards in **shadow mode**: they record what *would* have been denied and block nothing
  - enforce everything else
  - read a verified audit summary with `python -m datasec.report`
- **3A, Via side: handed over.** Via's code is never edited from this repo. Its share of the work is delivered as a self-contained prompt that the user runs in a Via thread (`docs/handoffs/2026-10-05-PROMPT_via_datasec_3A.md`). The same rule now covers every external repo, including `paper-trader`.
- **One-page capabilities summary** for Via: `docs/handoffs/2026-10-07-datasec-capabilities.md`.
- **The red team grew from 81 to 87 attacks:** 79 defended, 8 known gaps (unchanged), 0 unexpected. **Tests: 434 passed, 8 xfailed** (the known gaps).
- **3B has started.** The brainstorm is paused after two decisions; the rest of the design is open. **We'd like the design thread's input** on the questions below.

## What shipped

| Merge / commit | What it adds |
|---|---|
| 3A DataSec side (`c350788`, pinned `cf62c48`) | `Action.shadow` is an audit-only marker that never changes a decision. `datasec.adapters.gate.check(pipeline, action, payload, Mode)` either enforces or shadows. Shadow mode is accepted only for `tool:privileged` and `memory:write`, and **never** for secret memory writes. When the gate blocks, `Blocked` carries redacted text only. `python -m datasec.report` verifies the hash chain *before* summarising, counts decisions by sink, effect and mode, and lists the shadow denials. It exits 1 on a broken or corrupt log. |
| Via handoff prompt (`acf40d4`) | A pinned install line, the exact API and exception contract, tasks, done criteria, a manual shadow run, and traps for the Via thread |
| Capabilities one-pager (`12e94af`, `b963e8b`) | What DataSec protects against, how to roll it out, its guarantees, the evidence, and its known limits. It is written for Via |
| Project skills (`457eb4f`, then updates) | `datasec-onboard`, `datasec-new-feature` and `datasec-closeout`. They now also cover handoff prompts for external repos and how to resume a paused design |

**Decision recorded:** egress is always enforced. A project profile may shadow only the tool and memory sinks. No setting can turn off redaction or secret blocking on `llm` or `third_party`.

## Red-team scorecard

| Category | Defended | Known gap |
|---|---|---|
| Taint laundering | 9 | 1 |
| PII evasion | 22 | 4 |
| Secret exfiltration | 10 | 0 |
| Audit tampering (+R4.13: the report flags a flipped denial) | 13 | 3 |
| Fail-closed (+R5.10–R5.14: shadow on egress, misspelled sinks, a pre-set shadow flag on a secret, the enforce gate, PII hidden in a `Blocked` message) | 14 | 0 |
| Resource abuse | 11 | 0 |
| **Total** | **79** | **8** |

These numbers are from a fresh run on 2026-10-16 with Presidio installed (0 skipped).

## Issues found and fixed (3A whole-branch review)

The review found 0 critical and 4 important issues. Each is fixed and has a regression test:

- **I1:** shadow mode accepted sinks other than tool and memory, and an egress sink could be shadowed if it was misspelled. The fix is an allowlist of exactly `tool:privileged` and `memory:write`, so any other sink is refused.
- **I2:** the `Blocked` exception repeated the raw reason, which could contain PII. The reason is now redacted.
- **I3:** a secret memory write could be shadowed, which would skip sealing at rest. That is now refused.
- **I4:** the egress denial reason quoted the destination. The reason is now generic, and the redacted destination goes into the audit record only.

Three review minors were also fixed:

- Egress entries were wrongly marked as shadow.
- Control characters in the report could forge lines.
- A non-UTF-8 log or a malformed key crashed the report instead of failing cleanly.

**Totals across all five whole-branch reviews:** 3 critical and 22 important, all fixed. **My own defects caught before merge:** two wrong tests (the forge test counted escaped text; the key test never created the log), and a RED check that hid the new attacks. All three were found and corrected before commit.

**Deferred minors, none of which fail open:**

- **M3:** the report summarises entries even after the chain fails to verify, and crashes on fields with the wrong type. The exit code is still 1.
- **M5:** the report's wording needs caveats.
- **M6:** `check()` called with something that isn't an `Action` raises before anything is audited.
- **M7:** `Blocked` can't be pickled.
- **M8:** the report loads the whole log into memory.
- **M9:** the report's tests have gaps.

## Known gaps (8, unchanged, all deliberate and tested)

They are the same as in the last report: R1g.1 (hand-built TRUSTED provenance), R2g.1–R2g.4 (PII the patterns can't see), and R4g.1–R4g.3 (truncation or replay without an external anchor). 3B can help with R1g.1, because the adapter becomes the only place that assigns trust in an agent graph.

## 3B so far: an agent adapter, piloted on `paper-trader`

**What we found:** paper-trader lists `langgraph` as a dependency but **never imports it**. Its "graph" is a hand-written async supervisor loop:

> filter → research → predict → execute

with a pydantic state object and deterministic routing. It does have clean hook points:

- a per-node wrapper slot
- one LLM router that every call goes through
- an injected trading client

Two more facts shape the design:

- **The main untrusted input is Finnhub headlines.** They are pasted into LLM prompts as-is.
- **Trades are driven only by yfinance prices.** No headline-derived data reaches the trade step today. The adapter is meant to make sure it never can.

**Decisions made (DESIGN §10.9, §10.10):**

1. **Scope.** We'll build a framework-neutral agent adapter here, with three parts:
   - trust labels that travel with each state field
   - a guarded node wrapper
   - a guarded LLM router and tool client

   A thin LangGraph layer sits on top and is tested against real `langgraph`. paper-trader pilots the neutral core through its existing hooks and is not ported to LangGraph. Its side of the work is delivered as a handoff prompt.
2. **What may drive a trade.** This reuses the existing per-source allowlist, so the core doesn't change:
   - Market-data feeds are EXTERNAL with fixed source names, which the pilot allowlists.
   - Headlines, and anything an LLM wrote from them, are UNTRUSTED and are never allowlisted.

   Two options were rejected. A validator that "endorses" data up to INTERNAL would be a new way to launder trust. Treating paper trades as read-only would leave the sink unguarded.

## Where the design thread can contribute (later phases)

**For 3B** (we'll ask these one at a time when the brainstorm resumes; your view now would shape the answers):

1. **Are observability stores a "memory" sink?** paper-trader snapshots each step's outputs, untrusted headlines included, into an audit-style store. `memory:write` is privileged, so a strict policy would deny every snapshot. Our lean is to treat log and audit stores as **out of scope** for `memory:write`, and to reserve that sink for memory an agent later *reads back as context*. Do you agree?
2. **Prompt-injection stance on the `llm` sink.** Today, untrusted text may reach an LLM (PII is redacted), and the LLM's *output* inherits UNTRUSTED. That is what stops it from driving actions. Is that enough, or do you want untrusted spans marked or delimited inside prompts as well? That would add cost and complexity.
3. **Who builds the pipeline when Via runs paper-trader?** If Via's per-project profile (3A) owns the pipeline, the 3B adapter should accept a pipeline built elsewhere. We assume one pipeline and one audit log per project.

**For 3C (ASGI) and beyond:**

4. **3C scope.** Which HTTP projects come first, and should 3C reuse anything from the earlier ASGI test-rig spec (`datasec-asgi-testrig-spec.md`)?
5. **Phase 5 (the out-of-band harness) needs re-scoping.** This thread can't author the out-of-band attack harness, and the user skipped it (2026-10-02/03). If you still want external testing, please specify it as something run outside this repo. One agreed option is OWASP Juice Shop as the target for classic web vulnerabilities.

**Carried over from 2026-10-02 (still open):**

6. **Audit anchor location (closes R4g.3).** We still recommend a database row the application can't write, once Via has one.
7. **The location false-positive trade-off.** Once a location appears in a string, bare 5-digit numbers, long decimals and state codes in that string are redacted too. Is that acceptable?

## Still open (operational)

- The **user** pushes master (22+ commits).
- The **Via thread** runs the 3A handoff. Then the user does a manual shadow run and runs `python -m datasec.report` to tune the trust table. Only after that do the tool and memory sinks switch to enforce.
- The **3B brainstorm resumes** from `docs/superpowers/brainstorms/2026-10-16-datasec-langgraph-adapter.md`.

## Reproduce

```bash
uv sync --extra presidio --group presidio-model --group webapp
uv run pytest -q                          # 434 passed, 8 xfailed
uv run python -m redteam.runner           # 79 passed, 8 known gaps, 0 skipped, 0 unexpected / 87
uv run python -m datasec.report <audit.jsonl>   # verify + summarise an audit log
```
