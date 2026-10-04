# DataSec Phase 3A — Via Host Integration Design

**Date:** 2026-10-03 · **Status:** approved 2026-10-04 · **Parents:** DESIGN.md §3.4, §6, §8 · **Target:** `~/PycharmProjects/via-skelton`

## 1. Phase 3 shape: three sub-projects

DESIGN §6 planned an ASGI adapter and a LangGraph adapter. Via, however, is a **host**. It is an autonomous agent with memory that runs many projects, and it already plugs in middlewares (PulseWise for analytics, with HonedWise among the projects it runs). The projects Via runs have their own stacks. For example, `paper-trader` is a multi-agent LangGraph system whose untrusted news and market data can reach a trade-execution agent. Security therefore has to work at two levels, so Phase 3 has three sub-projects, each with its own spec → plan → build cycle:

| Sub-project | What it protects | Cycle |
|---|---|---|
| **A — Via host** (this spec) | Via's own operations for **every** project it runs: prompts, tool execution, memory and provider traffic. It is configured **per project** and reports to PulseWise like Via's other instruments. | now |
| **B — LangGraph adapter** | Multi-agent projects. Trust travels through graph state, so a research agent's fetched content can't drive an execute or trade agent. It will be piloted on `paper-trader` behind a flag. | next |
| **C — ASGI adapter** | Projects Via builds that serve HTTP. | after B |

A survey of Via shows it is a stdlib-only CLI and batch system with its own agent loop (`via/loop/engine.py`) and its own REST provider adapters (`via/substrate/providers/`). A therefore hooks Via's own choke points rather than a framework. Via and the `datasec` core are both stdlib-only, so there is no dependency clash.

## 2. Scope and constraints

- **This repo (`datasec`):** a shadow-mode marker, a small `adapters.gate` helper, and an audit report CLI.
- **`via-skelton`:** a feature branch `feat/datasec` that wires four hook points behind `VIA_DATASEC=1`. It is **off by default**. Nothing merges in Via without the user's review.
- **Rollout mode:**
  - **Enforce** on egress: `llm` and `third_party`.
  - **Shadow** on `tool:privileged` and `memory:write`. These are audited as would-deny but never blocked, until shadow data from real runs has been used to tune the trust mapping.
- **No live Via runs** in this cycle. In-flight Via work, budgets and data are untouched.
- **Fail closed:** if `VIA_DATASEC=1` is set and `datasec` can't be imported, or the pipeline can't be built, Via refuses to start with a clear message.
- **Via test suites:**
  - With the flag **off**, Via's existing test suite passes unchanged.
  - With the flag **on**, the new tests pass.

## 3. `datasec` changes

### 3.1 Shadow marker

`Action` gains `shadow: bool = False`. `guard()` is unchanged apart from one thing: when `shadow` is true, the audit entry's `extra` gets `{"mode": "shadow"}`. The returned `GuardResult` is the real decision, so a shadow DENY is still `allowed=False`, and the caller chooses what to do with it.

### 3.2 `datasec.adapters.gate`

```python
class Mode(Enum): ENFORCE = "enforce"; SHADOW = "shadow"

class Blocked(DataSecError):          # carries .decision (the DENY)
    ...

def check(pipeline, action, payload, mode: Mode) -> Any:
    """Return the payload the caller should use."""
```

- **ENFORCE:** ALLOW or REDACT returns `result.payload`. DENY raises `Blocked`.
- **SHADOW:** the action is sent with `shadow=True`. The original payload is always returned, unchanged and never redacted, so behaviour stays identical.

### 3.3 `python -m datasec.report <audit.jsonl> [--checkpoint PATH --key-env NAME]`

This prints:
- counts by sink × effect × mode
- the top deny reasons and rules
- shadow denials grouped by sink and source

It verifies the chain first (and the checkpoint, when one is given) and says so. It exits non-zero on a broken chain.

## 4. Via changes (branch `feat/datasec`)

### 4.1 `via/security/datasec_bridge.py` (the only module that imports `datasec`)

- `enabled()` returns true when `VIA_DATASEC=1`.
- `build_pipeline()` assembles the pipeline from these parts:
  - `PresidioRedactor` if it is installed, otherwise the regex `Redactor`.
  - **The project's own** `AuditLog` at `data/datasec/<project>/audit.jsonl` (§4.4). `$VIA_DATASEC_DIR` overrides the `data/datasec` root.
  - A signed checkpoint and a `LocalKeyProvider` **only** when `DATASEC_KEY_K1` is set and `cryptography` is importable. Otherwise the audit is chain-only, with a one-time warning.
  - `default_rules(egress_allowlist=...)`. The allowlist holds the provider hosts Via is configured for, plus the PulseWise host when `VIA_PULSEWISE_ENDPOINT` is set.
- **The trust mapping is a single table in this module.** This is a first draft, to be tuned from shadow data:

| Via source | TrustLevel | `source` string |
|---|---|---|
| memory row `provenance=principal`; principal hints | USER | `principal` |
| `via`, `genesis`; workspace files Via wrote | INTERNAL | `via`, `genesis`, `workspace` |
| referee / sweep stdout-stderr; consultant replies; rows `tool`, `external` | EXTERNAL | `tool:referee`, `llm:consultant`, `tool`, `external` |
| brownfield host-repo files; rows `web` | UNTRUSTED | `repo:host`, `web` |

- **Hook helpers**, one per sink:
  - `guard_prompt(messages, purpose) -> messages` (ENFORCE). It redacts each message's content in place.
  - `shadow_actions(actions, plan_provenance)` (SHADOW).
  - `shadow_memory_write(kind, provenance, content)` (SHADOW).
  - `check_destination(url)` (ENFORCE).
  - `guard_pulsewise(payload) -> payload` (ENFORCE, which redacts).

### 4.2 Prompt provenance

- Via's `Message` (`substrate/types.py`) gains an optional `provenance: Provenance | None = None`.
- `None` means INTERNAL, so every existing construction and test is unaffected.
- The brief builder (`loop/brief.py`) and the prompt assembly sites that insert referee output, consultant replies or host-repo files set `provenance` on the message they build. The value is `combine()` of the parts inserted: the weakest trust and the union of labels.

### 4.3 Hook points

| Sink | Location (survey refs) | Mode | On DENY |
|---|---|---|---|
| `llm` | `Substrate._do_call`, before `provider.complete` (`substrate/substrate.py:~404`); also the direct path `review/gate.py:~265` | enforce | raise into Via's existing provider-error handling, so the attempt fails visibly |
| `tool:privileged` | `Engine._execute_step`, right after `gate.assess` (`loop/engine.py:~1466`). Applies to `WriteFile`/`AppendFile`/`ReplaceInFile`/`RunCommand`, with the provenance of the prompt that produced the plan | shadow | never blocks; audited |
| `memory:write` | `MemoryStore.append` and `supersede` (`store/memory_store.py:~367/~409`). Trust comes from the row's `provenance` | shadow | never blocks; audited |
| `third_party` | `UrllibTransport.post` (`substrate/base.py:~73`): destination allowlist only, with an empty payload (the prompt was already guarded). `pulsewise._post`: payload redacted | enforce | raise into the transport's existing error path; for PulseWise, drop the event (it is fire-and-forget) and audit it |

Line numbers come from the survey. The plan re-verifies them against the branch head.

### 4.4 Per-project profiles

Via runs many projects, so security configuration is **per project**. The bridge is configured once per run with the project name (`args.project`, which is the same prefix Via uses for memory frames).

- **Profile file:** `data/datasec/<project>.json`. It is optional, and when it is missing the bridge defaults apply. It can set:
  - `modes`: per sink, `enforce` or `shadow`. The defaults are `llm` and `third_party` enforce; `tool:privileged` and `memory:write` shadow.
  - `trust_overrides`: entries that replace rows of the §4.1 table for this project only.
  - `egress_allowlist`: hosts this project may reach, added to the provider hosts.
  - `presidio`: `true`, `false` or `auto`.
- **Audit log per project:** `data/datasec/<project>/audit.jsonl`, plus `audit.checkpoint` when keys are available. Each project's evidence chain is separate, and `python -m datasec.report` runs against one project's log.
- **Bad profile:** an invalid profile file is a startup error when the flag is on. It is never silently ignored.

### 4.5 PulseWise metrics

DataSec reports to PulseWise the same way Via's other instruments do.

- **When:** at run close, next to `_audit_after_run`.
- **How:** the bridge emits one summary event through the existing `PulseWiseEmitter.from_env().emit(content=…, frame=f"{project}/security", run_id=…)`.
- **What:** counts only. These are decisions by sink × effect × mode, shadow denials by rule, redactions by label, and whether the chain verified. It **never sends payload text, sources or names.**
- **When PulseWise is off:** if the emitter is disabled (no `VIA_PULSEWISE_ENDPOINT`), this is a no-op.
- **What the plan must check:** the exact `content` shape PulseWise accepts (`to_pulse_event`). Changing PulseWise itself is out of scope.

## 5. Testing

**`datasec`** (TDD, in this repo):
- the shadow marker in the audit
- `check()` in both modes, including that shadow returns the original, unredacted payload
- report output on a known log, and its exit code on a broken chain

**Via, flag off:** the full existing suite, unchanged.

**Via, flag on** (new tests, using fake provider and transport objects, with no network and no spend):
- PII in a prompt is redacted before the provider sees it.
- A secret-labelled message blocks the call through the error path.
- A `RunCommand` planned from an EXTERNAL-derived prompt is audited as a shadow DENY and still executes.
- A memory write is audited with the mapped trust.
- An unknown transport host is refused.
- The PulseWise payload is redacted.
- `VIA_DATASEC=1` without `datasec` importable refuses to start.
- Two projects get separate audit logs and their own profile modes. Setting `"tool:privileged": "enforce"` in one project's profile blocks there but stays shadow in the other.
- An invalid profile is a startup error.
- The run-close PulseWise summary uses a fake emitter. It contains counts and no payload text, and it is a no-op when the emitter is disabled.

**Manual (user):** one real `via run` with the flag on, followed by `python -m datasec.report` to review the shadow denials before enabling enforcement.

## 6. Docs

- DESIGN.md §6 and §8: Phase 3 becomes A (Via host), B (LangGraph and `paper-trader`) and C (ASGI), each with its own cycle.
- §10.7, provenance persistence: partly answered. Memory rows already carry `provenance`, and prompts now carry it in memory.
- Via branch `INTEGRATION.md`: the flag, environment variables, modes, the trust table, and how to read the report and flip modes.

## 7. Out of scope

- Enforcing on tools and memory. That is a later flag flip, after tuning.
- Sealing secrets in Via memory. Via has no secret labels yet.
- The LangGraph adapter and the `paper-trader` pilot (sub-project B), and the ASGI adapter (sub-project C).
- Any change to Via's own gate, budget, or authentication.
