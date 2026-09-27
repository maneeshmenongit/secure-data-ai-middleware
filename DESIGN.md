# DataSec Middleware — Design Spec

**Status:** design, ready to implement · **Author:** Maneesh (Wise World LLC) · **Date:** 2026-09-27
**Intended builder:** Claude Code (this doc is the spec; it writes the code)

---

## 0. What this is and why two projects

Two related projects that are built to test each other:

1. **DataSec middleware** (this doc) — a *runtime* security layer that sits in the request/tool-call path of your projects. It intercepts, checks, redacts, encrypts, logs.
2. **Red-team harness** (companion doc, §7) — a *testing* system that runs *against* your projects out-of-band (CI / schedule) and reports what it broke.

They strengthen one another: every exploit the harness lands exposes a weak control in the middleware; every control the middleware adds gives the harness a new thing to try to bypass. Build a little of each in alternation rather than finishing one first.

**Sequence you chose:** build DataSec as a standalone runnable project first → then bring the design into Via once Via's interface stabilizes. This doc supports that: the core is framework-agnostic, and Via integration is isolated to thin adapters (§6).

---

## 1. Design goals

- **Framework-agnostic core.** The core knows nothing about FastAPI or LangGraph. The same security logic must protect an HTTP request path *and* an agent tool call. Framework specifics live only in adapters.
- **Provenance-first.** Trust travels *with* the data, not with the code path. This is what connects to Via's provenance axis and what makes anti-injection / anti-exfiltration rules possible.
- **Fail closed.** On any ambiguity a sink is denied, not allowed.
- **Zero-install first slice.** The initial version uses only the Python standard library so it runs anywhere. Heavier dependencies (Presidio, a real KMS) are drop-in upgrades behind stable interfaces.
- **Composable, one entry point.** Every adapter calls a single `SecurityPipeline.guard(...)` so behavior is consistent across entry points.

**Non-goals (first slice):** it is not a WAF, not an auth provider, not a secrets manager. It *consumes* those; it doesn't reimplement them.

---

## 2. Architecture

```
                       ┌─────────────────────────────────────────┐
   HTTP request  ─────▶│  ASGI adapter                            │
                       │                                          │
   LangGraph tool ────▶│  Tool-call adapter          (thin shims) │
                       └───────────────────┬──────────────────────┘
                                           │  calls guard(action, inputs)
                                           ▼
                       ┌──────────────────────────────────────────┐
                       │             SecurityPipeline              │
                       │   evaluate → redact → audit → return      │
                       └───┬───────────┬──────────┬───────────┬────┘
                           ▼           ▼          ▼           ▼
                     provenance    policy     redaction     audit
                     (taint)       (rules)    (PII)         (hash chain)
```

Package layout (proposed):

```
datasec-middleware/
  src/datasec/
    __init__.py
    provenance.py     # the spine: TrustLevel, Provenance, Tainted, combine()
    redaction.py      # PII detect/redact (regex now, Presidio later)
    policy.py         # Action, Decision, Effect, Rule, PolicyEngine
    audit.py          # hash-chained tamper-evident log
    pipeline.py       # SecurityPipeline.guard() ties it together
    adapters/
      asgi.py         # FastAPI/Starlette middleware  (Via HTTP path)
      langgraph.py    # tool-call wrapper             (Via agent path)
  tests/
  demo.py             # runnable end-to-end scenarios
  README.md
  DESIGN.md           # this file
```

---

## 3. The provenance / taint model (the spine)

Every value entering the system is wrapped at the boundary in a `Tainted[T]` container carrying a `Provenance`. Carry the wrapper through your logic; unwrap `.value` only when handing it to a sink the policy engine has cleared.

### 3.1 Trust levels

An ordered scale (`IntEnum`, lower = less trusted) so `min()` "just works":

| Level | Meaning |
|---|---|
| `UNTRUSTED` (0) | arbitrary external input: web pages, inbound email, internet tool output |
| `EXTERNAL` (1) | third-party API responses we called on purpose |
| `USER` (2) | the authenticated end user's own input |
| `INTERNAL` (3) | our own services and config |
| `TRUSTED` (4) | system-level, fully controlled (secrets, signed config) |

### 3.2 Provenance

Immutable (`frozen`) so trust can't be silently downgraded — you make a new one instead.

```python
@dataclass(frozen=True)
class Provenance:
    trust: TrustLevel
    source: str                 # "web:example.com", "user:req-42"
    labels: frozenset[str]      # {"pii"}, {"secret"}, ...
```

### 3.3 The one rule that matters — taint propagation

When a value is derived from several inputs, the result inherits:
- **trust = min(** all input trusts **)** — the weakest link wins
- **labels = union(** all input labels **)** — sensitivity is sticky

This is what stops *laundering*: you cannot fold a snippet of untrusted web text into a value and have it come out trusted. The **only** supported merge path is `combine(*inputs, value=...)`, so the rule can't be bypassed by hand-constructing a `Provenance`.

```python
def combine(*inputs: Tainted, source="derived", value=None) -> Tainted:
    trust  = min(t.provenance.trust for t in inputs)
    labels = union of every input's labels
    return Tainted(value, Provenance(trust, source, labels))
```

### 3.4 Mapping to Via

- Via's **trust dimension** ↔ `TrustLevel`.
- Via's **origin** ↔ `Provenance.source`.
- Via's **supersession / sensitivity tags** ↔ `Provenance.labels`.

When Via writes to long-term memory, the middleware's `memory:write` policy consults provenance: untrusted content can't overwrite trusted memory (memory-poisoning defense). This is the natural hook for Via's Week-4 principal-alignment work, so it's not a side quest.

---

## 4. Module contracts

Each module has a narrow, stable interface. Claude Code should implement to these signatures so adapters and tests don't churn.

### 4.1 `provenance.py`
- `TrustLevel(IntEnum)` — as §3.1.
- `Provenance(trust, source, labels)` frozen; `.with_labels(*l)`, `.has(l)`.
- `Tainted[T](value, provenance)` frozen; `.map(fn)` (single-input transform, trust unchanged).
- `combine(*inputs, source, value) -> Tainted` — the merge rule.
- Boundary constructors: `untrusted(...)`, `from_user(...)`, `internal(...)`.

### 4.2 `redaction.py`
- `Redactor.scan(text) -> {label: count}` — report without modifying (for decisions).
- `Redactor.redact(text) -> RedactionResult(text, found)` — replace spans with `[LABEL]` placeholders.
- First-slice detectors: `EMAIL, SSN, CREDIT_CARD, PHONE, IPV4` (regex).
- **Upgrade path:** swap the detector set for Presidio behind the same two methods; nothing else changes.

### 4.3 `policy.py`
- `Action(sink, name, provenance)` — what the system is about to do. Sink categories (strings): `llm`, `tool:privileged`, `tool:readonly`, `memory:write`, `third_party`, `http:response`.
- `Decision(effect, reason, rule)`; `Effect = ALLOW | REDACT | DENY`.
- `Rule(name, check)` where `check(action) -> Decision | None` (None = no objection).
- `PolicyEngine.evaluate(action) -> Decision`. **Resolution order: DENY > REDACT > ALLOW.**

### 4.4 `audit.py`
- Append-only, **hash-chained**: each entry stores `hash(prev_hash + entry_body)`. Any later edit breaks the chain.
- `AuditLog.append(entry)`, `AuditLog.verify() -> bool`, iterable of `AuditEntry`.
- Entry captures: timestamp, action sink/name, decision effect+reason, provenance summary, and a redaction tally (never raw PII/secret values).

### 4.5 `pipeline.py`
- `SecurityPipeline.guard(action, payload) -> GuardResult(allowed, payload, decision)`.
- Flow: `evaluate(action)` → if `DENY` return blocked; if `REDACT` run `Redactor.redact` on the payload; always `audit.append(...)`; return result.
- This is the single call every adapter uses.

---

## 5. Policy rule catalog (first slice)

| Rule | Fires when | Effect | Defends against |
|---|---|---|---|
| `no_untrusted_to_privileged` | `UNTRUSTED` data → `tool:privileged` / `third_party` / `memory:write` | DENY | prompt injection, excessive agency, memory poisoning |
| `never_leak_secrets` | value labelled `secret` → any egress sink (`llm`/`third_party`/`http:response`) | DENY | secret exfiltration |
| `redact_pii_on_egress` | value labelled `pii` → egress sink | REDACT | PII leakage to LLM / third parties |

Rules are pure predicates and pluggable, so the harness can add adversarial rules and you can grow the catalog without touching the engine.

---

## 6. Via integration (thin adapters — phase 3)

Keep all framework specifics here so the core stays portable.

- **`adapters/asgi.py`** — Starlette/FastAPI middleware. On each request: wrap the body as `from_user(...)` (or `untrusted(...)` for public endpoints), attach to the request scope. On response: `guard(Action("http:response", provenance=...), body)`.
- **`adapters/langgraph.py`** — wrap tool-call nodes. Before a tool runs: `guard(Action("tool:privileged"|"tool:readonly", name=tool, provenance=arg_provenance), args)`. Before an LLM node: `guard(Action("llm", provenance=prompt_provenance), prompt)`. On memory writes: `guard(Action("memory:write", provenance=...), record)`.
- Tool args derive their provenance via `combine(...)` of their sources, so a tool fed any untrusted input is treated as untrusted.

**Because Via is still at Spec stage:** don't harden a moving interface. Land the **threat model + taint rules into the Via spec now**, build the adapters alongside Via's first implementation slice, and point the harness at it once there's something real to attack.

---

## 7. Companion project — red-team harness (design summary)

Separate repo, runs out-of-band. Full spec is its own doc; the shape:

1. **Threat model first** — STRIDE per Via component; enumerate injection, poisoning, excessive-agency, exfiltration paths.
2. **LLM red-team suite** — `garak` / `PyRIT` / `promptfoo` red-team mode, plus a custom injection corpus aimed at Via's memory + tools. Each corpus item asserts a taint rule should have blocked it.
3. **Classic API testing** — OWASP ZAP, `nuclei`, `schemathesis` fuzzing against *your own* endpoints only.
4. **Findings → PulseWise** — emit results as metrics so security regressions sit next to your other analytics.

**The bridge between the two projects:** every landed exploit becomes a regression test in the harness *and* (usually) a new rule or tightened trust level in the middleware. Provenance/taint is the shared vocabulary.

Reference frameworks: OWASP Top 10 for LLM Applications, OWASP API Security Top 10, MITRE ATLAS.

---

## 8. Build phases

1. **Core, standalone** — provenance, redaction, policy, audit, pipeline + `demo.py` (4 scenarios: untrusted→privileged blocked; user PII→LLM redacted; clean allow; audit tamper detection) + unit tests.
2. **Harden the core** — grow rule catalog, add field-level encryption for `secret`-labelled memory (KMS-backed; local key for dev), add egress allowlist.
3. **Via adapters** — `asgi.py`, `langgraph.py`; wire taint rules into Via's spec.
4. **Harness + integration loop** — stand up the red-team harness, run against Via-lite, feed findings back.

---

## 9. Scope & safety rules (non-negotiable)

- **Test only systems you own.** Partner/third-party endpoints (e.g. Hopwise's travel providers) are off-limits.
- **Check the cloud provider's pen-test policy** before running scanners; prefer staging over production.
- Audit log stores **summaries and tallies, never raw PII or secret values**.
- Fail closed everywhere.

---

## 10. Open decisions for the builder

- **Encryption backend** for `secret` memory in phase 2: local Fernet for dev vs. cloud KMS abstraction from day one? (Recommend a `KeyProvider` interface with a `LocalKeyProvider` now, KMS later.)
- **Credit-card detector** should add a **Luhn check** to cut false positives before phase 2.
- **Provenance persistence** — how trust labels survive a round-trip through Via's memory store (serialization format). Depends on Via's memory schema; resolve when the adapter lands.
- **Redactor reversibility** — do any sinks need tokenization (reversible) vs. plain redaction (one-way)? Default one-way; revisit if a downstream tool needs the original.
