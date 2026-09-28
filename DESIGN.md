# DataSec Middleware — Design Spec

**Status:** Phase 1 built & reviewed; Phase 2 specified (see companion `datasec-phase2-design.md`) · **Author:** Maneesh (Wise World LLC) · **Date:** 2026-09-27 (rev. after Phase 1 report)
**Intended builder:** Claude Code (this doc is the spec; it writes the code)

> **Revision note (post-Phase 1):** §5, §8 and §10 updated to record what Phase 1 actually built, the deviations the build made, and the three design-thread decisions (audit-head storage, scoped integer scanning, EXTERNAL-trust policy). A separate black-box attack plan (`datasec-webapp-attack-plan.md`) covers the test web app, and Phase 2 has its own spec.

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

**How the `pii` label gets applied (Phase 1 deviation, kept).** The original design assumed something upstream labels a value `pii`. Nothing did. The Phase 1 pipeline now scans the payload itself at the sink and adds the `pii` label before the rules run, so PII is caught regardless of origin — including PII in *LLM output* on its way back. This is a strict improvement and is the intended behavior going forward.

**Open policy question — EXTERNAL trust to privileged sinks (decision, see §10.5).** `no_untrusted_to_privileged` fires on `trust == UNTRUSTED` (level 0). That leaves `EXTERNAL` (level 1: third-party API and tool responses) *allowed* to reach `tool:privileged`, `third_party`, and `memory:write`. For an agent, tool/third-party output is a primary indirect-prompt-injection vector. Resolution in §10.5: treat EXTERNAL as privileged-blocked by default.

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

1. **✅ Core, standalone (done)** — provenance, redaction, policy, audit, pipeline + `demo.py` + unit tests + an in-repo, in-process red-team seed suite. Phase 1 report: 50 attacks (44 defended, 6 documented known gaps, 0 unexpected); whole-branch review found 1 critical + 7 important, all fixed with regression tests. `demo.main()` returns a dict rather than the `list[GuardResult]` this doc first specified (scenario 4 yields a bool) — accepted.
2. **⏳ Test web app + minimal ASGI adapter (in progress)** — a deliberately app for black-box testing of *both* surfaces (data-security controls and classic web vulns). This pulls a thin slice of the Phase 3 ASGI adapter forward as a **test rig**; it is not the Via integration and its shortcuts must not leak into the real adapter. Attack plan: `datasec-webapp-attack-plan.md`.
3. **✅ Harden the core (Phase 2, done — Presidio deferred)** — `KeyProvider` + field-level encryption for `secret` memory, egress allowlist, Presidio behind the `Redactor` interface, payload size cap, case-insensitive labels, scoped integer scanning, EXTERNAL-trust policy, audit-head checkpointing. Full spec: `datasec-phase2-design.md`.
4. **Via adapters (Phase 3)** — real `asgi.py`, `langgraph.py`; wire taint rules into Via's spec.
5. **Harness + integration loop** — stand up the out-of-band red-team harness (§7 — distinct from the in-process seed suite), run against Via-lite, feed findings back.

---

## 9. Scope & safety rules (non-negotiable)

- **Test only systems you own.** Partner/third-party endpoints (e.g. Hopwise's travel providers) are off-limits.
- **Check the cloud provider's pen-test policy** before running scanners; prefer staging over production.
- Audit log stores **summaries and tallies, never raw PII or secret values**.
- Fail closed everywhere.

---

## 10. Decisions

Resolved items are marked **[resolved]**; the rest stay open with an owner.

- **10.1 Encryption backend — [implemented, Phase 2].** `KeyProvider` interface with a `LocalKeyProvider` (Fernet) for dev now; a KMS-backed provider later behind the same interface. Detail in the Phase 2 spec.
- **10.2 Credit-card Luhn check — [resolved, shipped in Phase 1].** Plus exact card-layout detectors after the whole-branch review found a card+CVV run reaching the LLM in plaintext.
- **10.3 Redactor reversibility — [resolved].** One-way redaction only. Revisit only if a downstream tool provably needs the original value; a reversible tokenizing provider would be a separate `Redactor` implementation.
- **10.4 Audit-head storage — [implemented, Phase 2].** The hash chain alone proves entries were *edited*, not that the whole log was *replaced or truncated*. Store `AuditLog.head` out-of-band. Proportionate choice for a solo sandbox: a periodic **signed checkpoint** (head + timestamp, signed with a `KeyProvider` key) written to a separate location, plus the current head in a second store (DB row or restricted file). No external log service yet. Specified in Phase 2. Implemented as `AuditLog(path, signer=..., checkpoint_path=...)`; without a checkpoint or pinned head, tail truncation and full-chain rewrite remain known gaps R4g.1/R4g.2.
- **10.5 EXTERNAL-trust to privileged sinks — [implemented, Phase 2].** Treat `EXTERNAL` (level 1) as privileged-blocked, same as `UNTRUSTED`: change `no_untrusted_to_privileged` to fire on `trust <= EXTERNAL` for `PRIVILEGED` sinks (rename to `no_low_trust_to_privileged`). Rationale: tool/third-party output is a primary indirect-injection vector for an agent. Add a red-team case asserting EXTERNAL→privileged is now blocked. If a specific trusted third party must reach a privileged sink, allowlist that `source`, don't lower the bar globally.
- **10.6 Integer scanning — [implemented, Phase 2].** Phase 1 scans JSON integers for SSN/card patterns and redacts them. Kept, but **scoped**: do not blanket-redact integers, because it corrupts legitimate numeric IDs (order numbers, primary keys, epoch timestamps). Default: scan **strings only**. Integer scanning becomes **opt-in per sink or per field** (e.g. a `scan_integers` flag on the `Action`, or a field allowlist). Rationale: for data-engineering payloads the false-positive/corruption cost of blanket integer redaction outweighs the rare integer-encoded-PII case. Specified in Phase 2.
- **10.7 Provenance persistence — [open, owner: Phase 3].** How trust labels survive a round-trip through Via's memory store (serialization format). Depends on Via's memory schema; resolve when the adapter lands.
- **10.8 Presidio — [deferred].** Its own cycle; its email/SSN recognizers are regex-based and would not close R2g.1/R2g.2, so it is scoped around NER (names, locations).
