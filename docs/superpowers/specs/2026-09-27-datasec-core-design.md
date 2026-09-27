# DataSec Core (Phase 1) + Red-Team Seed Suite — Design

**Date:** 2026-09-27 · **Status:** awaiting review · **Parent doc:** [DESIGN.md](../../../DESIGN.md)

## 1. Scope

This cycle builds **Phase 1** of DESIGN.md §8, plus an **in-repo adversarial suite** that attacks it.

In scope:
- `src/datasec/`: `provenance`, `redaction`, `policy`, `audit`, `pipeline`, `errors`
- `demo.py` (4 scenarios from DESIGN.md §8)
- Unit tests for every module
- `redteam/`: attack corpus + runner + scorecard, executed by pytest

Out of scope (own cycles later): Phase 2 hardening (encryption, KeyProvider, egress allowlist), Phase 3 adapters (`adapters/` package is not created), the full out-of-band harness from DESIGN.md §7 (garak/PyRIT/ZAP/nuclei against Via).

Safety: the red-team suite attacks only this repo's own code, in-process. No network activity.

## 2. Tooling

- `git` repo, `pyproject.toml`, `requires-python >= 3.11`, src layout, package name `datasec`.
- `uv` for env management; `pytest` is the only dependency and is dev-only. Runtime is stdlib-only.
- TDD for every module.

## 3. Module contracts

Implements DESIGN.md §4 signatures exactly; additions below are marked **(new)**.

### 3.1 `provenance.py`
- `TrustLevel(IntEnum)`: `UNTRUSTED=0, EXTERNAL=1, USER=2, INTERNAL=3, TRUSTED=4`.
- `Provenance(trust, source, labels: frozenset[str])`, frozen. `.with_labels(*l) -> Provenance`, `.has(l) -> bool`.
- `Tainted[T](value, provenance)`, frozen, generic. `.map(fn) -> Tainted` (trust and labels unchanged).
- `combine(*inputs, source="derived", value=None) -> Tainted`: trust = min, labels = union. Raises `ValueError` on zero inputs.
- Boundary constructors: `untrusted(value, source)`, `from_user(value, source)`, `internal(value, source)`; each accepts optional `labels`.

### 3.2 `redaction.py`
- Detectors (fixed order): `EMAIL`, `SSN`, `CREDIT_CARD`, `PHONE`, `IPV4`. SSN and CREDIT_CARD run before PHONE so they claim digit runs first.
- `CREDIT_CARD` matches 13–19 digits with optional space/dash separators **and must pass a Luhn check**.
- **(new) Normalization:** before scanning, each string is NFKC-normalized and zero-width characters (U+200B–U+200D, U+2060, U+FEFF) are stripped. `redact` returns the redacted *normalized* text.
- `Redactor.scan(payload) -> dict[str, int]`: empty dict when nothing is found.
- `Redactor.redact(payload) -> RedactionResult(payload, found)`: same shape as the input, with each span replaced by `[LABEL]`.
- **(new) Payload walking:** a payload is a `str`, or a `dict` / `list` / `tuple` nested to any depth. String leaves **and dict keys** are scanned and redacted. `int`, `float`, `bool` and `None` leaves pass through unchanged. Any other leaf type (e.g. `bytes`) raises `UnsupportedPayload`. If redacting keys makes two keys collide, `redact` raises `RedactionError`.
- Regexes must be linear-time (no nested quantifiers) — see redteam R6.

### 3.3 `policy.py`
- Sink constants: `KNOWN_SINKS = {"llm","tool:privileged","tool:readonly","memory:write","third_party","http:response"}`, `EGRESS = {"llm","third_party","http:response"}`, `PRIVILEGED = {"tool:privileged","third_party","memory:write"}`. Sinks match exactly and case-sensitively.
- `Action(sink, name, provenance)` frozen. `Effect(Enum)`: `ALLOW, REDACT, DENY`. `Decision(effect, reason, rule: str | None)`.
- `Rule(name, check)`; `check(action) -> Decision | None`.
- `PolicyEngine(rules=())`, `.evaluate(action) -> Decision`: runs every rule. Resolution is DENY > REDACT > ALLOW; within an effect, the first rule in list order wins. No objection → `Decision(ALLOW, "no rule objected", None)`. A rule that raises → `Decision(DENY, "rule <name> raised <ExcType>", name)`; only the exception type is recorded.
- `default_rules()` returns the three catalog rules (DESIGN.md §5):
  - `no_untrusted_to_privileged`: trust == UNTRUSTED and sink in PRIVILEGED → DENY
  - `never_leak_secrets`: has label `secret` and sink in EGRESS → DENY
  - `redact_pii_on_egress`: has label `pii` and sink in EGRESS → REDACT

### 3.4 `audit.py`
- `AuditEntry` frozen: `ts` (ISO-8601 UTC), `sink`, `name`, `effect`, `reason`, `rule`, `trust` (name), `source`, `labels` (sorted list), `tally` (dict), `prev_hash`, `hash`.
- `hash = sha256(prev_hash + canonical_json(body))`; canonical = `json.dumps(sort_keys=True, separators=(",",":"))`. Genesis `prev_hash` = 64 zeros.
- `AuditLog(path=None)`: in memory; if `path` is given, each entry is also appended as one JSONL line and flushed.
- `.append(...) -> AuditEntry`, iterable, `len()`, `.head -> str` **(new)** = hash of the last entry (genesis if empty).
- `.verify(expected_head=None) -> bool` **(new param)**: re-computes the chain. Passing `expected_head` (stored out-of-band) also catches tail truncation, which a bare chain cannot detect.
- `AuditLog.load(path) -> AuditLog`: reads a JSONL file for verification.
- Entries never contain payload content — only the tally.

### 3.5 `pipeline.py`
- `SecurityPipeline(engine=None, redactor=None, audit=None)`. Defaults: `PolicyEngine(default_rules())`, `Redactor()`, in-memory `AuditLog()`.
- `GuardResult(allowed, payload, decision)`. `allowed` is True for ALLOW and REDACT. `payload` is `None` when denied.
- `guard(action, payload) -> GuardResult`:

```
1. sink check   sink not in KNOWN_SINKS              → DENY("unknown sink")
2. scan         tally = redactor.scan(payload)
                UnsupportedPayload / RecursionError   → DENY("unsupported payload")
                tally non-empty → action = replace(action, provenance=provenance.with_labels("pii"))
3. evaluate     decision = engine.evaluate(action)
4. apply        DENY   → payload None
                REDACT → redactor.redact(payload).payload; any exception → DENY("redaction failed")
                ALLOW  → payload unchanged
5. audit        audit.append(...) — every path, including denials from steps 1–2
                failure → raise DataSecError (never return an unaudited result)
6. return       GuardResult
```

### 3.6 `errors.py`
`DataSecError` (base), `UnsupportedPayload`, `RedactionError`.

## 4. Demo

`demo.py` defines `main() -> list[GuardResult]` and prints one line per scenario:
1. Untrusted web text → `tool:privileged` → DENY
2. User message with an email → `llm` → REDACT, `[EMAIL]` in the output
3. Clean internal text → `llm` → ALLOW
4. Audit tamper: edit an entry → `verify()` is False

## 5. Red-team seed suite (`redteam/`)

Purpose: to attack the core the way the future harness (DESIGN.md §7) will attack Via, so every control has an adversarial test from day one.

- `redteam/corpus.py`: a list of `Attack(id, category, owasp, description, run: Callable[[], Outcome], expect)`. `expect` is one of `blocked`, `redacted`, `detected`, `bounded`, `known_gap`.
- `redteam/runner.py`: `run_all() -> Scorecard` plus `python -m redteam.runner`, which prints a table and writes `redteam/scorecard.json` (the future PulseWise metric feed).
- `tests/test_redteam.py`: parametrized over the corpus. `known_gap` items are `xfail(strict=True)`, so a later fix forces the item to be re-labelled.

Attack categories (at least these items):

| ID | Category | OWASP LLM | Attacks | Expect |
|---|---|---|---|---|
| R1 | Taint laundering | LLM01, LLM06 | combine untrusted+trusted → privileged; `.map` chain on untrusted → privileged; untrusted into `memory:write` | blocked |
| R1g | Taint laundering | LLM01 | caller hand-constructs `Provenance(TRUSTED, ...)` for untrusted data | known_gap (Python can't prevent it; mitigated by review/adapters) |
| R2 | PII evasion | LLM02 | SSN with spaces/dashes, card with separators, fullwidth digits, zero-width chars inside an email, PII in dict keys, PII split across nested list items | redacted |
| R2g | PII evasion | LLM02 | `john at example dot com`, spelled-out numbers | known_gap (regex limit; Presidio in Phase 2+) |
| R3 | Secret exfiltration | LLM02 | `secret` to each egress sink; secret combined with clean data; secret + pii (DENY beats REDACT) | blocked |
| R4 | Audit tampering | — | edit a field, delete a middle entry, reorder, recompute a single hash, truncate the tail with `expected_head` | detected |
| R4g | Audit tampering | — | truncate the tail without `expected_head` | known_gap |
| R5 | Fail-closed probes | LLM06 | sink `"LLM"` / `" llm"` / unknown; `bytes` payload; rule that raises; 10k-deep nesting | blocked |
| R6 | Resource abuse | LLM10 | 1 MB adversarial strings against each detector finish in < 1 s | bounded |

## 6. Testing

- Unit tests per module, covering every branch in §3.5.
- Invariant test: raw PII strings never appear in any `AuditEntry` or in the JSONL file.
- `tests/test_demo.py` runs `demo.main()` and asserts the four outcomes.
- `uv run pytest` must pass; `python -m redteam.runner` must report 0 unexpected results.

## 7. Resolved from DESIGN.md §10

- Luhn check: done now.
- Redactor reversibility: one-way only.
- Encryption backend and provenance persistence: deferred to Phase 2 / 3.
