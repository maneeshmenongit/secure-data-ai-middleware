# DataSec: Provenance-Gated Egress Redaction, Design

**Date:** 2026-11-15 · **Status:** awaiting user review · **Parents:** DESIGN.md §10.12; design-thread input `docs/superpowers/specs/Claude outputs/2026-10-25-design-thread-input-egress-fp.md`; brainstorm `docs/superpowers/brainstorms/2026-10-28-datasec-provenance-gated-egress.md` · **Answers:** `reports/egress-false-positives/2026-10-24-egress-false-positives-report.md` · **Branch:** `feat/provenance-gated-egress` · **Via contract:** `docs_to_claude/handoff_from_via/2026-10-28-NOTE_what_via_needs_to_hear.md`, items 1, 2, 3, 4 and 6

## 1. Goal

DataSec must stop rewriting text a host wrote itself.
- **Low-trust text** (provenance USER, EXTERNAL or UNTRUSTED) is redacted on egress, as today.
- **High-trust text** (INTERNAL or TRUSTED) is **scanned and observed in the audit, never rewritten**. So a host that mislabels user data as high-trust shows up in `datasec.report` on its first run.

**Why.** Every false positive found in the Via trials (loopback addresses, `mem_<uuid>` ids, `repr(float)` costs) came from Via's own INTERNAL text. The 2026-10-24 fix carved regex exemptions to work around them, and each exemption opened a true-positive gap (R2g.5–R2g.10). Provenance is the layer that knows whether a string can be reached by an attacker, so the decision belongs there.

**The constraint.** Hosts send one prompt built from several sources. Via's `guard_prompt` (`via/via/security/datasec_bridge.py:646-660`, `main` @ `7c03c89`) combines every message's provenance and guards the whole prompt as one payload, so the combined trust is at best USER. **A gate on the combined trust alone would skip nothing**, so the payload must carry **a provenance for each part**. One payload still gives one policy decision and one audit entry.

**Success means:**
1. The Via trial text passes unchanged even when it shares a prompt with the principal's brief.
2. The brief's email is still `[EMAIL]`.
3. Mislabelled high-trust PII is visible in the report.
4. Nothing that was redacted before leaks, unless a host explicitly marked it high-trust.

## 2. Decisions (user, 2026-10-28 → 2026-11-07)

| # | Decision |
|---|---|
| D1 | **Scope:** the core (per-part provenance, a trust gate on redaction, audit observation), narrowing the exemptions (as amended by A4), and location linking as a per-project opt-out. **Deferred:** the private-IP exemption on `llm` (design thread Q1) and host-declared structured fields (Q2). |
| D2 | **Location linking stays on by default**, and a project may opt out deliberately. This differs from the design thread's Q7, which asked for off by default. The reason: the trust gate removes the main source of over-redaction (a host's own data-heavy text). What is still scanned is user, external and untrusted text, which is exactly where addresses appear. |
| A1 | **Parts are `Tainted` objects nested inside the payload.** The Action's provenance is the **default for untagged content**, not a ceiling. A nested part gets `min(inner, outer)`. The output is always unwrapped. Rejected: a path-keyed provenance map on the Action; `check_parts()`; one `guard` per message. |
| A2 | **High-trust parts get a regex-only scan:** no NER, no charge to the NER budget, observed and never rewritten. |
| A3 | **Observations go in `extra` as strings:** `observed` and `observed_sources`. `tally` keeps meaning "what was rewritten". |
| A4 | **The id and decimal masks stay for parts at EXTERNAL and above, and are switched off for UNTRUSTED parts. Loopback stays exempt.** This departs from D1: the measurement (§9) showed loopback saves 0 hits in low-trust rows, and 127.0.0.1 identifies no one. |
| A5 | **The opt-out is a constructor flag, `location_linking=True`,** on `Redactor` and `PresidioRedactor`. |
| A6 | **A part counts as a container in `_over_cap`**, so the existing size and depth caps bound the new walk. |
| A7 | **The red team gains 20 attacks, R5.17 among them** (§7). |

## 3. Data flow

### 3.1 Payload shape

A payload may contain `Tainted(value, provenance)` nodes anywhere that a value could go: list or tuple items, dict values, or at the top level. Parts may nest. **A part can't be a dict key**; one used as a key is denied (§6).

```python
# Via, after the handoff (sketch):
payload = [Tainted(m.content, _msg_prov(st, m)) for m in msgs]
action  = Action("llm", f"llm:{purpose}", prov)        # prov: Via's combined provenance, as today
out     = check(pipeline, action, payload, Mode.ENFORCE)   # a list of plain strings
```

### 3.2 Trust gating inside the walk

`Redactor._walk` (`redaction.py:244`) gains `trust: TrustLevel` and `source: str`, passed down the walk the same way `field` and `ner` are.

- **At a `Tainted` node:** `trust = min(trust, node.provenance.trust)` and `source = node.provenance.source`. Then the walk goes into `node.value` and **returns the walked value without the wrapper**.
- **At a string**, and at an integer in scope when `scan_integers` is on:

| Effective trust | id/decimal masks | NER | Result |
|---|---|---|---|
| UNTRUSTED | **off** | on egress sinks | rewritten; counted in `found` |
| EXTERNAL, USER | on (as today) | on egress sinks | rewritten; counted in `found` |
| INTERNAL, TRUSTED | on | **never** | **unchanged**; counted in `observed`, and `source` is added to `observed_sources` |

- **Dict keys** inside a part follow the trust of that part.
- The masks are chosen per string from the effective trust. `self.detectors` is never mutated.

### 3.3 The pipeline (`SecurityPipeline._decide`)

1. **`_over_cap`** treats a `Tainted` as a container: one depth level, plus a fixed overhead per node as for lists. Along the way it collects every part's provenance. A part whose `provenance` isn't a `Provenance` means **deny "missing provenance"**.
2. **The decision provenance** is `combine(action, every part)`: the weakest trust and the union of all labels. The policy engine evaluates the Action carrying this provenance. `_decide` returns that Action, so `guard()`'s sealing check and the audit's `trust`/`labels` both see it. A `secret` label on any part is therefore sticky.
3. **The scan:**
   - **Part-aware redactor:** `scan_parts(payload, trust=action.provenance.trust, source=action.provenance.source, …)` → `PartScan(found, observed, observed_sources)`.
   - **A redactor that isn't part-aware:** if the payload contains parts, **deny "unsupported payload"**; otherwise the old `scan()`.
4. **Labels.** Only `found` (rewrite-eligible findings) adds the `pii` label, on **every** sink. "pii" now means *PII in low-trust content*.
5. **The decision:**
   - REDACT → `redact(payload, trust=…)`.
   - ALLOW → `unwrap(payload)`. This is new: today ALLOW returns the payload as it was given.
   - DENY → `None`.
6. **The audit:** `extra["observed"]` and `extra["observed_sources"]` when `observed` is non-empty (§5).

### 3.4 Payloads with no parts

The Action's own trust gates the whole payload:
- **INTERNAL or TRUSTED Actions:** the payload is observed, not rewritten.
- **UNTRUSTED Actions:** the id and decimal masks are off.
- **USER and EXTERNAL Actions:** exactly as today.

**This changes behaviour for every host,** even before it tags parts. For example, a Via prompt made only of INTERNAL messages stops being rewritten. The handoff says so under item 3.

## 4. API

### 4.1 `datasec.provenance`

- **New:** `unwrap(payload) -> Any` returns the payload with every `Tainted` replaced by its (recursively unwrapped) value. Lists, tuples and dicts are rebuilt; other values are returned as they are. A payload with no parts comes back equal to the original. An object that merely looks like a part (`.value`/`.provenance` but not a `Tainted`) isn't unwrapped.
  - It stays recursive, which is safe only because every caller runs it after the payload has passed `_over_cap`'s depth cap (§3.3 step 1). Any new caller has to keep it that way.
- `Tainted`, `Provenance`, `TrustLevel` and `combine` are unchanged.

### 4.2 `datasec.redaction.Redactor`

```python
Redactor(detectors=DEFAULT_DETECTORS, *, scan_integers=False, integer_fields=None,
         location_linking=True)
part_aware: ClassVar[bool] = True

redact(payload, *, scan_integers=None, trust=TrustLevel.USER) -> RedactionResult
scan(payload, *, scan_integers=None) -> dict[str, int]                   # unchanged
scan_parts(payload, *, trust, source, scan_integers=None) -> PartScan     # new
```

- **`redact()`:**
  - `trust` is the trust of untagged content. With the **USER default, the output matches today's** (§8 checks this against the existing corpus).
  - The pipeline's `_safe()` (audit metadata) keeps calling it without `trust=`, so audit metadata is redacted whatever the Action's trust.
- **`scan()`** keeps its signature and its return type. It walks with `trust=USER`, so a payload with no parts counts the same as today. It returns only `found`. The pipeline never calls it on a payload that contains parts (§3.3 step 3).
- **`RedactionResult`** gains `observed: dict[str, int] = field(default_factory=dict)`.
- **`PartScan`** is a frozen dataclass: `found: dict[str, int]`, `observed: dict[str, int]`, `observed_sources: tuple[str, ...]` (sorted, deduplicated).
- **`location_linking`:** the four `link_locations(...)` call sites (`redaction.py:300`, `presidio.py:123/154/163`) become `self._link(text, found)`, which returns `text` unchanged when the flag is off. Location fragments are still redacted each on its own. Linking behaves the same in redaction and observation, so ADDRESS counts mean the same in `tally` and in `extra["observed"]`.

### 4.3 `datasec.presidio.PresidioRedactor`

- It takes `location_linking` and passes it through.
- `scan_parts` and `redact` default `ner=True`, as `scan` does today.
- NER and the budget charge in `_redact_text` are reached only for low-trust text, because high-trust strings are counted in the walk and never passed through `_redact_text`'s NER branch.

### 4.4 `datasec.pipeline.SecurityPipeline`

- `guard()` and `GuardResult` are unchanged.
- **New:** `part_labels(payload) -> frozenset[str] | None`. It returns the union of labels over every part, using the same capped walk as `_over_cap`. It returns `None` when the payload is over the cap or too deep.

### 4.5 `datasec.adapters.gate.check`

- **SHADOW:**
  - Returns `unwrap(payload)` instead of `payload`.
  - Its check that a secret write isn't shadowed also raises the same `ValueError` when `pipeline.part_labels(payload)` contains `secret`. A `None` (over the cap) goes on to `guard()`, which denies and audits it.
- **ENFORCE:** unchanged.

## 5. Audit and report

### 5.1 Entries

- **The schema doesn't change.**
- **When something is observed**, `extra` gains two strings:
  - `observed`: `"LABEL=N"` items joined with `,`, sorted by label, each label passed through `_safe()`. Example: `"EMAIL=2,PHONE=1"`.
  - `observed_sources`: the sorted sources joined with `+`, each passed through `_safe(…, ner=True)`. **At most 8**; beyond that, `+N more` is appended.
- **When nothing is observed, neither key is written**, so the entry hashes exactly as it would today.
- `trust` and `labels` record the decision provenance (§3.3 step 2). `source` stays the Action's source.
- `tally`, `effect`, `rule` and `extra["mode"]` keep their meaning. Via's `run_summary` (`datasec_bridge.py:773-779`) counts redactions from `tally` only, so its numbers stay correct.
- The checkpoint format doesn't change.

### 5.2 Compatibility

- **Old log, new code:** verifies, because hashing is untouched. A committed fixture tests this (§8).
- **New log, old code (`1a1eb54`):** readable and verifiable, because `extra` is already a `dict[str, str]` field. This is checked once by hand from a temporary worktree at `1a1eb54`, and the result goes in the handoff.

### 5.3 `python -m datasec.report`

- **`summarize()`** gains the key `high_trust_observed: Counter[(sink, observed_sources)]` and the label totals. Existing keys don't change.
- **New output section:** "high-trust findings (sink / sources): mislabelled-PII candidates", showing count, sink, sources and label totals. Everything goes through `_clean()`.
- Old logs print the section empty. Exit codes don't change.

## 6. Error handling

`guard()` never raises for a bad payload, and the exception contract is unchanged. Every new failure is a **DENY with a reason**, written as one audit entry, and `check()` turns it into `Blocked`.

| Input | Reason |
|---|---|
| a part whose `provenance` isn't a `Provenance` | missing provenance |
| a part whose value is an unsupported type | unsupported payload |
| a part used as a dict key | unsupported payload |
| something that looks like a part but isn't a `Tainted` | unsupported payload |
| parts sent to a redactor that isn't part-aware | unsupported payload |
| parts nested too deep, or too large | payload too deep / payload too large |
| any exception from `scan_parts` (a low-trust **or** a high-trust part) | scan failed |
| any exception from `redact` | redaction failed |

- **Observing doesn't get a softer failure path:** an exception in a high-trust scan still denies.
- **Sealing:** a `secret` part makes the decision provenance `secret`, so on `memory:write` the unwrapped output is sealed (§3.3 step 2).

## 7. Red team

The new outcome *observed* (allowed, and the audit entry has `extra["observed"]`) is added to `redteam/common.py`.

| ID | Attack | Expected |
|---|---|---|
| R1.10 | an INTERNAL-tagged part that carries user PII | observed |
| R1.11 | an untagged part next to an INTERNAL part, Action at USER | redacted |
| R1.12 | a `secret` part inside a payload that is otherwise INTERNAL, sent to `llm` | blocked |
| R1.13 | a TRUSTED part nested inside an UNTRUSTED part | redacted |
| R1.14 | INTERNAL instructions plus an UNTRUSTED web part, sent to `tool:privileged` | blocked |
| R1g.2 | a host mislabels user PII as INTERNAL/TRUSTED, so it leaves unredacted (observed, not prevented) | known gap |
| R2.29–R2.34 | the R2g.5–R2g.10 forms (PII disguised as a UUID or a decimal), each in an UNTRUSTED part | redacted |
| R4.14 | a part source with an email, a newline and ANSI codes, in `observed_sources` and in the report | defended (redacted and escaped) |
| R5.15 | a part whose provenance isn't a `Provenance` | blocked |
| R5.16 | a part whose value is an unsupported type | blocked |
| R5.17 | a `secret` part in a SHADOW `memory:write` | refused (`ValueError`) |
| R6.15 | 1 MB across ~100k mixed-trust parts | bounded (< 1 s) |
| R6.16 | parts nested 201 deep | blocked |
| R6.17 | a 10 MB string inside one part, under the default cap | blocked |
| R6.18 (Presidio) | a 60k-character INTERNAL part plus a short USER part with a name | not denied; the name is `[PERSON]`; < 1 s |

- **Existing entries:**
  - R1g.1 gets a note that a hand-built TRUSTED part now also skips redaction.
  - R2g.5–R2g.10 are reworded "in USER/EXTERNAL text".
- **Expected totals:** 121 attacks, 106 defended, 15 known gaps, 0 unexpected, with Presidio.

## 8. Testing

Every test is written first and seen to fail.

- **`test_provenance.py`:** `unwrap` on nested lists, tuples and dicts and on parts inside parts; equality for payloads with no parts; a lookalike isn't unwrapped.
- **`test_redaction.py`**
  - The §3.2 table, one case per trust level.
  - Masks are off only for UNTRUSTED.
  - `min(inner, outer)` for nesting.
  - Untagged content takes `trust=`.
  - **`redact()` without `trust=` gives the same output as today** across the existing redaction corpus.
  - `location_linking=False` on both paths.
  - The cap on `observed_sources`.
- **`test_presidio.py`:** high-trust text never reaches `_analyzer.analyze` (spy) and never charges the budget; a USER part next to a 60k-character INTERNAL part still gets NER.
- **`test_pipeline.py`**
  - One decision and one audit entry per payload.
  - The decision provenance is `combine` of the action and every part.
  - ALLOW and REDACT both return unwrapped values.
  - Only `found` adds `pii`; observed-only gives ALLOW plus `extra["observed"]`.
  - A `secret` part is sealed on `memory:write`.
  - Every row of §6.
  - §3.4 (payloads with no parts, at each Action trust).
- **`test_gate.py`:** SHADOW returns `unwrap(payload)`; a `secret` part in SHADOW raises `ValueError`; `part_labels` returns `None` past the cap.
- **`test_audit.py`:** `tests/fixtures/audit_1a1eb54.jsonl` holds entries written by `1a1eb54`, mixing ones with no `extra`, `mode: shadow`, `encryption` and `destination`. It verifies, takes appended entries with `observed`, and verifies again. Entries where nothing was observed hash as before.
- **`test_report.py`:** the high-trust section; a hostile source is escaped; an old log prints the section empty.
- **Manual, once:** the new log verifies under `1a1eb54` from a temporary worktree. The result goes in the handoff.
- **Baseline:** 491 passed + 14 xfailed today. The final count is reported as measured.

## 9. Evidence: the A4 measurement (2026-10-29, read-only)

- **What was scanned:** about 25.8k memory rows in `via-data/projects/datasec-3a-trial{,2}/trial.db` and `via-data/CURRENT.db`.
- **How:** `Redactor()` at master, with the trust from each row's provenance through Via's `TRUST_TABLE`. The script was throwaway and printed only shapes and email domains.
- **Low-trust rows (USER/EXTERNAL):**
  - the id mask saves about 25 hits (`mem_<uuid>` in `principal`/`tool` rows)
  - the decimal mask saves about 214 CREDIT_CARD hits (`repr(float)` costs in `tool` rows)
  - loopback saves 0
  - **There are no UNTRUSTED rows** in any store, so turning the masks off for UNTRUSTED costs 0 measured false positives.
- **INTERNAL rows:** about 3,300 current rewrites stop under the gate. Most are false positives:
  - `@app.get`/`@click.option` decorators read as EMAIL (about 2,000)
  - git author-line epochs read as PHONE (about 740)
  - hex runs read as SSN/PHONE (about 180)
- **One real class: 125 hits of `<user>@<host>.local`.** Under the gate these go out unredacted and are observed.
- **Expect noise:** decorator false positives will dominate the report's high-trust section until the EMAIL detector is tightened (out of scope, §11).
- **Caveats:**
  - These are rows, not assembled prompts.
  - `tool`+`llm_call` rows (INTERNAL in Via's `OWN_RECORDS`) couldn't be told apart, because the kind isn't stored in `content`.

## 10. Docs and handoff

- **`DESIGN.md` §10.12** moves from "in design" to decided, with D1–D2 and A1–A7. It records that D1's loopback narrowing was dropped (§9) and the reason D2 differs from Q7. The one-pager's limits and numbers are updated.
- **The Via handoff,** `docs/handoffs/YYYY-MM-DD-PROMPT_via_datasec_repin_provenance_gate.md`, is pinned to a full 40-character SHA. It contains:
  - **Item 1, the API:**
    - `redact` gains `trust=`; `scan_parts`, `PartScan` and `unwrap` are new; `location_linking` is a new constructor flag.
    - The bridge change: `guard_prompt` wraps each `m.content` in `Tainted(m.content, _msg_prov(st, m))` (`datasec_bridge.py:654-658`).
    - The new profile key `location_linking` (true by default) goes in `PROFILE_KEYS` (`:60`) and is passed through where the redactor is built (`:353-360`).
  - **Item 2, the exception contract:** unchanged, except that SHADOW also raises `ValueError` for a `secret` part.
  - **Item 3, what egress redacts:**
    - INTERNAL/TRUSTED text is no longer rewritten, **even before Via tags parts** (§3.4).
    - UNTRUSTED loses the id/decimal masks.
    - The §9 numbers, including the 125 `<user>@<host>` strings now going out observed.
  - **Item 4, the audit format:**
    - Old logs verify.
    - Rolling back is safe (with the manual-check result).
    - The two new optional `extra` keys.
    - `run_summary` may add `observed.<label>`.
  - **Item 6, speed:** the measured R6.15 and R6.18 timings.
  - **Known limits:**
    - R1g.1/R1g.2: Via is the only one assigning trust, and its labels are trusted.
    - R2g.5–R2g.10 in USER/EXTERNAL text.
    - Decorator noise in the report.
  - **Steps for Via:** install the pin, rerun the trial test, add a `guard_prompt` test with mixed parts, and merge with a merge commit.

## 11. Out of scope

- The private-IP exemption on `llm` (Q1)
- Host-declared structured fields (Q2)
- An epoch keyword rule (Q3: no)
- A proximity heuristic for names (Q4: no)
- Tightening the EMAIL detector against decorators
- Before/after samples of rewritten text in the audit (counts only; the log never holds payload text)
- 3B (follows this cycle and reuses its per-part mechanism)
- Any edit to Via
