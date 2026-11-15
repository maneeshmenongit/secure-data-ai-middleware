# [2026-10-28] Provenance-gated egress redaction: paused brainstorm

**Status:** DESIGN APPROVED (2026-11-15). All five sections were approved in chat. The spec is `docs/superpowers/specs/2026-11-15-datasec-provenance-gated-egress-design.md` and is awaiting the user's review. Then come writing-plans and Native execution. Corrections made during the sections, all reflected in the spec:
- Payloads with no parts are gated by the Action's own trust (spec §3.4).
- SHADOW returns `unwrap(payload)`.
- A `secret` part is caught by `part_labels`.
- R5.17 was added, bringing the total to 121 attacks. There is no spec, plan or code yet.
**Path:** architectural. It changes what `guard()` does on egress for every host, and it adds per-part provenance to the payload. So the route is spec → plan → Native execution → whole-branch review → a re-pin handoff for Via.
**Branch:** `feat/provenance-gated-egress`. It has no commits of its own; it was reset to `master` when work paused.
**Resume:** invoke `superpowers:brainstorming` and say "resuming the paused provenance-gated egress brainstorm at step 4". Re-read the inputs below, then propose approaches for **A1**. Do **not** re-ask D1 or D2.
**Comes before 3B.** 3B's per-field labels should reuse this cycle's per-part mechanism. See `2026-10-16-datasec-langgraph-adapter.md`.

## Via state (checked read-only, 2026-10-28)
- **Merged on Via's `main`:**
  - `feat/datasec-repin` (`0d0e30f`), which pins `1a1eb54`
  - `1a8d633`, which stops Via reading `.git/`; that removes the 40-hex git-hash hits
  - `feat/datasec-default-on` (`7c03c89`, the principal, 2026-10-28)
- **DataSec is now on by default in Via.** So every Via prompt goes through egress redaction, and this cycle's change reaches all of Via's traffic once it re-pins.
- The A1 lines in Via's bridge should be re-checked on `main` before they are cited in the spec.

## Inputs (read these first)
- **The design thread's input:** `docs/superpowers/specs/Claude outputs/2026-10-25-design-thread-input-egress-fp.md`. The user left it untracked at that path.
  - **The reframe:** these false positives came from scanning trusted, system-written text. Redact on egress only when `trust <= USER`, and skip INTERNAL and TRUSTED. On top of that, make rewrites of high-trust text observable.
  - Its answers to the four questions:
    - **Q1:** exempt private IPs on `llm`. *(Deferred by the user to a later cycle.)*
    - **Q2:** host-declared fields. *(Deferred.)*
    - **Q3:** no keyword rule for epoch timestamps. Accept them being redacted short-term.
    - **Q4:** require Presidio where names matter. No proximity heuristic.
- **The design thread's 3B input:** `docs_to_claude/design/phase3/2026-10-17-design-thread-input-3B.md`. Its Q7 asks for location linking to be per-project opt-in; see D2.
- **Via's contract note:** `docs_to_claude/handoff_from_via/2026-10-28-NOTE_what_via_needs_to_hear.md`. It is summarised in the `datasec-new-feature` skill §5. **This cycle triggers items 1 (the API), 3 (egress redaction), 4 (the audit format: an old log must still verify) and 6 (speed).** So it ends with a re-pin handoff that covers all four.
- **The report this answers:** `reports/egress-false-positives/2026-10-24-egress-false-positives-report.md`.

## Understanding (written back to the user on 2026-10-25; not corrected)
- **The aim.** DataSec must stop rewriting text a host wrote itself. Text whose provenance is USER, EXTERNAL or UNTRUSTED is redacted as today. Text that is INTERNAL or TRUSTED is not rewritten.
- **The constraint I found.** Hosts send one prompt built from several sources. Via's `guard_prompt` (via-skelton `feat/datasec-repin`, `via/via/security/datasec_bridge.py:591-615`) combines every message's provenance (`:599`) and guards the **whole prompt as one payload**. Via's instructions and the principal's brief end up in the same payload, which is then at best USER. **A gate on the combined trust alone would skip nothing**, so the gate needs **provenance for each part of a payload**.
  - One payload must still give one policy decision and one audit entry.
  - The weakest trust and the sticky labels still decide sinks and secrets, so a `secret` label still denies egress whatever the trust.
- **Observability.** High-trust parts are still **scanned**, and what is found is recorded in the audit (for example a separate tally or an `extra` marker), but **never rewritten**. A host that mislabels user data as INTERNAL then shows up in `datasec.report` on the first run.
- **Success means:**
  - The Via trial text passes unchanged even when it shares a prompt with the principal's brief.
  - The brief's email is still `[EMAIL]`.
  - Mislabelled high-trust PII is visible in the report.
  - Nothing that was redacted before leaks unless a host explicitly marked it high-trust.
- **The risk.** Known gap R1g.1 (hand-built TRUSTED) gains a new consequence: it would now skip redaction too. This needs red-team attacks and an honest gap entry. 3B's goal of making the adapter the only place trust is assigned is the long-term fix.

## Decisions made (user)
- **D1. Scope (2026-10-28).**
  - **In this cycle:**
    - the core: per-part provenance on egress, trust-gated redaction, and audit observation of high-trust findings
    - **narrowing the regex exemptions** from `1a1eb54` (UUID ids, decimal fractions, loopback), and with them gaps R2g.5–R2g.10, now that trusted text is gated
    - **making location linking per-project opt-in**
  - **Deferred to later:**
    - the private-IP exemption on `llm` (design thread Q1)
    - host-declared structured fields (Q2)
- **D2. Location-linking default: A, on by default (2026-10-28).** A project may opt out in its profile, but only deliberately. This keeps the user's 2026-10-02 all-or-nothing rule wherever nothing else was decided. The design thread's Q7 asked for the opposite default (off); **tell the design thread why**.
  - Reason: the trust gate removes the main source of over-redaction (a host's own data-heavy text, which is INTERNAL). What is still scanned is user, external and untrusted text, which is where addresses appear.
  - Rejected: B, off by default (the design thread's position). A user's "145 Main St, NJ 07922" would leave the ZIP and coordinates visible unless a project opted in.

- **A1. Per-part provenance: (a), nested `Tainted` in the payload (2026-10-29).**
  - The Action's provenance is the **default for untagged content**, not a ceiling. Tagged parts state their own trust.
  - The decision uses `combine(action, every part)`: one decision and one audit entry per payload, and `secret` stays sticky.
  - A nested part gets `min(inner, outer)`, so it can never raise its parent's trust.
  - The output is unwrapped to plain values. Via's change is about 3 lines at `datasec_bridge.py:646-660` (`main` `7c03c89`): wrap each `m.content` in `Tainted(m.content, _msg_prov(st, m))`.
  - Rejected: (b) a path-keyed provenance map on the Action (paths drift from the payload, and it adds an `Action` field); (c) `check_parts` (flat lists only, a second entry point).
  - **Trap:** `_over_cap` counts an unknown object as 8 bytes without walking it (`pipeline.py:53`). It must walk into `Tainted`, or a large string wrapped in a part bypasses the 1 MB cap. Today `Redactor._walk` raises `UnsupportedPayload` on a `Tainted` (`redaction.py:282`), so an old pin denies a new-style payload (fails closed).
- **A2. High-trust parts: regex-only scan, observed and never rewritten (option 1, 2026-10-29).**
  - INTERNAL and TRUSTED parts are scanned by regex only: no NER, and nothing charged to the NER budget.
  - Why: the Presidio budget (`presidio.py:85-87`, 20k characters per string, 50k in total) raises `RedactionError` → deny. A full scan could block a prompt just to observe it, or leave no NER budget for the user's text.
  - A high-trust finding never adds the `pii` label, so it never turns the decision into REDACT.
  - Accepted gap: a name in a mislabelled high-trust part is not observed (part of R1g.1).
  - Rejected: a full scan with NER (budget denials, as slow as today); skipping entirely (no observability).
- **A3. High-trust findings go in `extra`, as strings (option 1, 2026-10-29).**
  - `extra["observed"] = "EMAIL=2,PHONE=1"`: detector labels with counts, sorted so the text is always the same.
  - `extra["observed_sources"]`: the part sources that had findings, joined with `+` and passed through `_safe()`.
  - Both keys appear only when something was observed, so entries without findings hash as before and old logs verify.
  - **Rolling back is safe:** the old pin `1a1eb54` reads `extra` already, so it can read and verify a new log.
  - `tally` stays "what was rewritten" (low-trust findings only). Via's `run_summary` (`datasec_bridge.py:773-779`, `main` `7c03c89`) counts `redactions.<label>` from `tally` when `effect == "redact"`.
  - `datasec.report` gets a section "high-trust findings (sink / observed_sources)".
  - Rejected: a top-level `observed` field (the old pin's `AuditEntry(**json)` raises `TypeError` on an unknown key, so Via would refuse to start after a rollback); nested values in `extra` (breaks the `dict[str, str]` contract).
- **A4. Exemptions: keep the id and decimal masks for parts at EXTERNAL and above, switch them off for UNTRUSTED parts, and keep loopback (option 1, 2026-10-29).**
  - This closes R2g.5–R2g.10 for attacker-reachable text (UNTRUSTED). For USER and EXTERNAL text they stay open as narrower, documented gaps.
  - **Departs from D1:** the loopback exemption is *not* narrowed. It saves 0 hits in low-trust rows, and 127.0.0.1 identifies no one, so dropping it would buy nothing.
  - Observation scans of high-trust parts (A2) keep the masks.
  - **Measurement (2026-10-29, read-only):** about 25.8k memory rows in `via-data/projects/datasec-3a-trial{,2}/trial.db` and `via-data/CURRENT.db`, scanned with `Redactor()` at master, with trust from row provenance via Via's `TRUST_TABLE`. The script is throwaway; only shapes and domains were printed.
    - Low-trust rows (USER/EXTERNAL): the id mask saves about 25 hits (`mem_<uuid>` in `principal`/`tool` rows), the decimal mask about 214 CREDIT_CARD (`repr(float)` costs in `tool` rows), and loopback 0. There are **no UNTRUSTED rows** (`web`/`repo:host`) in any store.
    - INTERNAL rows: about 3,300 current rewrites stop under the gate. Most are false positives: `@app.get`/`@click.option` decorators read as EMAIL (about 2,000), git author-line epochs read as PHONE (about 740), hex runs read as SSN/PHONE (about 180).
    - **One real class: 125 hits of `<user>@maneesh-mac-mini.local`**, which under the gate go unredacted and are observed.
    - Expect the report's high-trust section to be dominated by decorator false positives until the EMAIL detector is tightened. That is a separate fix, not in this cycle.
    - Caveat: these are rows, not assembled prompts, and `tool`+`llm_call` (INTERNAL in Via's `OWN_RECORDS`) could not be told apart, because the kind is not in `content`.
- **A5. Location opt-out: a constructor flag `location_linking=True` on `Redactor` and `PresidioRedactor` (option 1, 2026-10-29).**
  - It follows the `scan_integers`/`integer_fields` pattern. It isn't named `link_locations`, because that is the module function.
  - All four call sites (`redaction.py:300`, `presidio.py:123/154/163`) check the one attribute.
  - Via adds a profile key `location_linking` (true by default) to `PROFILE_KEYS` (`datasec_bridge.py:60`) and passes it where the redactor is built (`:353-360`). This goes in the handoff.
  - Linking behaves the same in redaction and in observation scans, so ADDRESS counts mean the same in `tally` and in `extra["observed"]`.
  - Rejected: a per-Action override (adds an `Action` field, and any single call could switch linking off, against D2's "only deliberately"); a per-part label (YAGNI).
- **A6. Speed: a `Tainted` part counts as a container in `_over_cap` (2026-11-04).** Each part adds one depth level and a few bytes, like lists and dicts at `pipeline.py:45-52`, so the existing 1 MB / 200-level caps bound the walk. No new limit.
  - New attacks, all timed against the 1 s limit:
    - R6.15: 1 MB across ~100k mixed-trust parts → bounded
    - R6.16: parts nested 201 deep → blocked ("payload too deep")
    - R6.17: a 10 MB string inside one part, under the default cap → blocked
    - R6.18 (Presidio): a 60k-character INTERNAL part next to a short USER part with a name → not denied, and the name is `[PERSON]`
  - The handoff (Via item 6) reports the R6.15 and R6.18 timings.
- **A7. Red team: 19 new attacks, 18 defended and 1 new gap; 101 → 120 attacks, 15 gaps (2026-11-07).**
  - R1.10: a mislabelled INTERNAL part with PII is unchanged **and** recorded in `extra["observed"]`. This needs a new outcome, *observed*.
  - R1.11: an untagged part inherits the Action's USER trust → redacted.
  - R1.12: a `secret` part inside a payload that is otherwise INTERNAL → egress blocked.
  - R1.13: a TRUSTED part nested inside an UNTRUSTED part → redacted.
  - R1.14: INTERNAL plus an UNTRUSTED part sent to `tool:privileged` → blocked.
  - R1g.2 (new gap): mislabelled high-trust PII leaves unredacted (it is observed, not prevented). R1g.1 gets a note that it now also skips redaction.
  - R2.29–R2.34: the R2g.5–R2g.10 forms in UNTRUSTED parts → redacted. R2g.5–R2g.10 are reworded "in USER/EXTERNAL text".
  - R4.14: a hostile part source (email, newline, ANSI codes) is passed through `_safe()` into `observed_sources` and escaped by `report.py`.
  - R5.15: a part whose provenance isn't a `Provenance` → blocked. R5.16: a part with an unsupported value → blocked.
  - R6.15–R6.18: as in A6.
  - That old logs still verify is a regression **test** (fixture log from `1a1eb54`), not an attack.

## Questions still to settle (in order, with my leaning)
- **A1. How a payload carries per-part provenance.** Propose these approaches next:
  - (a) `Tainted` objects nested inside the payload. The pipeline walks them, gates each one, and unwraps them in the output. The Action's provenance is lowered to `combine()` of everything embedded. Parts without a tag inherit the Action's provenance.
  - (b) A new `check_parts(...)` that takes a list of `Tainted` parts.
  - (c) The host calls `guard` once per message. This gives several decisions and audit entries per prompt, which is wrong for privileged sinks.
  - **Lean: (a).** It works with the existing `guard()` and `check()` signatures, handles nested JSON, and fits 3B's per-field labels.
- **A2. High-trust parts: scan and record, or skip entirely?** Lean: **scan and record** (observability). The cost is that scanning is as heavy as today.
- **A3. Where high-trust findings go in the audit, without breaking old logs.**
  - Via reads `sink`, `effect`, `rule`, `tally` and `extra["mode"]`, so any new field must be additive.
  - **Old logs must still verify under the new pin.**
  - `python -m datasec.report` should show high-trust findings.
- **A4. Which exemptions to narrow, and how.**
  - The trap: without Q2 (field declarations), low-trust parts that legitimately carry ids would regress. Example: Via's EXTERNAL `tool` memory rows citing `mem_<uuid>` ids.
  - Options:
    - Keep the exemptions only for parts below a trust floor.
    - Keep the id exemption and drop the decimal and loopback ones.
    - Measure first on Via's trial stores (the hand-back counted 132 hits, all of them 40-hex git hashes).
  - Lean: decide with data. Re-run the hand-back's measurement method on the trial stores, split by part trust.
- **A5. The location opt-in mechanism.** Options: a `Redactor(link_locations=True)` flag, a per-Action override, or a per-project profile field that Via maps onto the flag. Lean: a Redactor constructor flag (the profile builds the redactor), defaulting to on.
- **A6. Speed.** Walking `Tainted` nodes plus scanning high-trust parts must keep R6.x under 1 s at 1 MB (Via's item 6). Add a timing attack for a 1 MB payload made of many tagged parts.
- **A7. Red team.** New attacks:
  - mislabelled-INTERNAL PII is not rewritten but **is** recorded
  - an untagged part inherits low trust
  - a `secret` part inside a high-trust payload is still denied on egress
  - a hand-built TRUSTED part (an R1g.1 variant, recorded as a gap)
  - a nested `Tainted` part that tries to raise the trust of its parent

## Facts (DataSec, 2026-10-28, master `a8baacc` and later)
- **`pipeline.py`:**
  - `_decide` is at `:115`.
  - The whole payload is scanned once at `:128` (`tally = self.redactor.scan(payload, **ints)`).
  - NER runs only on egress sinks.
  - A non-empty tally adds the `pii` label, and `redact_pii_on_egress` turns that into REDACT.
  - `_record` is at `:150`.
- **`redaction.py`:**
  - `Detector.skip_ids_and_fractions` is at `:61`.
  - `_is_routable_ipv4` is at `:82`, `_UUID` at `:93` and `_FRACTION` at `:103`.
  - `_redact_spans` is at `:302` and `link_locations` at `:413`.
- **`presidio.py`** calls `_redact_spans` and `link_locations` (`:121-163`), so any change to linking must keep both paths in step.
- **Current numbers:** 491 tests passed + 14 xfailed. Red team: 101 attacks, 87 defended, 14 known gaps, 0 unexpected, with Presidio installed.
