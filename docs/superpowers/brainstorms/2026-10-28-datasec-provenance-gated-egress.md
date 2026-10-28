# [2026-10-28] Provenance-gated egress redaction: paused brainstorm

**Status:** PAUSED at brainstorming checklist step 4 (propose 2–3 approaches). Two decisions are made. There is no spec, plan or code yet.
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
