# DataSec: Status Report (3A Closed, Provenance-Gated Egress Started)

**Date:** 2026-10-28 · **Since:** [2026-10-24 egress false-positives report](../egress-false-positives/2026-10-24-egress-false-positives-report.md) · **Answers:** your 2026-10-17 (3B) and 2026-10-25 (egress false positives) input · **Repo:** `master` @ `a8baacc` and later

## TL;DR

- **3A is closed on the DataSec side.**
  - The egress false-positive fix is merged (`a8baacc`, a merge commit, so Via's pin `1a1eb54` stays reachable).
  - Via re-pinned to it. Its new test failed on the old pin (a cost came out as `0.[CREDIT_CARD]`) and passes on the new one.
  - Via's re-pin branch is waiting on the principal's review.
  - Still open, on the Via and principal side: switching `tool:privileged` and `memory:write` from shadow to enforce.
- **We're adopting your reframe:** egress redaction will depend on provenance. This cycle has started and is paused after its scoping decisions. **3B comes after it**, because it changes what the `llm` sink means for every adapter.
- **One catch you couldn't have seen from the report:** a host sends **one** prompt built from several sources, so the gate needs **provenance per part**, not per call. Details below.
- **One default differs from your Q7:** location linking stays **on** by default, and a project can opt out. The reasoning is below.

## How your input was used

| Your item | Decision |
|---|---|
| **Reframe:** gate egress redaction on provenance (skip INTERNAL/TRUSTED) | **Adopted.** This cycle builds it |
| **Observability:** surface rewrites of high-trust text | **Adopted.** High-trust parts are still scanned and what's found is recorded in the audit, but they are never rewritten. A host that mislabels user data as INTERNAL shows up in `datasec.report` on the first run |
| Q1: exempt private IPs on `llm` | **Deferred** to a later cycle (user's choice) |
| Q2: host-declared structured fields | **Deferred** to a later cycle |
| Q3: no keyword rule for epoch timestamps | **Accepted.** Via found 0 epoch timestamps in its prompts anyway |
| Q4: require Presidio where names matter; no proximity heuristic | **Accepted.** It's a documented limit in the one-pager |
| **Narrow the regex exemptions now that trusted text is gated** | **In scope this cycle**, with one trap (below) |
| 3B Q7: location linking per-project opt-in, **off** by default | **Opt-in mechanism in scope, but on by default** (see below) |
| 3B Q1 (stores count as memory only if read back), Q2 (taint on output is enough), Q3 (inject the pipeline), and the sole-trust-assigner goal | **Recorded** in the 3B brainstorm for when it resumes |
| Push master first | **Done** (2026-10-17 and 2026-10-24). This report's commits are not pushed yet |

## The catch: per-part provenance

Via's bridge guards each prompt as **one payload**, with the weakest trust of its messages. Its instructions (INTERNAL) and the principal's brief (USER) end up in the same payload, which is then at best USER. A gate on that combined trust **would skip nothing**, so Via's loopback instruction would still be rewritten.

The design therefore lets each **part** of a payload carry its own provenance:
- Low-trust parts are redacted.
- High-trust parts are scanned and recorded, but left untouched.
- The **policy decision** still uses the weakest trust and every label. So a `secret` label still blocks egress whatever the trust, and one prompt still gives one decision and one audit entry.

This is also the mechanism 3B's per-field labels need.

**The risk, stated plainly:** hand-built TRUSTED provenance (known gap R1g.1) now also skips redaction. That gets red-team attacks and an honest gap entry. 3B's goal of making the adapter the only place trust is assigned is the structural fix.

## Why location linking stays on by default (your Q7)

On 2026-10-02 the user ruled that location redaction is all-or-nothing. A redacted city next to a visible ZIP still identifies the person. Your concern was over-redaction of data-heavy payloads (order ids, measurements, epochs), and **the trust gate already removes most of it**: that data-heavy text is the host's own, which is INTERNAL and won't be rewritten.

What's still scanned is user, external and untrusted text, which is where a home address appears. So linking stays on, and a project can switch it off in its profile, but only on purpose. If shadow data later shows low-trust over-redaction, revisit this.

## The trap in narrowing the exemptions

Without Q2 (field declarations), low-trust parts that legitimately carry ids would get worse. For example, Via's EXTERNAL memory rows cite `mem_<uuid>` ids. We'll decide which exemptions to drop **with data**, by re-measuring Via's trial stores and splitting the hits by part trust, rather than dropping them all at once.

Via's hand-back gives a baseline: 132 places are still rewritten, all inside 40-hex git hashes, from a Via bug. Separately, Via's 12-hex short ids trip a detector about 2.3% of the time.

## Via's contract (agreed 2026-10-28)

Via now lists exactly when DataSec must send it a re-pin handoff:
- a change to the API Via calls
- a change to the exception contract
- a change to what gets redacted on egress
- a change to the audit or checkpoint format (an old log must still verify)
- a change to the privileged-action rules
- a change in speed
- Presidio being ready

**This cycle hits four of them: the API, egress redaction, the audit format, and speed.** It will end with a re-pin handoff that covers each one.

## Open questions where your view would help

1. **Should high-trust findings ever block?**
   - Today the plan is that INTERNAL text containing PII is recorded but sent as-is.
   - Should there be a per-project switch that turns "PII found in INTERNAL text" into a deny, for hosts that want to enforce correct labelling?
2. **What should an untagged part inherit?**
   - The plan is that it inherits the payload's provenance (fail-closed for a mislabel upward).
   - Alternatively, it would always count as low trust.

## Numbers (unchanged since 2026-10-24)

491 tests passed + 14 xfailed. Red team: 101 attacks, 87 defended, 14 known gaps, 0 unexpected, with Presidio installed.
