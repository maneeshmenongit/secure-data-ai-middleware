# DataSec — Design-Thread Input (Egress False Positives)

**Date:** 2026-10-25 · **In response to:** 2026-10-24 egress-false-positives report (`fix/egress-false-positives` @ `1a1eb54`) · **For:** the egress-redaction decision and Q1–Q4

Position doc, not a plan. Verdict + reason for each item.

---

## Credit where due

The trial → measure → fix loop worked as designed: a real Via run surfaced the problem, you quantified it (3.9% of `mem_` ids, 9.9% of float costs, per-detector counts) instead of guessing, drove it to 0/10,000, and recorded the 6 new gaps honestly rather than burying them. The self-caught defect list (over-broad decimal rule, the quadratic DoS your own speed fix introduced, the stray `git checkout`) is what makes the report trustworthy. None of what follows is a knock on the execution — it's about the layer the fight is happening at.

---

## The reframe: this is the wrong layer, and the report says so

Every incident here — loopback addresses, `mem_<uuid>` ids, `$0.4111…` costs — is **Via's own INTERNAL, system-authored text** being PII-scanned and rewritten on egress. The root cause is not greedy regexes; it is that egress redaction runs on trusted content at all. That traces to the Phase 1 "scan-at-sink regardless of origin" deviation (justified then for catching PII in LLM *output*), which now rewrites trusted system text.

### Fix: provenance-gated redaction

Only PII-redact content whose provenance is below a trust floor — redact on egress when `trust <= USER`; **skip INTERNAL / TRUSTED**.

- Fixes all three incidents **at the source**: Via's instructions, memory ids and costs are INTERNAL, so they're never scanned.
- Lets you **remove most of the UUID / decimal / loopback exemptions and retire most of the 6 new gaps** (R2g.5–R2g.10) — the only content still scanned is low-trust, where a UUID-shaped false positive is rare and acceptable.
- More faithful to the provenance-first thesis than regex carve-outs: the redactor fights blind on text; provenance is the layer that knows whether a string is attacker-reachable.
- Coherent on both sinks. An LLM reply derived from a prompt that carried user/external content inherits low trust via `combine`, so it's still scanned; only all-trusted content is exempt.

**Why this matters beyond these three bugs:** the whack-a-mole is already visible — epoch seconds (100% redacted), epoch millis (~10%), dashless 32-hex ids (~9.5%) are each another trusted-text pattern that would otherwise need its own exemption, and each exemption opens a new true-positive gap. That trade is unwinnable at the regex layer and dissolves once redaction is trust-aware.

### Companion: observability on egress rewrites

Egress is enforced, so these were real rewrites of what the model saw, across two live trials, before anyone noticed. Even enforced egress should surface **what redaction changed on high-trust content** — a sampled or hashed before/after in the audit, or an alert when INTERNAL/TRUSTED text is rewritten. That catches corruption on run 1, not after a trial and a measurement study.

---

## Q1 — Private IP ranges: lean the opposite, at least on `llm`

A private IP is not PII; it identifies no person. The concern you name (internal network layout) is a **topology-leak** control, not a privacy one, and folding it into the PII redactor is what mangles Via's own infra instructions the same way loopback did.

- **Exempt private ranges from the PII path on the `llm` sink.**
- If topology-hiding to third parties genuinely matters, make it an **explicit, separately-named egress control scoped to `third_party`** — not a silent behavior of the IPV4 PII detector.

## Q2 — Host-declared structured fields: strong yes, this is the real fix

Same shape as the existing `integer_fields`. Closes R2g.5–R2g.10, and fixes epoch timestamps and dashless ids **precisely** instead of with blunt global exemptions you then gap around.

- Build it as a per-Action / per-field skip list.
- Composes with the provenance gate: trust-gating removes the common case (trusted text); field declaration handles the residue (low-trust content that legitimately carries ids). Together they let you narrow or drop almost every exemption in this report.

## Q3 — Epoch timestamps: do not add the keyword rule

"A 10-digit number after `ts`/`time`/`epoch`" is one more fragile exemption that itself opens a gap (a real phone number after the word "time" now leaks), and you'll be back here.

- Epochs appear in Via's own INTERNAL payloads, so the **provenance gate fixes them now**; **Q2 fixes them precisely later**.
- If neither is ready this week, **accept** the 100% epoch redaction short-term rather than ship a rule you'll have to carve a hole in.

## Q4 — Guessable values: require Presidio where names matter; no proximity heuristic

"Redact a visible name next to a redacted email" is a weak partial measure that gives false confidence and is trivially evaded (move the name a line away). Name detection without NER is exactly what regex can't do.

- State it as a documented limit (you already have, in Finding 3 / the one-pager): a host handling names installs Presidio; without it, name redaction is best-effort.
- The deeper truth: redaction protects a **value**, not the **fact** it encodes — if the name is visible the email is guessable regardless. The real control is redacting the name (NER) or not sending the identifying context (provenance / field-level), not a bolted-on proximity rule.

---

## Summary

| # | Question | Position |
|---|---|---|
| — | Root cause | Egress redaction rewrites trusted system text. **Gate redaction on provenance (skip INTERNAL/TRUSTED).** Fixes all 3 incidents at source; retires most of the 6 new gaps |
| — | Observability | Surface before/after when high-trust text is rewritten on egress, so corruption is caught on run 1 |
| 1 | Private IP ranges | Not PII — exempt on `llm`; if topology-hiding matters, a separate control scoped to `third_party` |
| 2 | Host-declared structured fields | Strong yes — the precise fix; composes with the provenance gate |
| 3 | Epoch timestamps | No keyword rule; provenance gate now + Q2 later; accept short-term if neither ready |
| 4 | Guessable values | Require Presidio where names matter; no proximity heuristic |

**Net:** move the fight off the regex layer. Provenance-gate egress redaction first (fixes the incidents, retires most new gaps), then field declaration (Q2) for the low-trust residue. Both put the decision back on provenance, which is the point of the project.
