# DataSec Middleware — Phase 1 Security Report

**Date:** 2026-09-27 · **Scope:** Phase 1 of [DESIGN.md](../DESIGN.md) §8 (standalone core) · **PR:** [#1](https://github.com/maneeshmenongit/secure-data-ai-middleware/pull/1)

## TL;DR

- The core that DESIGN.md §2–§5 describes is built. It uses only the Python standard library, and every entry point goes through a single `SecurityPipeline.guard()` call.
- An in-repo red-team suite ran **50 attacks** against it. **44 were defended**, **6 are documented known gaps**, and **0 were unexpected**.
- A separate review of the whole branch found **1 critical and 7 important issues**. All 8 are fixed and each is covered by a regression test.
- The design thread needs to decide on **three points** (see the last section).

## What was built

| DESIGN.md module | Status | Notes |
|---|---|---|
| `provenance` (§3, §4.1) | ✅ | Combining values gives min trust and the union of labels. Everything is immutable. A label passed as a single string is treated as one label. |
| `redaction` (§4.2) | ✅ | EMAIL, SSN, CREDIT_CARD (with Luhn check), PHONE, IPV4. Scans nested dicts and lists, including dict keys and integer fields. Unicode is normalized first, invisible characters are stripped and dashes are unified. Matching time is linear in input size. |
| `policy` (§4.3, §5) | ✅ | The 3 rules from §5. DENY beats REDACT beats ALLOW. A rule that crashes or returns something malformed produces DENY. |
| `audit` (§4.4) | ✅ | SHA-256 hash chain written to a JSONL file. Thread-safe. When the service restarts it continues the existing chain, and it refuses to start if that file fails verification. `expected_head` also catches deleted entries at the end of the log. |
| `pipeline` (§4.5) | ✅ | Every path writes an audit entry. Errors produce DENY, or raise an error if the audit write itself fails. Caller-supplied metadata is redacted before it is logged. |
| `adapters/` (§6) | ⏳ Phase 3 | Intentionally not built yet. |

### Changes to the design worth knowing

1. **PII is detected where the data leaves (at the sink), not where it enters.** The `redact_pii_on_egress` rule in DESIGN.md only fires when a value already carries the `pii` label, and nothing applied that label. `guard()` now scans the payload itself and adds `pii` before the rules run. This catches PII from any origin, including LLM output.
2. **Unknown sinks are denied.** Sink names must match exactly, so `"LLM"`, `" llm"` or made-up sinks are denied.
3. **The audit log also redacts `source`, `name`, `labels` and any rule text.** Otherwise a value such as `source="user:jane@example.com"` would write raw PII into the log.

## Red-team results

The attacks run against the code itself (no network) with `uv run python -m redteam.runner`. Each attack has an expected outcome. A known gap is recorded as a test that is expected to fail, and the build breaks when a gap gets fixed, so its label has to be updated.

| Category | OWASP LLM | Defended | Known gap |
|---|---|---|---|
| Laundering untrusted data into privileged calls (combining values, transform chains, memory writes, third-party calls) | LLM01/04/06 | 4 | 1 |
| Hiding PII from detection (spacing, full-width digits, zero-width characters, soft hyphens, en-dashes, dict keys, card+CVV, integer fields, nesting) | LLM02 | 14 | 3 |
| Secret exfiltration (each outbound sink, secrets mixed with other data, secret+PII) | LLM02 | 5 | 0 |
| Audit log tampering (edit, delete, reorder, recomputing hashes, rewriting the whole chain, truncation) | — | 7 | 2 |
| Fail-closed probes (sink name variants, bytes payload, crashing rule, 10k-deep nesting, missing provenance) | LLM06/10 | 7 | 0 |
| Resource abuse (1 MB pathological inputs against each detector, each must finish in under 1 s) | LLM10 | 7 | 0 |
| **Total** | | **44** | **6** |

The slowest resource attack takes about 0.15 s, against a 1 s limit.

## Issues found and fixed

These were found by the whole-branch review. Each fix started with a test that reproduced the problem.

| Severity | Issue | Fix |
|---|---|---|
| Critical | A card number followed by its CVV (`4111 1111 1111 1111 123`) reached the LLM in plain text | Added exact card-layout detectors. A first fix that Luhn-checked every sub-window broke the 1 s limit on attack R6.5 and was replaced. |
| Important | A rule returning a `Decision` with a malformed effect was silently dropped, which allowed the request | Such a rule now produces DENY |
| Important | PII could reach the audit log through labels, reasons or rule names | All of those are redacted before logging |
| Important | Soft hyphens, left-to-right marks, bidi controls and en-dashes hid SSNs and card numbers | All invisible format characters are stripped and all dashes unified before matching |
| Important | Restarting the service made the log file fail verification | The log continues the existing chain when reopened |
| Important | Concurrent `guard()` calls split the hash chain | Appends are now locked |
| Important | Malformed actions or engine output raised errors without an audit entry | Such calls now produce DENY and are audited |
| Important | A card number or SSN stored as a JSON integer was never scanned | Integers are now scanned (this overrides the spec; the spec has been updated) |

## Known gaps

| Gap | Why it stays open | Proposed mitigation |
|---|---|---|
| A caller can construct `Provenance(TRUSTED, …)` directly for untrusted data | Python can't stop in-process code from doing this | Phase 3 adapters own wrapping data at the boundary; add a lint or review rule against constructing `Provenance` directly |
| PII written out in words (`john at example dot com`), or split across list items | Regex detectors can't recognise these | Phase 2: use Presidio behind the same `Redactor` interface |
| Deleting the end of the audit log, or rewriting the whole chain, goes undetected if nobody stored the latest hash | The hash chain has no key | Store `AuditLog.head` somewhere independent, such as a separate store or a periodic signed checkpoint |

## Decisions for the design thread

1. **Where should the latest audit hash be stored?** Without storing it independently, the log only shows that entries were changed, not that the whole log was replaced. Options: a separate database row, a signed file or an external log service.
2. **Scanning integers.** We now redact integers that look like SSNs or card numbers inside JSON bodies bound for the LLM. This protects data but can alter legitimate numeric IDs. Should we keep this?
3. **What goes into Phase 2?** Recommended: a `KeyProvider` interface with a local key for development (DESIGN.md §10), an egress allowlist, Presidio, a payload size cap, and case-insensitive labels.

## Reproduce

```bash
uv sync
uv run pytest                     # 168 passed, 6 xfailed
uv run python demo.py             # 4 end-to-end scenarios
uv run python -m redteam.runner   # scorecard -> redteam/scorecard.json
```
