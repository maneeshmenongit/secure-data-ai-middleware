# DataSec Middleware — Progress Report (Phase 2 → Demo Console)

**Date:** 2026-10-02 · **Since:** [Phase 1 report](2026-09-27-phase1-security-report.md) · **Repo:** `master` @ `5555bd4` (pushed)

## TL;DR

- **Phase 2 (harden the core) is done,** including the follow-up fixes. Every item in the Phase 2 spec has shipped except Presidio, which shipped in its own cycle.
- **There is now a local demo console** with a Protection ON/OFF switch, real Claude and Gemini replies, and a live audit log. It shows the middleware working end to end.
- **The red team grew from 50 to 81 attacks:** 73 defended, 8 known gaps, 0 unexpected.
- **The test suite has 392 tests,** all passing apart from the 8 known gaps, which are recorded as tests that are expected to fail.
- **Three whole-branch reviews** found 2 critical and 11 important issues across these merges. All are fixed, and each has a regression test.
- **We need three decisions** from this thread (see the last section).

## What shipped

| Merge | What it adds |
|---|---|
| Phase 2 (`70c801d`) | EXTERNAL trust blocked from privileged sinks, with a per-source allowlist (§10.5) · integer PII scanning is opt-in and scoped (§10.6) · an egress destination allowlist · payload size and depth caps · labels matched regardless of case · a `KeyProvider` that encrypts `secret` memory writes at rest (§10.1) · signed audit checkpoints (§10.4) |
| Phase 2 follow-ups (`7ef87eb`) | 9 smaller issues closed: an allowlist passed as a plain string no longer fails open, labels are matched across Unicode variants, checkpoint files are owner-only, egress destinations are written to the audit log, `AuditLog.load(checkpoint=…)`, and others |
| Presidio (`de6fe1a`) | An optional NER redactor for **names and places**. It runs only on outbound sinks, loads its model once at startup, and has a per-payload work budget. The base install still needs no dependencies (§10.8) |
| Demo console (`9c1c303`) | A local web page with 6 scenarios, the Protection switch, a choice of mock/Claude/Gemini, and audit Verify and Tamper-demo buttons. It accepts only local, same-origin requests |
| Location linking (`5555bd4`) | New detectors for a self-introduced name ("my name is X"), street addresses, state + ZIP, coordinates and account numbers. Once any part of a location is found, the rest of it is redacted too |

### Design point worth discussing: location is all-or-nothing

A manual test on the console redacted the city but left the ZIP, house number and coordinates. Those remainders still identify the person (they are quasi-identifiers), so redacting only the city did not protect anything. Redaction now works like this: once a string contains any location, every remaining location-like fragment in that string is redacted too, and the pieces collapse into one `[ADDRESS]`. Strings with no location keep the conservative rules, so prices, version numbers and order IDs are untouched. The user's own message now comes out as:

> my name is [PERSON] and I live in [ADDRESS] and my phone number is [PHONE]. I could provide my lat [GEO_COORDINATE] and long [GEO_COORDINATE] … the account number is [ACCOUNT_NUMBER].

## Red-team scorecard

| Category | Defended | Known gap |
|---|---|---|
| Taint laundering (incl. EXTERNAL tool replies, allowlisted source not over-blocked) | 9 | 1 |
| PII evasion (spacing, Unicode, CSV rows, names next to emails, addresses/ZIP/coordinates/accounts) | 22 | 4 |
| Secret exfiltration (egress allowlist, at-rest encryption, label case) | 10 | 0 |
| Audit tampering (checkpoint deletion, forged and sealed-value checkpoints) | 12 | 3 |
| Fail-closed probes (self-referencing and shared-reference payloads, sink spoofing) | 9 | 0 |
| Resource abuse (1 MB inputs per detector, NER budget, 10 MB cap) | 11 | 0 |
| **Total** | **73** | **8** |

Attacks that need Presidio are reported as `skipped`, not failed, when it isn't installed. In that case the base install scores 69 defended, 8 gaps and 4 skipped.

## Issues found and fixed (whole-branch reviews)

- **Phase 2 review:**
  - Deleting the checkpoint file silently turned checkpoint verification off. Fixed: checkpoints are now required once a log exists.
  - A sealed secret could be passed off as a valid checkpoint, because both used the same key and format. Fixed: each kind of encrypted value now carries a purpose tag.
  - A payload full of shared references could hang `guard()`. Fixed: every node now counts against the size budget.
  - A `third_party` call with no destination skipped the allowlist. Fixed: it is now denied.
- **Presidio review:**
  - A name next to an email or phone leaked. This covered CSV rows, `Name <email>`, and a bracket typed right before a name. Fixed: regex placeholders and brackets are masked before NER runs, and overlapping spans are clipped instead of dropped.
  - Many short strings could stall NER. Fixed: each payload now has an NER budget.
- **Demo console review:**
  - Any web page open in the user's browser could POST to `/api/reset` and wipe the audit log. Fixed: requests must be same-origin and JSON.
  - DNS rebinding could let a remote page use the console with the user's API keys. Fixed: the Host header is checked.
  - The Gemini client had no timeout. Fixed.
- **Caught by the red team itself:**
  - A coordinate or ZIP followed by a full stop slipped through. Fixed.
  - An early version of the Presidio fix was too slow for the resource limits. It was redesigned to stay linear.

## Known gaps (8, all deliberate and tested)

| Gap | Why it's open | Path forward |
|---|---|---|
| R1g.1 — calling code can construct a `TRUSTED` provenance by hand | Python can't stop in-process code from doing this | Phase 3 adapters own all trust tagging at the boundary |
| R2g.1/2 — PII written out in words | Pattern detectors and Presidio's email/SSN recognisers can't read spelled-out values | Would need an LLM-based classifier, which is a cost and latency decision |
| R2g.3 — an email split across list items | Each string is scanned on its own | Accept the gap, or scan strings joined together |
| R2g.4 — names and cities without Presidio | Regex can't recognise them | Deploy with Presidio |
| R4g.1/2 — truncating or rewriting the audit log when no checkpoint is configured | Configuring checkpoints is up to the operator | Make checkpoints the default in Phase 3 adapters |
| R4g.3 — replaying an older genuine checkpoint | Needs an anchor that only moves forward and that the attacker can't reach | External anchor (see decisions) |

## Decisions for the design thread

1. **Where should the audit anchor live? (closes R4g.3)** Today the latest checkpoint sits on the same disk as the log. Options are a database row the application can't write to, a transparency log, or periodic signed exports. We recommend a write-only database row once Via has one.
2. **Is the location false-positive trade-off acceptable?** Once a location appears, any bare 5-digit number, any decimal with 4 or more places, and any uppercase US state code in the same string is redacted. That is safe, but it can over-redact an order ID or a measurement that sits next to an address.
3. **What comes next?** Options:
   - Phase 3 (Via adapters), which depends on how stable Via's interface is.
   - The out-of-band harness (§7), aimed first at the demo console.
   - The v2 test rig, built securely, with OWASP Juice Shop for the Bucket B attacks.

## Still open (smaller items)

- **Presidio:**
  - NER on audit metadata can be costly.
  - Input validation is minor.
  - Scan and redact each run NER once (2× cost).
  - Recall limits: names written as `J.a.n.e`, or split across list items.
- **Demo console:**
  - The run result shows the reply-guard audit entry rather than the input's.
  - Pressing Reset during a run can lose that run's audit entries.
  - The page doesn't disable buttons while a request is in flight.
  - Request validation is loose in a few places.

All of these are listed in the merge ledgers and none of them fail open on the protected path.

## Reproduce

```bash
uv sync --extra presidio --group presidio-model --group webapp
uv run pytest                     # 392 passed, 8 xfailed
uv run python -m redteam.runner   # 73 passed, 8 known gaps, 0 unexpected / 81
uv run --group webapp python -m webapp   # demo console at http://127.0.0.1:8000
```
