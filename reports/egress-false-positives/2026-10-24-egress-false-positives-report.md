# DataSec — Egress False Positives From the Via 3A Trial

**Date:** 2026-10-24 · **Since:** [2026-10-16 progress report](../2026-10-16-phase3-progress-report.md) · **Branch:** `fix/egress-false-positives` (code at `1a1eb54`) · **Via re-pin:** `docs/handoffs/2026-10-24-PROMPT_via_datasec_repin_egress_fp.md`

## TL;DR

- **Via ran the 3A trial.** Two real runs, on 2026-10-21 and 2026-10-24, finished with 169 audit entries and a verified chain on the first. **DataSec's egress redaction was rewriting Via's own text.** Egress is always enforced, so these were real changes to what the model saw, not shadow observations:
  - Loopback addresses in Via's instructions: "no requests to 127.0.0.1" reached the model as "to [IPV4]".
  - Memory ids: `mem_01a15cc8-…` became `mem_01a15cc8-8c5e-71bb-a[PHONE]e24e6`. Via must cite these ids exactly.
  - Cost figures: `$0.4111111111111111` became `$0.[CREDIT_CARD]`.
- **Measured here, the problem was worse than Via reported:**
  - 3.9% of random `mem_<uuid4>` ids tripped a detector, and SSN tripped more often than PHONE (out of 10,000: SSN 225, PHONE 141, card 24).
  - 9.9% of Python float costs tripped the card detector.
- **Fixed.**
  - UUID-shaped ids and long decimal fractions are now hidden from the SSN, card and phone detectors.
  - Loopback (127.0.0.0/8) and `0.0.0.0` are no longer redacted.
  - Measured after the fix: **0 out of 10,000** in every form tested (`mem_<uuid>`, `mem-<uuid>`, `<uuid>-v2`, `<uuid>-<uuid>-<uuid>`, float costs, float ranges).
- **Cost of the fix: 6 new known gaps.** PII that someone deliberately formats as a UUID, or as a bare decimal fraction, is no longer caught (R2g.5–R2g.10). Ordinary text isn't affected.
- **Red team: 101 attacks, 87 defended, 14 known gaps, 0 unexpected. Tests: 491 passed, 14 xfailed.**
- **Four questions for you**, listed under "Questions for the design thread".

## What changed in redaction

| Before | After | Detectors |
|---|---|---|
| A UUID's digit groups (`a771-3638710e24e6`) read as a phone number, SSN or card | Hex digits inside an 8-4-4-4-12 token are hidden from those detectors, but only if the token has at least one a–f letter. An all-digit dashed run is still scanned as a number. Ids joined by dashes (`<uuid>-v2`, `mem-<uuid>`, `<uuid>-<uuid>`) also count | SSN, CREDIT_CARD (4 patterns), PHONE |
| The digits after `0.` in a float passed the card check (Luhn) | Hidden only when a bare run of **9 or more** digits directly follows `<digit>.`. No SSN, phone or card fits in fewer digits, and a fraction never contains separators, so `2.123-45-6789` (list numbering) is still scanned | SSN, CREDIT_CARD, PHONE |
| `127.0.0.1` and `0.0.0.0` became `[IPV4]` | Exempt, because they identify no one. **Private ranges (10/8, 172.16/12, 192.168/16) and public addresses are still redacted** | IPV4 |
| Location linking could rewrite an id's digits | Linking never matches inside an id | location linking |

Masking is **opt-in per detector**. Only the default SSN, card and phone detectors use it, so a host's own detectors (for example a UUID-shaped `PATIENT_ID`) still see the text exactly as written.

## Red-team scorecard

| Category | Defended | Known gap |
|---|---|---|
| Taint laundering | 9 | 1 |
| PII evasion (+R2.24–R2.28: PII next to ids, decimals and list numbers is still redacted; Via's own text passes untouched) | 27 | 10 |
| Secret exfiltration | 10 | 0 |
| Audit tampering | 13 | 3 |
| Fail-closed | 14 | 0 |
| Resource abuse (+R6.12–R6.14: 1 MB of ids, near-misses and decimals; ids next to an address; all-digit id look-alikes next to an address; each under 1 s) | 14 | 0 |
| **Total** | **87** | **14** |

Fresh run on 2026-10-24 with Presidio installed (0 skipped). Every new attack was checked against the code before its fix:

- **R2.25** (Via's own text must pass untouched) failed on master.
- **R2.27 and R2.28** (PII after list numbers, and PII glued to an id) each failed on the version just before their fix.
- **R2g.5–R2g.10** show as defended on master. They became gaps because of this fix, so they are recorded honestly.

## Review findings and fixes

There were four review rounds by a fresh reviewer. They found 1 critical issue and 3 important ones, all fixed with tests:

- **Round 1, I1.** My first decimal rule was "no match right after `<digit>.`". That was too broad. Dashed SSNs, phones and cards written straight after a list number leaked (`2.123-45-6789`, `Step 3.555-123-4567`, `2.(555) 123-4567`). **Fix:** only a bare run of 9 or more digits counts as a decimal fraction.
- **Round 1, I2.** Masking applied to *every* detector, which blinded a host's own UUID-shaped detectors, and validators received the masked text. **Fix:** masking became opt-in per detector, and validators see the real text.
- **Round 2, I1.** My change that let ids be joined by dashes let a dashed SSN, phone or card hide by gluing its last group to an id (`555-123-4567abcd-1234-…`). **Fix:** a dash may come before an id only when it follows another id or a non-digit.
- **Round 4, C1 (critical, a denial-of-service path my own speed fix introduced).** The new location-linking code folded all-digit UUID look-alikes back into the text by copying the stretch built so far each time, which is quadratic. 1 MB of them next to an address took 1.95 s at the default size cap, against the 1 s bound. **Fix:** build each stretch once. It's now linear: 0.10 s, 0.18 s and 0.36 s for 1, 2 and 4 MB. A new attack, R6.14, covers it.
- **Minors, all done:**
  - The known gaps were split into one case each, so closing one shows up on its own.
  - The decimal gap's description was widened to say that what follows the digit run isn't checked.
  - Formatting.

**My own defects, all caught before merge:**

- **My first decimal rule was too broad** (round 1, I1). My test for list numbering had a space after the dot, so it never exercised the rule.
- **Two speed problems:**
  - My rewrite of location linking slowed it enough that the 1 MB timing attack R6.11 started failing intermittently (about 1.0 s against a 1.0 s limit).
  - My first fix for that was a shortcut that changed behaviour. A fuzz comparison caught it (38 differences in 200,000 strings), and I replaced it.
  - That speed fix itself introduced the quadratic path (round 4, C1).
  - The final version: on the R6.11 payload the branch takes 0.62 s and master 0.61 s; on the new R6.13 worst case, 0.68 s and 0.59 s.
  - Fuzzing the final version against the reviewed one gave **0 differences** in 200,000 linking strings and in 100,000 full-redaction strings.
- **A zero-count bug that would have tagged clean payloads as PII.** Caught by a new test before commit.
- **A test expectation I wrote wrong.** The code was right; I fixed the test.
- **A process slip.** During a check, a stray `git checkout` overwrote my uncommitted review fixes. I rebuilt them from the committed version and the same edit scripts, and confirmed the results matched exactly. Nothing was lost.

## Known gaps (14). 6 are new and deliberate, the price of the exemption

| Gap | Why it's open | Path forward |
|---|---|---|
| R2g.5–R2g.7: a card, SSN or phone formatted as a UUID with hex letters | Ids must pass untouched, and a crafted id looks the same as a real one | A host could declare which fields hold ids, so only those skip (see Q2) |
| R2g.8–R2g.10: a card, SSN or phone written as a bare decimal fraction of 9+ digits, including when more digit groups follow | Costs and ratios must pass untouched | The same field declaration (Q2) |
| The other 8 | Unchanged from the 2026-10-16 report | — |

Every one of these needs input that someone formatted on purpose. They're in the same class as PII spelled out in words (R2g.1–R2g.2): pattern detectors can't stop a determined encoder. The control that stops them is provenance, which decides what may reach a sink at all.

## Still not fixed (measured on the branch)

- **Epoch-second timestamps:** 100% are redacted as PHONE. A 10-digit epoch is indistinguishable from a bare 10-digit phone number.
- **Epoch milliseconds:** about 10%.
- **Dashless 32-hex ids** (`uuid.hex`): about 9.5%.
- **Long decimals inside a string that also contains an address:** redacted by the location rule. That is deliberate (the 2026-10-02 trade-off).

Via has been asked to report back whether its prompts contain any of these.

## Finding 3 from Via: redaction hides a value, not a guessable one

The brief said "credit Jane Tester, jane.tester@example.com". Every prompt carried `[EMAIL]`, yet the model wrote `jane.tester@example.com` into the product, guessing it from the visible name. The regex name detector only fires on phrases like "my name is…", and Presidio wasn't installed.

This isn't a defect. It is a limit we now state in the capabilities one-pager: where names matter, install Presidio. See Q4.

## Questions for the design thread

1. **Private IP ranges.** Keep redacting 10/8, 172.16/12 and 192.168/16, or exempt them as well? They identify no person, but they reveal an internal network layout. **We lean towards keeping them.**
2. **Should hosts declare which fields are structured?** Via's report suggested hosts could declare id-shaped fields for the redactor to skip. That would close R2g.5–R2g.10, fix epoch timestamps and dashless ids precisely, and let the general exemptions narrow again. It would be a per-Action or per-field skip list, like the existing `integer_fields`. Is this worth a design?
3. **Epoch timestamps** are redacted as phone numbers 100% of the time. Should we accept that until Q2 exists, or add a narrower rule now (for example, a 10-digit number after a keyword such as `ts`, `time` or `epoch`)?
4. **Guessable values.** When an email is redacted, should a visible name next to it be redacted too, even without Presidio? Or should any host that handles PII be required to install Presidio?

## Reproduce

```bash
uv sync --extra presidio --group presidio-model --group webapp
uv run pytest -q                          # 491 passed, 14 xfailed
uv run python -m redteam.runner           # 87 passed, 14 known gaps, 0 skipped, 0 unexpected / 101
```
