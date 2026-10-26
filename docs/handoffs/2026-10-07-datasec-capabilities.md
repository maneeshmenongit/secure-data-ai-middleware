# DataSec — what the security middleware does (one page)

**Status:** 2026-10-07, updated 2026-10-24 · repo `secure-data-ai-middleware` · Via integration pinned at `cf62c48`, with a re-pin pending for the egress false-positive fix · 491 tests, 101 red-team attacks (87 defended, 14 documented gaps, 0 unexpected)

## In one sentence
A stdlib-only Python layer that sits at every point where an AI system's data **leaves or acts**: prompts to an LLM, tool calls, memory writes, third-party calls and HTTP responses. Each such point calls `guard()`. Each call returns **allow**, **redact** or **deny**, based on *where the data came from*, and leaves a tamper-evident audit record.

## How a host uses it
```python
check(pipeline, Action(sink, name, provenance), payload, Mode.ENFORCE)   # -> safe payload, or raises Blocked
```
- **Sinks** (where data goes): `llm`, `tool:privileged`, `tool:readonly`, `memory:write`, `third_party`, `http:response`.
- **Provenance** (where data came from): `UNTRUSTED` < `EXTERNAL` < `USER` < `INTERNAL` < `TRUSTED`, plus labels such as `secret` and `pii`. When data is combined, the result gets the **weakest trust** of its parts and **all of their labels**, so untrusted text can't be "laundered" into trusted data.

## What it protects against
| Threat | Control |
|---|---|
| **Prompt injection driving actions.** A web page or a tool reply tells the agent to pay, write or call out | Untrusted and external data **can't reach privileged sinks**. Trusted third parties can be allowlisted per source |
| **PII leaving to an LLM or a third party** | Redacted before egress: email, phone, SSN, card (Luhn-checked), IPv4, account and routing numbers, self-introduced names, street addresses, state + ZIP, coordinates. Optional NER (Presidio) adds names and places |
| **Re-identification from leftovers** | **Location is all-or-nothing.** Once any part of an address is found, the ZIP, state, house number and coordinates go too, merged into one `[ADDRESS]` |
| **Evasion tricks** | Unicode normalisation, zero-width and invisible characters, full-width digits, unusual dashes, PII inside dict keys or nested JSON, PII next to other text |
| **Secret exfiltration** | Anything labelled `secret` is **denied** on every egress sink. Secrets written to memory can be **sealed at rest** (Fernet, key rotation) |
| **Data going to the wrong place** | An egress **destination allowlist**. A third-party call to an unlisted or unnamed host is denied |
| **Abuse and denial of service** | Payload byte and depth caps, NER work budgets, and linear-time detectors (1 MB adversarial inputs stay under 1 s) |
| **Covering tracks** | A hash-chained audit log, plus **signed checkpoints** that detect edits, deletions, reordering, truncation and rewrites. The log stores **counts and redacted metadata, never payloads** |

## Safe rollout for a host like Via
- **Shadow mode** for `tool:privileged` and `memory:write`: decisions are recorded as *would-have-denied*, and nothing is blocked. Real runs then show false positives before anything is enforced.
- **Egress (`llm`, `third_party`) is always enforced.** No configuration can switch off redaction or secret blocking.
- **Per-project profiles** (in the Via integration) set trust, allowlists and which of the two tool and memory sinks enforce.
- **`python -m datasec.report <audit.jsonl>`** verifies the chain, then summarises decisions and the shadow denials to review.

## Guarantees
- **Fails closed.** Unknown sinks, missing provenance, a crashing rule, a scan error or a malformed decision all produce **deny**, and are audited. An audit-write failure stops the call. Nothing is ever returned unaudited.
- **No extra dependencies.** The core uses the Python standard library only. NER (`datasec[presidio]`) and encryption (`datasec[crypto]`) are optional.
- **Errors safe to log.** `Blocked` errors carry only redacted text, so a host can store them.

## Evidence
- Every control ships with unit tests **and** a red-team attack. The current suite has 101 attacks; each one fails if its control is removed.
- Six whole-branch security reviews (Phase 1, Phase 2, NER, demo console, 3A, the egress false-positive fix) found and fixed **4 critical and 25 important** issues, each with a regression test.

## Known limits (documented, tested as open gaps)
- **Hand-built trust.** Code that hand-builds `TRUSTED` provenance is trusted. Mitigation: only the integration's boundary assigns trust.
- **PII the patterns can't see.** This covers PII spelled out in words, PII split across list items, names when NER isn't installed, and (since 2026-10-24) PII deliberately formatted as a UUID or a long decimal fraction. Ids and costs that hosts write themselves must pass untouched, so those shapes are exempt.
- **Redaction hides a value, not a value that can be guessed.** If a person's name stays visible, a model can rebuild their redacted email (`Jane Tester, [EMAIL]`). Install NER wherever names matter.
- **Audit truncation without an anchor.** If no checkpoint is configured, truncation goes undetected. If an attacker can replay an old checkpoint, it does too. That needs an external, forward-only anchor, which is an open decision.
- **Shadow data needed.** Tool and memory enforcement thresholds need tuning from real shadow data before they are switched on.

## Roadmap
- **3A**: Via as host. The DataSec side is done; the Via side is handed over (`2026-10-05-PROMPT_via_datasec_3A.md`).
- **3B**: LangGraph adapter, piloted on `paper-trader` (research agents can't drive the trade agent).
- **3C**: ASGI adapter for HTTP projects.
