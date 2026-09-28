# DataSec Middleware — Phase 2 Design Spec (Harden the Core)

**Date:** 2026-09-27 · **Status:** design, ready to implement · **Parent:** [DESIGN.md](DESIGN.md) §8.3, §10 · **Intended builder:** Claude Code (this doc is the spec; it writes the code)

---

## 0. Scope

Phase 2 hardens the standalone core. It adds no framework adapters (still Phase 3) and does not stand up the out-of-band harness (still §7). It stays **stdlib-only at runtime except where a feature inherently needs a library** — that exception is Presidio, which is optional and loaded behind the existing `Redactor` interface, so the default install stays stdlib-only.

**Hard constraint: do not break Phase 1 contracts.** Every Phase 1 unit test and red-team attack must still pass unchanged (except where a decision below deliberately tightens behavior, in which case update the specific test and say so). Fail-closed and "never return an unaudited result" remain absolute.

**In scope (each is a resolved §10 decision or the §8.3 list):**
1. `KeyProvider` + field-level encryption for `secret`-labelled values (§10.1)
2. Audit-head checkpointing (§10.4)
3. EXTERNAL-trust → privileged blocked (§10.5)
4. Scoped integer scanning (§10.6)
5. Egress allowlist
6. Payload size cap
7. Case-insensitive labels
8. Presidio behind the `Redactor` interface (§10.2 follow-on)

Ordering below is by dependency and risk: policy changes first (cheap, high-value), then infra (encryption, checkpoint), then the detector upgrade (largest, most optional).

---

## 1. EXTERNAL-trust → privileged blocked (§10.5)

**Why:** tool and third-party responses (`EXTERNAL`, level 1) are a primary indirect-prompt-injection vector. Today only `UNTRUSTED` (0) is blocked from privileged sinks, so a poisoned tool result can trigger a privileged action.

**Change:** rename `no_untrusted_to_privileged` → `no_low_trust_to_privileged`; fire when `action.provenance.trust <= TrustLevel.EXTERNAL` **and** `sink in PRIVILEGED`. Keep the old rule name as a thin alias for one release so nothing importing it breaks.

**Escape hatch (don't lower the bar globally):** a per-`source` allowlist for the rare trusted third party that must reach a privileged sink.
```python
# policy.py
PRIVILEGED_SOURCE_ALLOWLIST: frozenset[str] = frozenset()  # e.g. {"api:stripe-verified"}
# rule passes when trust <= EXTERNAL only if action.provenance.source not in the allowlist
```

**Tests / red-team:** update the R1 corpus — add `EXTERNAL → {tool:privileged, third_party, memory:write}` expecting `blocked`; add one allowlisted-source case expecting `allowed`. Update any Phase 1 test that asserted EXTERNAL→privileged was allowed (there should be none relying on it; if so, it becomes a blocked assertion).

---

## 2. Scoped integer scanning (§10.6)

**Why:** Phase 1 redacts any JSON integer matching SSN/card patterns. That corrupts legitimate numeric IDs (order numbers, primary keys, epoch timestamps) — a high false-positive cost for data-engineering payloads.

**Change:** default the redactor to **scan strings only**. Integer scanning is **opt-in**, at two granularities:
- per call: a `scan_integers: bool = False` flag on `Action` (or passed to `guard`);
- per field: an optional field-name allowlist so only declared fields (e.g. `"ssn"`, `"card"`) have their integer values scanned.

```python
# redaction.py
class Redactor:
    def __init__(self, detectors=DEFAULT_DETECTORS, *, scan_integers: bool = False,
                 integer_fields: frozenset[str] | None = None): ...
```
When `scan_integers` is False (default), integer leaves pass through untouched — reverting the Phase 1 blanket behavior. When True, integers are stringified and scanned; with `integer_fields` set, only values under those keys are scanned.

**Tests / red-team:** default path — an order-id integer that looks like an SSN passes through unchanged (new regression test asserting no corruption). Opt-in path — an integer SSN under an `ssn` field is redacted. Update the Phase 1 "integers are scanned" test to the opt-in form.

---

## 3. Egress allowlist

**Why:** defense in depth beyond content redaction — constrain *where* egress sinks may send, so an exfiltration attempt to an unknown destination is denied even if content checks were somehow bypassed.

**Change:** a new pluggable rule `egress_allowlist` for `third_party` (and any sink that names a destination). The destination travels on the `Action` (e.g. `Action.destination: str | None`). Deny egress to a destination not on the allowlist.
```python
# policy.py
EGRESS_ALLOWLIST: frozenset[str] = frozenset()  # e.g. {"api.openai.com", "api.stripe.com"}
def _egress_allowlist(action) -> Decision | None:
    if action.sink in EGRESS and action.destination and action.destination not in EGRESS_ALLOWLIST:
        return Decision(Effect.DENY, f"egress to {action.destination} not allowlisted", "egress_allowlist")
```
Empty allowlist = deny all destination-bearing egress (fail closed); configure explicitly. Sinks with no `destination` (e.g. `llm` to the configured model) are unaffected.

**Tests / red-team:** egress to an unlisted host → blocked; to a listed host → allowed; add an R3 variant sending a secret to an unlisted host and confirm DENY (belt and suspenders with `never_leak_secrets`).

---

## 4. Payload size cap

**Why:** bound resource use and stop giant payloads before the detectors walk them; complements the R6 linear-time guarantee.

**Change:** a configurable byte/串 cap checked at the very top of `guard()` (before scan). Over cap → `DENY("payload too large")`, audited. Cap applies to the serialized payload size and to max nesting depth (the 10k-deep case already denies — formalize it as a `max_depth` config rather than relying on `RecursionError`).
```python
# pipeline.py
SecurityPipeline(..., max_bytes: int = 1_000_000, max_depth: int = 200)
```

**Tests / red-team:** payload just over cap → DENY audited; nesting past `max_depth` → DENY (deterministic, not via `RecursionError`); ensure a normal payload under cap is unaffected.

---

## 5. Case-insensitive labels

**Why:** `"PII"`, `"Pii"`, `"pii"` should be one label; today they're distinct, which could silently defeat `redact_pii_on_egress`.

**Change:** normalize labels to lowercase at the boundary — in `Provenance.__post_init__` and `with_labels`. `has()` compares lowercased. This is a small change with wide blast radius, so:
- keep the stored form lowercased;
- audit output already sorts labels — confirm it emits the normalized form.

**Tests:** `Provenance(..., labels={"PII"}).has("pii")` is True; `with_labels("Secret")` then egress → DENY via `never_leak_secrets`. Add a red-team case: a `"PII"`-cased label on egress still redacts (guards against case-based evasion).

---

## 6. KeyProvider + field-level encryption for `secret` values (§10.1)

**Why:** `secret`-labelled values that are *stored* (e.g. written to memory) should be encrypted at rest, not just blocked from egress. Phase 1 blocks secrets from leaving; Phase 2 protects them where they legitimately land.

**Design — interface first, so the backend swaps without touching callers:**
```python
# crypto.py  (new module)
class KeyProvider(Protocol):
    def encrypt(self, plaintext: bytes, *, key_id: str = "default") -> bytes: ...
    def decrypt(self, ciphertext: bytes, *, key_id: str = "default") -> bytes: ...
    def current_key_id(self) -> str: ...

class LocalKeyProvider:      # dev: Fernet (cryptography lib) or stdlib AES-GCM via `hashlib`+`hmac`? -> see note
    ...
class KmsKeyProvider:        # later: wraps a cloud KMS behind the same Protocol
    ...
```
**Library note:** true authenticated encryption needs a crypto library (`cryptography`'s Fernet, or `pyca`), which breaks the stdlib-only rule. Resolution: encryption is an **optional feature** — if no `KeyProvider` is configured, `secret`-labelled values are still *blocked from egress* (Phase 1 behavior) and simply not encrypted-at-rest. `LocalKeyProvider` requires `cryptography` as an optional dependency group (`pip install datasec[crypto]`). Do **not** hand-roll AES; if the lib is absent, degrade to "block-only, no at-rest encryption" and log that clearly.

**Where it plugs in:** a new sink behavior for `memory:write` of a `secret` value — encrypt the field before it is persisted, decrypt on authorized read. The pipeline records that encryption occurred in the audit entry (a flag, never the key or plaintext).

**Tests / red-team:** round-trip encrypt/decrypt; a `secret` written to memory is ciphertext at rest (assert plaintext absent from the store); with no provider configured, the secret is block-only and the degradation is audited; key rotation via `key_id` decrypts old ciphertext.

---

## 7. Audit-head checkpointing (§10.4)

**Why:** the hash chain proves entries were *edited* but not that the whole log was *replaced or truncated* — a known gap (R4g). Anchor the head out-of-band.

**Design (proportionate for a solo sandbox):**
- Write a **signed checkpoint** periodically and on clean shutdown: `{head, count, ts}` signed with a `KeyProvider` key (reuses §6). Store it separately from the JSONL log (different file with restricted perms, or a DB row).
- On startup, `AuditLog` verifies the chain **and** checks the latest signed checkpoint: head must match or be an ancestor with `count` consistent. Mismatch or missing-tail-past-checkpoint → refuse to start (fail closed), surfacing a tamper alert.
- `verify(expected_head=...)` already catches truncation when a head is supplied; the checkpoint is what *supplies* it automatically.

```python
# audit.py additions
class AuditLog:
    def checkpoint(self, signer: KeyProvider) -> SignedCheckpoint: ...
    @classmethod
    def load(cls, path, *, checkpoint: SignedCheckpoint | None = None, verifier=None) -> "AuditLog": ...
```
No external log service yet — revisit only if this leaves the sandbox.

**Tests / red-team:** promote R4g.1 (tail truncation) and R4g.2 (full-chain rewrite) from `known_gap` to `detected` **once a checkpoint exists** — a rewritten chain fails the signed-head check; a truncated tail past the checkpoint count fails. Tampering with the checkpoint file itself fails signature verification. (Per the red-team rules, flipping these labels is the whole point — do it with the fix, not before.)

---

## 8. Presidio behind the `Redactor` interface (§10.2 follow-on)

**Why:** the Phase 1 critical (card+CVV) showed regex coverage is inherently partial; known gaps R2g (spelled-out PII) need an NLP detector. Presidio adds entity recognition without changing the pipeline.

**Design:** a `PresidioRedactor` implementing the same `scan`/`redact` contract as the regex `Redactor`. Selectable by config; default stays the stdlib regex redactor so the base install is dependency-free and fast. Presidio is an optional dependency group.
- Keep the regex redactor as the fast path; optionally run Presidio as a second pass for higher recall on text sinks (`llm`, `http:response`) where latency is acceptable.
- Presidio's model download / init cost is startup-time, not per-request — document it.

**Tests / red-team:** with Presidio enabled, attempt to flip R2g.1/R2g.2 (spelled-out email/SSN) from `known_gap` to `redacted`; keep them as `known_gap` under the default regex redactor. Parity test: everything the regex redactor catches, Presidio also catches (no regression when switching).

---

## 9. Config surface (summary)

All new knobs, defaulting to fail-closed / Phase-1-compatible:

| Knob | Default | Effect |
|---|---|---|
| `PRIVILEGED_SOURCE_ALLOWLIST` | empty | which sources may reach privileged sinks despite low trust |
| `scan_integers` / `integer_fields` | False / none | opt-in integer PII scanning |
| `EGRESS_ALLOWLIST` | empty (deny destination-bearing egress) | permitted egress destinations |
| `max_bytes` / `max_depth` | 1 MB / 200 | payload caps |
| label case | lowercased | case-insensitive labels |
| `KeyProvider` | none (block-only, no at-rest encryption) | secret encryption backend |
| audit checkpoint | on shutdown + interval | out-of-band head anchor |
| redactor | regex (stdlib) | `PresidioRedactor` optional |

---

## 10. Definition of done

- All Phase 1 tests pass, except the specific ones §1/§2/§5 deliberately tighten (updated in the same commit that makes the change).
- Red-team corpus grows: EXTERNAL→privileged blocked; integer false-positive regression; egress-allowlist cases; label-case evasion; and R4g promoted to `detected` behind a checkpoint. `python -m redteam.runner` still exits 0 with `0 unexpected`.
- Every new feature degrades fail-closed when its optional dependency is absent (no crypto lib → block-only; no Presidio → regex only), and the degradation is audited/logged.
- `datasec` base install remains dependency-free; `datasec[crypto]` and `datasec[presidio]` add the optional backends.
- DESIGN.md §10 decisions 10.1, 10.4, 10.5, 10.6 are marked implemented.
