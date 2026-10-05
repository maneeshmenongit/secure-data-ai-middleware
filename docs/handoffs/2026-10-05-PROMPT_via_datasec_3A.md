# [2026-10-05] DataSec 3A — wire the security layer into Via behind VIA_DATASEC=1

You are in a **via-skelton** thread, on a branch the user created for this work. Build the Via side of DataSec Phase 3A: a per-project, shadow-first security layer that is **off by default**.

## 0. Read first, in order
1. Your own `via-onboard` skill (verify state mechanically) and your `via-code` skill.
2. This prompt, in full.
3. The DataSec spec. It lives in another repo; read it but do not edit it: `/Users/maneeshmenon/PycharmProjects/secure-data-ai-middleware/docs/superpowers/specs/2026-10-03-datasec-via-integration-design.md`.

## 1. Verified DataSec state (pinned)
| | |
|---|---|
| datasec commit | `cf62c48472424a67ff573776a1fd06b06dba7a6b` |
| datasec tests | 434 passed, 2 deselected, 8 xfailed |
| datasec red team | 79 passed, 8 known gaps, 0 skipped, 0 unexpected / 87 attacks |

**Install into Via's venv, not as a base dependency.** Via stays stdlib-only.
```
/Users/maneeshmenon/PycharmProjects/via-data/.venv-run/bin/python -m pip install \
  "datasec[crypto] @ git+file:///Users/maneeshmenon/PycharmProjects/secure-data-ai-middleware@cf62c48472424a67ff573776a1fd06b06dba7a6b"
```
- If that venv has no pip, use `uv pip install --python <that python> …` with the same spec.
- Presidio is optional and heavy, so don't install it. The bridge falls back to the regex redactor.
- If Via should declare the package, add it **only** as an optional extra (`datasec = [...]`), never to `dependencies`.

## 2. The DataSec API you call (do not re-implement)
```python
from datasec.adapters.gate import Mode, Blocked, check      # check(pipeline, action, payload, mode) -> payload
from datasec.pipeline import SecurityPipeline               # SecurityPipeline(engine=None, redactor=None, audit=None)
from datasec.policy import Action, PolicyEngine, default_rules   # Action(sink, name, provenance, destination=None)
from datasec.provenance import Provenance, Tainted, TrustLevel, combine  # combine(*Tainted, source=..., value=...)
from datasec.redaction import Redactor                      # regex; datasec.presidio.PresidioRedactor if installed
from datasec.audit import AuditLog                          # AuditLog(path, signer=..., checkpoint_path=...); .close()
from datasec.crypto import LocalKeyProvider                 # [crypto] extra
```
**The contract.** These are the review-verified behaviours at the pinned commit.
- `check(..., Mode.ENFORCE)`:
  - returns the guarded payload (redacted where needed), or
  - raises **`Blocked`**, whose `.decision.reason` / `str(exc)` are **already PII-redacted**, so it is safe to persist.
- `check(..., Mode.SHADOW)`:
  - is **only accepted for exactly `"tool:privileged"` and `"memory:write"`**;
  - audits the real decision as `mode=shadow` and returns the **original** payload;
  - **raises `ValueError` for every other sink**, including egress, misspellings like `"LLM"` and unknown sinks, and for **secret-labelled `memory:write`**.
- **Exceptions to handle:**
  - Catch **`Blocked` specifically** as the deny path.
  - **Do not** use a blanket `except DataSecError`. `DataSecError("audit append failed")` can come from **both** modes and must stay fatal (fail closed).
  - `ValueError`: a sink or mode was misconfigured. Rule this out at startup through profile validation; it should never fire per call.
  - `TypeError`: `mode` was not a `Mode`. Use `Mode("shadow")`; `"Shadow"` does not parse.
- **Egress allowlist** (`default_rules(egress_allowlist={hosts})`):
  - It compares **hostnames**, so pass `urllib.parse.urlparse(url).hostname` as `Action.destination`, never the full URL.
  - A `third_party` Action without a destination is denied.
- **No sealing in 3A.** Pass `LocalKeyProvider` only as the `AuditLog` signer. Do **not** pass `SecurityPipeline(key_provider=…)`. Via has no secret labels yet, and ENFORCE on a secret `memory:write` with a key provider returns a `Sealed` object, not the payload.
- Do not set `Action(shadow=…)` yourself. Use `check(..., Mode.SHADOW)`.
- **Report:** `python -m datasec.report <audit.jsonl> [--checkpoint P --key-env DATASEC_KEY_K1]`. It exits 1 if the log is broken or corrupt. Without `--checkpoint`, "VERIFIED" means the chain only; truncation is a known gap.

## 3. Global constraints
- **Off by default.** With `VIA_DATASEC` unset, Via behaves exactly as today and the full existing suite passes **unchanged**. Run it with the flag off before and after your changes.
- **Fail closed.** With `VIA_DATASEC=1`, Via must refuse to start, with a clear message, if any of these happen:
  - `datasec` can't be imported
  - the pipeline can't be built
  - a profile is invalid
  - a seam is missing
- **Egress is always enforced** (`llm`, `third_party`). Profiles may set only `tool:privileged` / `memory:write` to `enforce` or `shadow`. A profile that shadows egress is **invalid**.
- **Seam hooks only.** Wrap named functions; never patch by line number.
- **Only `via/security/datasec_bridge.py` imports `datasec`**, lazily, and only when the flag is on.
- **No live Via runs.** Use fakes for providers, transport and the PulseWise emitter. No network, no spend.
- Via's own rules apply:
  - RED→green for every mechanism and audit
  - signatures only for money or decisions
  - launch only via runner scripts
- Commit trailer: copy your session's attribution line verbatim.

## 4. Tasks (TDD: failing test, run red, implement, run green, commit)

**Task 0 — verify the seams first (no code).** For each sink, find the **current** function that every call of that kind passes through. The survey reported:

| Sink | Seam to wrap | Mode | On DENY |
|---|---|---|---|
| `llm` | `Substrate._do_call` before `provider.complete`; **plus** the direct path in `review/gate.py` (`tier1_review`) | enforce | raise into Via's existing provider-error path (`Blocked` is safe to stringify) |
| `tool:privileged` | `Engine._execute_step`, right after `gate.assess` (WriteFile/AppendFile/ReplaceInFile/RunCommand) | shadow (a profile may set enforce) | shadow: never blocks |
| `memory:write` | `MemoryStore.append` and `supersede` | shadow (a profile may set enforce) | shadow: never blocks |
| `third_party` | `UrllibTransport.post` (destination = hostname, empty payload); `pulsewise._post` (payload redacted) | enforce | transport: raise into its error path. PulseWise: drop the event, audited |

If a sink has more than one entry path, hook all of them or lift the hook to a common caller. Record the confirmed names in `INTEGRATION.md`.

**Task 1 — `via/security/datasec_bridge.py` and profiles.**
- `enabled()` returns true when `VIA_DATASEC=1`.
- `build_pipeline(project)` assembles the pipeline:
  - **Redactor:** `PresidioRedactor` if importable, else `Redactor`.
  - **Audit log:** `data/datasec/<safe project dir>/audit.jsonl`. `$VIA_DATASEC_DIR` overrides the root.
  - **Checkpoint:** `AuditLog(..., signer=LocalKeyProvider({"k1": key}), checkpoint_path=…)` **only** when `DATASEC_KEY_K1` is set and `cryptography` imports. Otherwise the log is chain-only and logs one warning.
  - **Rules:** `default_rules(egress_allowlist=` the provider hosts, plus the PulseWise host when `VIA_PULSEWISE_ENDPOINT` is set`)`.
- **Trust table**, one table in this module:

  | Via source | TrustLevel | source |
  |---|---|---|
  | memory row `principal`; principal hints | USER | `principal` |
  | `via`, `genesis`; workspace files Via wrote | INTERNAL | `via` / `genesis` / `workspace` |
  | referee/sweep stdout-stderr; consultant replies; rows `tool`, `external` | EXTERNAL | `tool:referee` / `llm:consultant` / `tool` / `external` |
  | brownfield host-repo files; rows `web` | UNTRUSTED | `repo:host` / `web` |

- **Profile** `data/datasec/<project>.json` is optional. It may contain:
  - `modes`: only for `tool:privileged` / `memory:write`
  - `trust_overrides`
  - `egress_allowlist`
  - `presidio`: `true` / `false` / `auto`

  An invalid profile is a startup error. **That includes one that names an egress sink in `modes`.**
- **Tests:**
  - `enabled()` reads the env.
  - Each project gets its own log dir.
  - A project with no profile gets the defaults.
  - Project A with `"tool:privileged":"enforce"` enforces while project B stays shadow.
  - An egress-shadow profile raises.
  - With no key, the log is chain-only and the warning fires once.

**Task 2 — prompt provenance and insertion-site tagging.**
- `Message` gains `provenance: Provenance | None = None`. `None` means INTERNAL. `Message` is frozen, so build new Messages and never mutate one.
- Enumerate **every** site that inserts referee or sweep output, consultant replies, host-repo files or memory rows into a prompt. At each one, set `provenance` to the `combine(...)` of the parts.
- **Tests:**
  - One per site: referee output gives EXTERNAL, a host-repo file gives UNTRUSTED, and via/principal-only content stays INTERNAL/USER.
  - A **parametrized regression guard** over the known sites, so that a future untagged site fails.

**Task 3 — seam hooks and the bypass test.**
- **Bridge helpers:**
  - `guard_prompt(messages, purpose) -> new messages` (ENFORCE)
  - `shadow_actions(actions, plan_provenance)` (mode from the profile)
  - `shadow_memory_write(kind, provenance, content)`
  - `check_destination(url)` (ENFORCE; hostname only)
  - `guard_pulsewise(payload) -> payload` (ENFORCE)
- **Tests**, with the flag on and fakes:
  - PII is redacted before the fake provider sees it.
  - A secret blocks via the error path, and the stored error text has no raw PII.
  - An EXTERNAL-derived `RunCommand` is audited as a shadow DENY **and still executes**.
  - A memory write is audited with the mapped trust.
  - An unknown host is refused and a known host passes.
  - **Bypass test:** with the flag on, a provider call that skips `guard_prompt` must fail. For example, use a per-call token that the provider wrapper checks, or replace the unwrapped provider at bridge init.

**Task 4 — PulseWise run-close summary.**
- At run close (next to `_audit_after_run`), call `PulseWiseEmitter.from_env().emit(content=…, frame=f"{project}/security", run_id=…)`.
- **Compute your own counts**, and **never forward `datasec.report.summarize()` output**, because it is keyed by source. Send:
  - sink × effect × mode
  - shadow denials by **rule**
  - redactions by **label** (from each entry's `tally`)
  - `chain_verified`

  Send **no** payload text, sources or names. It is a no-op when the emitter is disabled.
- Verify the `content` shape against `to_pulse_event`. Don't change PulseWise.

**Task 5 — `INTEGRATION.md`.** Cover:
- the flag
- the env vars: `VIA_DATASEC`, `VIA_DATASEC_DIR`, `DATASEC_KEY_K1`, `VIA_PULSEWISE_ENDPOINT`
- the modes, and that egress is always enforced
- the trust table
- the confirmed seams from Task 0
- the install line
- the exception contract from §2
- how to read `python -m datasec.report`
- how to flip a tool or memory sink to enforce via a profile

## 5. Done
- With the flag off, Via's full suite is unchanged.
- With the flag on, all new tests pass, including the bypass test and the per-site provenance tests.
- No live runs happened. Nothing merged without the user's review.
- **Hand back:**
  - the files changed
  - the confirmed seam table
  - test counts with the flag off and on
  - anything that didn't fit, especially any place the §2 contract was awkward to use

## 6. Then the user (manual, after review)
1. Make one real `via run` on a throwaway project with `VIA_DATASEC=1`. Keys unset is fine.
2. Run `python -m datasec.report data/datasec/<project>/audit.jsonl` and review the **shadow denials**. They are the trust-table tuning input, and the evidence on location-redaction false positives.
3. Keep tool and memory in shadow until that review is done.

## Traps
- **The bypass path.** An `llm` call that goes around `Substrate` (`review/gate.py`) is the classic fail-open. Hook it too.
- **Shadow must return the original payload.** Returning a redacted one changes Via's behaviour before anyone decided it should.
- **Project keys.** Via's store may key projects by **full workspace path**. Use the run's `args.project` for the audit directory, sanitised to a safe directory name, and the same key for its profile.
- **`except DataSecError`** would swallow audit-write failures, which must stay fatal. Catch `Blocked`.
