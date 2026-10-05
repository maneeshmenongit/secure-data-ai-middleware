# DataSec Phase 3A — Via Host Integration — Final Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the DataSec side of the Via integration in this repo: the shadow marker, `adapters.gate`, the report CLI, red-team attacks and the DESIGN note. Then hand the Via side over as a self-contained prompt, pinned to the resulting commit.

**Architecture:**
- **Shadow marker:** `Action.shadow` only marks the audit entry (`extra.mode = "shadow"`). It never changes the decision.
- **`gate.check()`:** the one call an adapter makes. ENFORCE returns the guarded payload or raises `Blocked`. SHADOW records the real decision and returns the original payload, and is refused on egress sinks.
- **`python -m datasec.report`:** verifies an audit log and summarises it.
- **Via side:** all Via changes (bridge, trust table, profiles, seam hooks, provenance tagging, PulseWise summary) are **not made here**. Task 6 writes them up as `docs/handoffs/…PROMPT…md` for a Via thread, per the user's decision of 2026-10-04.

**Tech Stack:** Python ≥3.11, stdlib core, `uv`, pytest.

**Spec:** [docs/superpowers/specs/2026-10-03-datasec-via-integration-design.md](../specs/2026-10-03-datasec-via-integration-design.md) (approved 2026-10-04). **Source draft:** the user's `docs_to_claude/design/phase3/2026-10-04-datasec-via-3A-implementation.md`, merged here with the 2026-10-04 review fixes.

## Global Constraints

- **Never edit `~/PycharmProjects/via-skelton` from this repo.** Reading it is allowed. Via work goes into the handoff prompt (Task 6).
- `src/datasec` stays stdlib-only (`dependencies = []`). All new options default to the old behaviour.
- **Egress (`llm`, `third_party`) is always enforced.** Shadow mode is only for `tool:privileged` and `memory:write`, and egress shadow is refused. This is the user's decision of 2026-10-04, and it is enforced in code here (Task 2) and in Via's profile validation (Task 6).
- Fail closed. Audit entries never contain payloads or raw PII.
- Sync only with `uv sync --extra presidio --group presidio-model --group webapp`.
- Every new control ships with a red-team attack (Task 4).
- Commit trailer: copy the attribution line from the session's system reminder verbatim, passed as a second `-m`. Never invent a model name.
- Never push or merge without the user choosing it.

## Review Focus

1. A caller that pre-sets `Action(shadow=True)` on an **egress** action through `pipeline.guard` must still be denied or redacted. `shadow` is an audit marker, never a decision input → Task 1 `test_shadow_flag_never_changes_the_decision`.
2. `check(..., Mode.ENFORCE)` with a caller-supplied `shadow=True` must audit as enforce, not shadow → Task 2 `test_enforce_strips_caller_shadow_flag`.
3. SHADOW on an egress sink must raise before anything is audited or returned → Task 2 `test_shadow_on_egress_is_refused`.
4. The report must exit non-zero on a corrupt (unparseable) log, not only on a hash mismatch → Task 3 `test_corrupt_log_is_broken`.
5. Old audit logs (entries without `extra.mode`) must summarise as `enforce` → Task 3 `test_entries_without_mode_count_as_enforce`.

---

### Task 1: Shadow marker

**Files:** Modify `src/datasec/policy.py` (`Action`) and `src/datasec/pipeline.py` (`guard`). Test: `tests/test_pipeline.py`.

**Interfaces:**
- Produces:
  - `Action(..., destination=None, scan_integers=False, shadow: bool = False)`. The new field goes last, which keeps it back-compatible.
  - An audit entry for a shadow action has `extra["mode"] == "shadow"`. `AuditEntry.extra` already exists from Phase 2 and is excluded from the hash when empty, so it is not re-added.

- [ ] **Step 1: Write the failing tests.** Append to `tests/test_pipeline.py`:
```python


def test_shadow_deny_is_marked_and_still_denied():
    p = SecurityPipeline()
    r = p.guard(Action("tool:privileged", "pay", WEB, shadow=True), "wire money")
    assert not r.allowed and r.payload is None
    assert r.decision.rule == "no_low_trust_to_privileged"
    assert last(p).extra == {"mode": "shadow"}


def test_non_shadow_entries_have_no_mode():
    p = SecurityPipeline()
    p.guard(Action("llm", "chat", SVC), "hi")
    assert "mode" not in last(p).extra


def test_shadow_flag_never_changes_the_decision():
    secret = internal("", source="vault", labels="secret").provenance
    for shadow in (False, True):
        p = SecurityPipeline()
        r = p.guard(Action("llm", "chat", secret, shadow=shadow), "sk-test-FAKE")
        assert not r.allowed and r.decision.rule == "never_leak_secrets"
        r = p.guard(Action("llm", "chat", USER, shadow=shadow), "mail jane@example.com")
        assert r.payload == "mail [EMAIL]"


def test_shadow_entries_keep_the_chain_verifiable(tmp_path):
    path = tmp_path / "audit.jsonl"
    p = SecurityPipeline(audit=AuditLog(path))
    p.guard(Action("tool:privileged", "pay", WEB, shadow=True), "x")
    p.guard(Action("llm", "chat", SVC), "y")
    assert AuditLog.load(path).verify(expected_head=p.audit.head)
```
- [ ] **Step 2: Run red.** `uv run pytest tests/test_pipeline.py -q 2>&1 | tail -3`. Expected: 4 failures with `TypeError: Action.__init__() got an unexpected keyword argument 'shadow'`.
- [ ] **Step 3: Implement.**
  - In `src/datasec/policy.py`, add `shadow: bool = False` as the last field of `Action`, directly after `scan_integers: bool = False`.
  - In `src/datasec/pipeline.py` `guard`, directly after the `if action.destination is not None:` block, add:
```python
        if action.shadow:
            extra = {**extra, "mode": "shadow"}  # audit marker only; the decision is unchanged
```
- [ ] **Step 4: Run green.** `uv run pytest -q 2>&1 | tail -1 && uv run python -m redteam.runner | tail -1`. Expected: 0 failed, and `0 unexpected / 81 attacks`.
- [ ] **Step 5: Commit.**
```bash
git add src/datasec/policy.py src/datasec/pipeline.py tests/test_pipeline.py
git commit -m "feat: Action.shadow marks audit entries; never changes the decision" -m "<attribution line from the system reminder>"
```

---

### Task 2: `datasec.adapters.gate`

**Files:** Create `src/datasec/adapters/__init__.py` and `src/datasec/adapters/gate.py`. Test: `tests/test_gate.py`.

**Interfaces:**
- Consumes: `SecurityPipeline.guard`, `Action.shadow` (Task 1) and `EGRESS`.
- Produces:
  - `Mode` (`ENFORCE`, `SHADOW`)
  - `Blocked(DataSecError)` with `.decision`
  - `check(pipeline, action, payload, mode) -> Any`. A non-`Mode` mode raises `TypeError`. SHADOW on an egress sink raises `ValueError`.

- [ ] **Step 1: Write the failing tests.** Create `tests/test_gate.py`:
```python
import pytest

from datasec.adapters.gate import Blocked, Mode, check
from datasec.pipeline import SecurityPipeline
from datasec.policy import Action
from datasec.provenance import from_user, internal, untrusted

USER = from_user("", source="user:1").provenance
WEB = untrusted("", source="web:evil").provenance
SVC = internal("", source="svc").provenance


def last(p):
    return list(p.audit)[-1]


def test_enforce_returns_redacted_payload():
    assert check(SecurityPipeline(), Action("llm", "chat", USER), "mail jane@example.com", Mode.ENFORCE) == "mail [EMAIL]"


def test_enforce_allow_returns_same_object():
    payload = {"q": "hi"}
    assert check(SecurityPipeline(), Action("llm", "chat", SVC), payload, Mode.ENFORCE) is payload


def test_enforce_deny_raises_blocked_with_decision():
    with pytest.raises(Blocked) as exc:
        check(SecurityPipeline(), Action("tool:privileged", "pay", WEB), "wire", Mode.ENFORCE)
    assert exc.value.decision.rule == "no_low_trust_to_privileged"


def test_shadow_returns_original_and_audits_real_decision():
    p = SecurityPipeline()
    payload = ["wire money"]
    assert check(p, Action("tool:privileged", "pay", WEB), payload, Mode.SHADOW) is payload
    assert last(p).effect == "deny" and last(p).extra == {"mode": "shadow"}


def test_shadow_memory_write_returns_original_even_with_pii():
    p = SecurityPipeline()
    payload = "remember jane@example.com"
    assert check(p, Action("memory:write", "note", USER), payload, Mode.SHADOW) is payload
    assert last(p).extra == {"mode": "shadow"}


@pytest.mark.parametrize("sink", ["llm", "third_party", "http:response"])
def test_shadow_on_egress_is_refused(sink):
    p = SecurityPipeline()
    with pytest.raises(ValueError):
        check(p, Action(sink, "x", USER), "jane@example.com", Mode.SHADOW)
    assert len(p.audit) == 0


def test_enforce_strips_caller_shadow_flag():
    p = SecurityPipeline()
    check(p, Action("llm", "chat", SVC, shadow=True), "hi", Mode.ENFORCE)
    assert "mode" not in last(p).extra


def test_mode_must_be_a_mode():
    with pytest.raises(TypeError):
        check(SecurityPipeline(), Action("llm", "chat", SVC), "hi", "shadow")
```
- [ ] **Step 2: Run red.** `uv run pytest tests/test_gate.py -q 2>&1 | grep -m1 "^E  "`. Expected: `ModuleNotFoundError: No module named 'datasec.adapters'`.
- [ ] **Step 3: Implement.** Create `src/datasec/adapters/__init__.py`:
```python
"""Integration helpers for hosts that call the DataSec pipeline (e.g. Via)."""
```
Create `src/datasec/adapters/gate.py`:
```python
"""One call for adapters: enforce a decision, or audit it in shadow mode without acting on it."""

from __future__ import annotations

from dataclasses import replace
from enum import Enum
from typing import Any

from ..errors import DataSecError
from ..pipeline import SecurityPipeline
from ..policy import EGRESS, Action, Decision


class Mode(Enum):
    ENFORCE = "enforce"
    SHADOW = "shadow"


class Blocked(DataSecError):
    """An ENFORCE check denied the action; `.decision` says why."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(f"blocked by datasec: {decision.reason}")
        self.decision = decision


def check(pipeline: SecurityPipeline, action: Action, payload: Any, mode: Mode) -> Any:
    """Return the payload the caller should use.

    ENFORCE: ALLOW/REDACT -> the guarded payload; DENY -> raise Blocked.
    SHADOW: audit the real decision (marked mode=shadow) and return the ORIGINAL payload,
    so behaviour is unchanged while the decision is observed. Egress sinks are never
    shadowed: PII redaction and secret blocking can't be switched off.
    """
    if not isinstance(mode, Mode):
        raise TypeError(f"mode must be a Mode, got {type(mode).__name__}")
    if mode is Mode.SHADOW:
        if action.sink in EGRESS:
            raise ValueError(f"egress sink {action.sink!r} is always enforced; shadow refused")
        pipeline.guard(replace(action, shadow=True), payload)
        return payload
    result = pipeline.guard(replace(action, shadow=False), payload)
    if not result.allowed:
        raise Blocked(result.decision)
    return result.payload
```
- [ ] **Step 4: Run green.** `uv run pytest tests/test_gate.py -q 2>&1 | tail -1`. Expected: 10 passed. Then the full suite: 0 failed.
- [ ] **Step 5: Commit.**
```bash
git add src/datasec/adapters tests/test_gate.py
git commit -m "feat: adapters.gate check() — enforce, or shadow (never on egress)" -m "<attribution line from the system reminder>"
```

---

### Task 3: `python -m datasec.report`

**Files:** Create `src/datasec/report.py`. Test: `tests/test_report.py`.

**Interfaces:**
- Produces:
  - `summarize(entries) -> dict` with the keys `by_sink_effect_mode`, `deny_reasons` and `shadow_denials`
  - `main(argv=None) -> int`, which returns 0 when the log verifies and 1 when it is broken or corrupt
  - Usage: `python -m datasec.report <audit.jsonl> [--checkpoint PATH --key-env NAME]`. The key env var holds the Fernet key and needs the `crypto` extra.

- [ ] **Step 1: Write the failing tests.** Create `tests/test_report.py`:
```python
import json

import pytest

from datasec.adapters.gate import Mode, check
from datasec.audit import AuditLog
from datasec.pipeline import SecurityPipeline
from datasec.policy import Action
from datasec.provenance import Provenance, TrustLevel, from_user, untrusted
from datasec.report import main, summarize


def build_log(path):
    p = SecurityPipeline(audit=AuditLog(path))
    ext = Provenance(TrustLevel.EXTERNAL, "tool:referee")
    for _ in range(2):
        check(p, Action("tool:privileged", "RunCommand", ext), ["python", "x.py"], Mode.SHADOW)
    check(p, Action("llm", "plan", from_user("", source="principal").provenance), "mail jane@example.com", Mode.ENFORCE)
    p.guard(Action("tool:privileged", "pay", untrusted("", source="web").provenance), "wire")
    return p


def test_summary_counts(tmp_path):
    p = build_log(tmp_path / "a.jsonl")
    s = summarize(list(p.audit))
    assert s["by_sink_effect_mode"][("tool:privileged", "deny", "shadow")] == 2
    assert s["by_sink_effect_mode"][("llm", "redact", "enforce")] == 1
    assert s["by_sink_effect_mode"][("tool:privileged", "deny", "enforce")] == 1
    assert s["shadow_denials"][("tool:privileged", "tool:referee")] == 2


def test_main_good_log(tmp_path, capsys):
    build_log(tmp_path / "a.jsonl")
    assert main([str(tmp_path / "a.jsonl")]) == 0
    out = capsys.readouterr().out
    assert "chain: VERIFIED" in out and "tool:referee" in out
    assert "jane@example.com" not in out


def test_tampered_log_is_broken(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    build_log(path)
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["effect"] = "allow"
    lines[0] = json.dumps(first, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    assert main([str(path)]) == 1
    assert "chain: BROKEN" in capsys.readouterr().out


def test_corrupt_log_is_broken(tmp_path, capsys):
    path = tmp_path / "a.jsonl"
    path.write_text("not json\n")
    assert main([str(path)]) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_entries_without_mode_count_as_enforce(tmp_path):
    p = SecurityPipeline()
    p.guard(Action("llm", "chat", from_user("", source="u").provenance), "hi")
    assert summarize(list(p.audit))["by_sink_effect_mode"][("llm", "allow", "enforce")] == 1


def test_checkpoint_verification(tmp_path, monkeypatch, capsys):
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet

    from datasec.crypto import LocalKeyProvider

    key = Fernet.generate_key()
    monkeypatch.setenv("DATASEC_KEY_K1", key.decode())
    path, cp = tmp_path / "a.jsonl", tmp_path / "a.checkpoint"
    log = AuditLog(path, signer=LocalKeyProvider({"k1": key}), checkpoint_path=cp)
    SecurityPipeline(audit=log).guard(Action("llm", "chat", from_user("", source="u").provenance), "hi")
    log.close()
    args = [str(path), "--checkpoint", str(cp), "--key-env", "DATASEC_KEY_K1"]
    assert main(args) == 0 and "checkpoint: VERIFIED" in capsys.readouterr().out
    path.write_text("")  # truncate everything after the checkpoint was written
    assert main(args) == 1 and "checkpoint: BROKEN" in capsys.readouterr().out
```
- [ ] **Step 2: Run red.** `uv run pytest tests/test_report.py -q 2>&1 | grep -m1 "^E  "`. Expected: `ModuleNotFoundError: No module named 'datasec.report'`.
- [ ] **Step 3: Implement.** Create `src/datasec/report.py`:
```python
"""Summarise a DataSec audit log: python -m datasec.report <audit.jsonl> [--checkpoint P --key-env NAME]

Verifies the chain (and a signed checkpoint when given) before summarising, and exits 1 when
the log is broken. Prints only the fields the log stores; the log never holds payloads.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from typing import Iterable

from .audit import AuditEntry, AuditLog, SignedCheckpoint
from .errors import DataSecError


def _mode(e: AuditEntry) -> str:
    return e.extra.get("mode", "enforce")  # entries from before shadow mode are enforce


def summarize(entries: Iterable[AuditEntry]) -> dict:
    by: Counter = Counter()
    reasons: Counter = Counter()
    shadow: Counter = Counter()
    for e in entries:
        by[(e.sink, e.effect, _mode(e))] += 1
        if e.effect == "deny":
            reasons[(e.reason, e.rule)] += 1
            if _mode(e) == "shadow":
                shadow[(e.sink, e.source)] += 1
    return {"by_sink_effect_mode": by, "deny_reasons": reasons, "shadow_denials": shadow}


def _checkpoint_status(log: AuditLog, cp_path: str, key_env: str) -> bool:
    from .crypto import LocalKeyProvider  # needs the crypto extra

    cp = SignedCheckpoint.read(cp_path)
    key = os.environ.get(key_env)
    if not key:
        raise DataSecError(f"env var {key_env} is not set")
    return log.verify(checkpoint=cp, verifier=LocalKeyProvider({cp.key_id: key.encode()}))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m datasec.report", description="Summarise a DataSec audit log")
    ap.add_argument("log")
    ap.add_argument("--checkpoint")
    ap.add_argument("--key-env")
    args = ap.parse_args(argv)
    try:
        log = AuditLog.load(args.log)
    except (DataSecError, OSError) as exc:
        print(f"audit: {args.log}\nchain: BROKEN ({type(exc).__name__}: unreadable log)")
        return 1
    ok = log.verify()
    line = f"audit: {args.log}  entries: {len(log)}  chain: {'VERIFIED' if ok else 'BROKEN'}"
    if args.checkpoint:
        try:
            cp_ok = _checkpoint_status(log, args.checkpoint, args.key_env or "DATASEC_KEY_K1")
        except DataSecError as exc:
            cp_ok = False
            line += f"  ({exc})"
        ok = ok and cp_ok
        line += f"  checkpoint: {'VERIFIED' if cp_ok else 'BROKEN'}"
    print(line)
    s = summarize(log)
    print("\ndecisions (sink / effect / mode):")
    for (sink, effect, mode), n in sorted(s["by_sink_effect_mode"].items()):
        print(f"  {sink:18} {effect:7} {mode:8} {n}")
    print("\ntop deny reasons:")
    for (reason, rule), n in s["deny_reasons"].most_common(10):
        print(f"  {n:4}  {reason}  [{rule}]")
    print("\nshadow denials (sink / source) — false-positive candidates to review:")
    for (sink, source), n in s["shadow_denials"].most_common():
        print(f"  {sink:18} {source:24} {n}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
```
- [ ] **Step 4: Run green.** `uv run pytest tests/test_report.py -q 2>&1 | tail -1`. Expected: 6 passed. Then the full suite (0 failed) and `uv run python -m datasec.report --help` (prints usage).
- [ ] **Step 5: Commit.**
```bash
git add src/datasec/report.py tests/test_report.py
git commit -m "feat: python -m datasec.report — verify then summarise an audit log" -m "<attribution line from the system reminder>"
```

---

### Task 4: Red-team attacks for the new controls

**Files:** Modify `redteam/attacks/failclosed.py` and `redteam/attacks/audit_tamper.py`.

- [ ] **Step 1: Add the attacks (red first).**

  In `redteam/attacks/failclosed.py`, add the imports `from datasec.adapters.gate import Blocked, Mode, check` and `from datasec.policy import Action`, and change the provenance import to `from datasec.provenance import from_user, internal, untrusted`. Add these functions above `ATTACKS`:
```python
def _shadow_on_egress():
    p = SecurityPipeline()
    try:
        out = check(p, Action("llm", "chat", from_user("", source="u").provenance), "mail jane@example.com", Mode.SHADOW)
    except ValueError:
        return "blocked"
    return "leaked" if "jane@example.com" in str(out) else "allowed"


def _caller_shadow_flag_on_egress():
    secret = internal("sk-test-FAKE", source="vault", labels="secret")
    r = SecurityPipeline().guard(Action("llm", "chat", secret.provenance, shadow=True), secret.value)
    return outcome(r)


def _enforce_gate_blocks():
    try:
        check(SecurityPipeline(), Action("tool:privileged", "pay", untrusted("", source="web:evil").provenance),
              "wire", Mode.ENFORCE)
    except Blocked:
        return "blocked"
    return "allowed"
```
  Then append these to `ATTACKS`:
```python
    Attack("R5.10", "fail_closed", "LLM02", "ask the gate to shadow an egress sink (llm) to skip redaction",
           _shadow_on_egress, "blocked"),
    Attack("R5.11", "fail_closed", "LLM02", "pre-set Action.shadow on a secret headed to the llm",
           _caller_shadow_flag_on_egress, "blocked"),
    Attack("R5.12", "fail_closed", "LLM06", "untrusted data through the ENFORCE gate to a privileged tool",
           _enforce_gate_blocks, "blocked"),
```
  In `redteam/attacks/audit_tamper.py`, add this above `ATTACKS`:
```python
def _report_flags_tampering():
    from datasec.report import main as report_main

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "audit.jsonl"
        p = SecurityPipeline(audit=AuditLog(path))
        _record_three(p)
        lines = path.read_text().splitlines()
        first = json.loads(lines[0])
        first["effect"] = "allow"
        lines[0] = json.dumps(first, sort_keys=True)
        path.write_text("\n".join(lines) + "\n")
        import contextlib
        import io

        with contextlib.redirect_stdout(io.StringIO()):
            code = report_main([str(path)])
        return "detected" if code != 0 else "undetected"
```
  and append this to `ATTACKS`:
```python
    Attack("R4.13", "audit_tampering", "n/a", "flip a denial to allow and see if the report notices",
           _report_flags_tampering, "detected"),
```
- [ ] **Step 2: Run.** `uv run pytest tests/test_redteam.py -q 2>&1 | tail -1 && uv run python -m redteam.runner | grep -E "R5.1[012]|R4.13|attacks$"`. Expected: all four `pass`, and `77 passed, 8 known gaps, 0 skipped, 0 unexpected / 85 attacks`. These attacks pin controls built in Tasks 1–3. To see each one RED, temporarily remove the egress check in `gate.check` and watch R5.10 turn `leaked`, then restore it.
- [ ] **Step 3: Commit.**
```bash
git add redteam/attacks/failclosed.py redteam/attacks/audit_tamper.py
git commit -m "test: red-team attacks for shadow mode, the enforce gate and the report" -m "<attribution line from the system reminder>"
```

---

### Task 5: DESIGN.md — Phase 3 split, §10.7

**Files:** Modify `DESIGN.md`.

- [ ] **Step 1: Edit.**
  - Replace line 212, which begins `4. **Via adapters (Phase 3)**`, with:
    `4. **Via integration (Phase 3)** — three sub-projects: **A** Via as host (per-project profiles, PulseWise metrics; DataSec side built, Via side handed over as a prompt — spec \`docs/superpowers/specs/2026-10-03-datasec-via-integration-design.md\`), **B** LangGraph adapter piloted on \`paper-trader\`, **C** ASGI adapter.`
  - Directly under the heading `## 6. Via integration (thin adapters — phase 3)`, insert:
    `> **2026-10-04:** Via has no HTTP server or LangGraph of its own; it is a host that runs many projects that do. §6 is superseded by Phase 3 A/B/C (see §8 and the 3A spec). Via code is never edited from this repo.`
  - In the line beginning `- **10.7 Provenance persistence — [open, owner: Phase 3].**`, change `[open, owner: Phase 3]` to `[partly answered, Phase 3A]` and append: ` Via memory rows already carry \`provenance\`; prompts carry it in memory via \`Message.provenance\` (3A).`
- [ ] **Step 2: Verify.** `grep -n "Via integration (Phase 3)\|superseded by Phase 3\|partly answered, Phase 3A" DESIGN.md` prints 3 lines.
- [ ] **Step 3: Commit.**
```bash
git add DESIGN.md
git commit -m "docs: DESIGN Phase 3 split into A/B/C; §10.7 partly answered" -m "<attribution line from the system reminder>"
```

---

### Task 6: The Via handoff prompt

**Files:** Create `docs/handoffs/2026-10-05-PROMPT_via_datasec_3A.md`.

- [ ] **Step 1: Pin the commit.** Run `git rev-parse HEAD` and use the full SHA wherever the prompt below says `DATASEC_SHA`. Verify it first: `uv run pytest -q | tail -1` and `uv run python -m redteam.runner | tail -1` must be green at that SHA. Record both lines in the prompt's state table.
- [ ] **Step 2: Write the prompt** with exactly this content, with `DATASEC_SHA` and the two verified lines substituted:
````markdown
# [2026-10-05] DataSec 3A — wire the security layer into Via behind VIA_DATASEC=1

You are in a **via-skelton** thread. The user has created this branch for the work. Build the Via side of DataSec Phase 3A: a per-project, shadow-first security layer, **off by default**.

## 0. Read first, in order
1. Your own `via-onboard` skill (verify state mechanically) and `via-code` skill.
2. This prompt, in full.
3. The DataSec spec (read-only, in another repo): `/Users/maneeshmenon/PycharmProjects/secure-data-ai-middleware/docs/superpowers/specs/2026-10-03-datasec-via-integration-design.md`.

## 1. Verified DataSec state (pinned)
| | |
|---|---|
| datasec commit | `DATASEC_SHA` |
| datasec tests | <pytest line from Step 1> |
| datasec red team | <runner line from Step 1> |

**Install into Via's venv, not as a base dependency** (Via stays stdlib-only):
```
/Users/maneeshmenon/PycharmProjects/via-data/.venv-run/bin/python -m pip install \
  "datasec[crypto] @ git+file:///Users/maneeshmenon/PycharmProjects/secure-data-ai-middleware@DATASEC_SHA"
```
(If that venv has no pip, use `uv pip install --python <that python> …` with the same spec.) Presidio is optional and heavy, so don't install it. The bridge falls back to the regex redactor. If you want Via to declare it, add it **only** as an optional extra (`datasec = [...]`), never to `dependencies`.

## 2. The DataSec API you call (do not re-implement)
```python
from datasec.adapters.gate import Mode, Blocked, check      # check(pipeline, action, payload, mode) -> payload
from datasec.pipeline import SecurityPipeline               # SecurityPipeline(engine=None, redactor=None, audit=None, *, key_provider=None)
from datasec.policy import Action, PolicyEngine, default_rules   # Action(sink, name, provenance, destination=None, scan_integers=False, shadow=False)
from datasec.provenance import Provenance, TrustLevel, combine   # combine(*tainted, source=..., value=...) -> weakest trust, union labels
from datasec.redaction import Redactor                      # regex; datasec.presidio.PresidioRedactor if installed
from datasec.audit import AuditLog                          # AuditLog(path, signer=..., checkpoint_path=...) ; .close()
from datasec.crypto import LocalKeyProvider                 # needs the [crypto] extra
```
- `check(..., Mode.ENFORCE)`: returns the redacted payload, or raises `Blocked` (`.decision.reason`).
- `check(..., Mode.SHADOW)`: audits the real decision as `mode=shadow` and returns the **original** payload. It **raises `ValueError` for egress sinks** (`llm`, `third_party`, `http:response`).
- `default_rules(egress_allowlist={hosts})`: a `third_party` Action must carry `destination=<host>`.
- Report: `python -m datasec.report <audit.jsonl> [--checkpoint P --key-env DATASEC_KEY_K1]`.

## 3. Global constraints
- **Off by default.** With `VIA_DATASEC` unset, Via behaves exactly as today and the full existing suite passes **unchanged**. Run it with the flag off before and after.
- **Fail closed.** With `VIA_DATASEC=1`, an unimportable `datasec`, an unbuildable pipeline, an invalid profile or a missing seam → Via refuses to start with a clear message.
- **Egress is always enforced** (`llm`, `third_party`). Profiles may set `tool:privileged` / `memory:write` to `enforce` or `shadow` only. A profile that shadows egress is **invalid**.
- **Seam hooks only.** Wrap named functions; never patch by line number.
- **Only `via/security/datasec_bridge.py` imports `datasec`,** lazily, when the flag is on.
- **No live Via runs.** Use fakes for providers, transport and the PulseWise emitter. No network, no spend.
- Via's own rules apply: RED→green for every mechanism and audit; signatures only for money or decisions; launch only via runner scripts.
- Commit trailer: copy your session's attribution line verbatim.

## 4. Tasks (TDD: failing test, red, implement, green, commit)

**Task 0 — verify the seams first (no code).** For each sink, find the **current** function every call of that kind passes through. The survey said:

| Sink | Seam to wrap | Mode | On DENY |
|---|---|---|---|
| `llm` | `Substrate._do_call` before `provider.complete`; plus the direct path in `review/gate.py` (`tier1_review`) | enforce | raise into Via's existing provider-error path |
| `tool:privileged` | `Engine._execute_step` right after `gate.assess` (WriteFile/AppendFile/ReplaceInFile/RunCommand) | shadow (profile may enforce) | shadow: never blocks |
| `memory:write` | `MemoryStore.append` and `supersede` | shadow (profile may enforce) | shadow: never blocks |
| `third_party` | `UrllibTransport.post` (destination allowlist, empty payload); `pulsewise._post` (payload redacted) | enforce | transport: raise into its error path; PulseWise: drop the event, audited |

If a sink has more than one entry path, hook all of them or lift the hook to a common caller. Record the confirmed names in `INTEGRATION.md`.

**Task 1 — `via/security/datasec_bridge.py` and profiles.**
- Provide `enabled()`.
- Provide `build_pipeline(project)`. It uses `PresidioRedactor` if importable, else `Redactor`. The audit log goes at `data/datasec/<project>/audit.jsonl`, and `$VIA_DATASEC_DIR` overrides the root. A checkpoint is written **only** when `DATASEC_KEY_K1` is set and `cryptography` imports; otherwise the log is chain-only with one warning. Pass `default_rules(egress_allowlist=` the provider hosts, plus the PulseWise host when `VIA_PULSEWISE_ENDPOINT` is set`)`.
- The trust table is one table in this module:

| Via source | TrustLevel | source |
|---|---|---|
| memory row `principal`; principal hints | USER | `principal` |
| `via`, `genesis`; workspace files Via wrote | INTERNAL | `via` / `genesis` / `workspace` |
| referee/sweep stdout-stderr; consultant replies; rows `tool`, `external` | EXTERNAL | `tool:referee` / `llm:consultant` / `tool` / `external` |
| brownfield host-repo files; rows `web` | UNTRUSTED | `repo:host` / `web` |

- Profile `data/datasec/<project>.json` (optional) can set:
  - `modes`, for `tool:privileged` / `memory:write` only
  - `trust_overrides`
  - `egress_allowlist`
  - `presidio` (`true` / `false` / `auto`)

  An invalid profile, **including one that shadows egress**, is a startup error.
- Tests:
  - `enabled()` reads the env.
  - Each project gets its own log dir.
  - Defaults apply when there is no profile.
  - Project A with `"tool:privileged":"enforce"` enforces, while B stays shadow.
  - An egress-shadow profile raises.
  - With no key, the log is chain-only and warns once.

**Task 2 — prompt provenance and insertion-site tagging.**
- `Message` gains `provenance: Provenance | None = None`. `None` means INTERNAL. `Message` is frozen, so build new Messages; never mutate.
- Enumerate **every** site that inserts referee/sweep output, consultant replies, host-repo files or memory rows. At each one, set `provenance = combine(...)`.
- Tests:
  - one per site: referee gives EXTERNAL, host-repo gives UNTRUSTED, only via/principal content stays INTERNAL/USER
  - a **parametrized regression guard** over the known sites, so a future untagged site fails

**Task 3 — seam hooks and the bypass test.**
- Bridge helpers:
  - `guard_prompt(messages, purpose) -> new messages` (ENFORCE)
  - `shadow_actions(actions, plan_provenance)` (mode from the profile)
  - `shadow_memory_write(kind, provenance, content)`
  - `check_destination(url)` (ENFORCE)
  - `guard_pulsewise(payload) -> payload` (ENFORCE)
- Tests, with the flag on and fakes:
  - PII is redacted before the fake provider sees it.
  - A secret blocks via the error path.
  - An EXTERNAL-derived `RunCommand` is audited as a shadow DENY **and still executes**.
  - A memory write is audited with the mapped trust.
  - An unknown host is refused and a known host passes.
  - **Bypass test:** with the flag on, a provider call that skips `guard_prompt` must fail. For example, use a per-call token the provider wrapper checks, or replace the unwrapped provider at bridge init.

**Task 4 — PulseWise run-close summary.**
- At run close (next to `_audit_after_run`), call `PulseWiseEmitter.from_env().emit(content=…, frame=f"{project}/security", run_id=…)`.
- Content is counts only: sink × effect × mode, shadow denials by rule, redactions by label, and `chain_verified`. **No** payload text, sources or names. It's a no-op when the emitter is disabled.
- Verify the `content` shape against `to_pulse_event`. Don't change PulseWise.

**Task 5 — `INTEGRATION.md`.** Cover:
- the flag
- the env vars: `VIA_DATASEC`, `VIA_DATASEC_DIR`, `DATASEC_KEY_K1`, `VIA_PULSEWISE_ENDPOINT`
- the modes, and that egress is always enforced
- the trust table
- the confirmed seams from Task 0
- the install line
- how to read `python -m datasec.report`
- how to flip a tool or memory sink to enforce via a profile

## 5. Done
- With the flag off, Via's full suite is unchanged.
- With the flag on, all new tests pass, including the bypass test and the per-site provenance tests.
- No live runs happened. Nothing merged without the user's review.
- Hand back:
  - the files changed
  - the confirmed seam table
  - test counts with the flag off and on
  - anything that didn't fit

## 6. Then the user (manual, after review)
1. Make one real `via run` on a throwaway project with `VIA_DATASEC=1`. Keys unset is fine.
2. Run `python -m datasec.report data/datasec/<project>/audit.jsonl` and review the **shadow denials**. Those are the trust-table tuning input and the location-redaction false-positive evidence.
3. Leave tool and memory in shadow until that review is done.

## Traps
- An `llm` path that bypasses `Substrate` (`review/gate.py`) is the classic fail-open. Hook it too.
- Shadow must **return the original payload**. Using a redacted one changes Via's behaviour before anyone decided it should.
- Project keys may be **full workspace paths** in Via's store. Use the same key the run uses (`args.project`) for the audit directory, and sanitise it into a safe directory name.
````
- [ ] **Step 3: Check it is self-contained.**
  - `grep -n "DATASEC_SHA\|<pytest line\|<runner line" docs/handoffs/2026-10-05-PROMPT_via_datasec_3A.md` prints nothing, so every placeholder has been filled.
  - The prompt names no file in this repo except the spec path, which it gives absolutely.
- [ ] **Step 4: Commit.**
```bash
git add docs/handoffs/2026-10-05-PROMPT_via_datasec_3A.md
git commit -m "docs: Via handoff prompt for Phase 3A, pinned to DATASEC_SHA" -m "<attribution line from the system reminder>"
```
(Put the real SHA in the commit message.)
