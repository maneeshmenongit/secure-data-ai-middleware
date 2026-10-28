---
name: datasec-new-feature
description: Use when starting any new control, detector, adapter, integration or phase in the secure-data-ai-middleware (DataSec) repo — including "quick" additions — before branching or writing code.
---

# Starting a DataSec feature

DataSec is a security product: every control ships with the evidence that it holds. The workflow is superpowers; this skill adds the repo's conventions and the traps that already cost a cycle.

## 1. Before designing
- Check `docs_to_claude/` (gitignored) for a design-thread doc on this feature: `ls -lt docs_to_claude/*/`. If one exists it is the spec's parent — design from it, don't re-invent.
- Branch from `master`: `feat/<topic>` or `fix/<topic>`. Never stack on an unrelated open branch (`git branch --no-merged master`).

## 2. The cycle
superpowers:brainstorming (classify spike / bounded / architectural out loud) → spec `docs/superpowers/specs/YYYY-MM-DD-datasec-<topic>-design.md` → plan `docs/superpowers/plans/YYYY-MM-DD-datasec-<topic>.md` → execute (user's default: Native) → whole-branch review by a fresh reviewer on the most capable model → superpowers:finishing-a-development-branch. Bounded fixes skip spec/plan docs but not tests or red team. "Quick" changes the size of each artifact, not whether it exists.

## 3. What every control must ship with
| Requirement | Where |
|---|---|
| RED→GREEN unit tests | `tests/test_<module>.py` |
| ≥1 red-team attack per new control; deliberate gaps as strict xfail `R<n>g.<m>` | `redteam/attacks/*.py` |
| New regex/detector: 1 MB adversarial timing attack (<1 s) **and** false-positive tests (prices, versions, IDs, ordinary prose) | `redteam/attacks/resource.py`, tests |
| Optional dependency → extra or uv group; attack with `requires=` so base installs report `skipped` | `pyproject.toml` |
| Fail closed; new options default to old behaviour; caller metadata through `_safe` (no raw PII in audit) | core |

Core `src/datasec` stays stdlib-only (`dependencies = []`).

## 4. Environment and commits
- Sync only with `uv sync --extra presidio --group presidio-model --group webapp`. **A bare or partial `uv sync` uninstalls the groups you omit.**
- Commit trailer: copy the attribution line from the session's system reminder verbatim. Never invent a model name.
- Never push or merge without the user choosing it.

## 5. External projects (Via, paper-trader, any other repo)
Via (`~/PycharmProjects/via-skelton`) is a host running many projects (e.g. `paper-trader` at `~/PycharmProjects/paper-trader`, LangGraph). **Never edit any other repo from here** — the same rule covers Via, paper-trader and every project they run — read it (read-only) to design, then hand that project's work over as a prompt: `docs/handoffs/YYYY-MM-DD-PROMPT_<topic>.md`, first line `# [YYYY-MM-DD] <context>`, self-contained for a fresh thread in that repo (read order, pinned datasec API + install, tasks, done-criteria/tests, traps — every detail it needs; it cannot ask you). The user runs it there. Never start Via or project runs (they spend the user's budget, and paper-trader trades).

**When Via needs a handoff.** Via agreed these triggers on 2026-10-28; the source is `docs_to_claude/handoff_from_via/2026-10-28-NOTE_what_via_needs_to_hear.md`. Via is pinned to one exact SHA, so nothing here reaches it until it re-pins. Send a re-pin handoff when a change touches any of these:
1. **The API Via calls:**
   - `adapters.gate` (`check`, `Mode`, `Blocked`)
   - `SecurityPipeline(...)`
   - `Action`, `PolicyEngine`, `default_rules(...)`
   - `Provenance`, `Tainted`, `TrustLevel`, `combine`
   - `Redactor` and `PresidioRedactor`
   - `AuditLog(...)`, `.verify()`, `.close()`
   - `LocalKeyProvider`
2. **The exception contract.** Via catches `Blocked` by name; any other `DataSecError` is fatal to Via; SHADOW raises `ValueError` for every sink except `tool:privileged` and `memory:write`.
3. **What gets redacted on egress.**
4. **The audit-log or checkpoint format.** Via reads `sink`, `effect`, `rule`, `tally` and `extra["mode"]`, and refuses to start if an existing log fails to verify. **An old log must still verify under the new pin; if it can't, say so.**
5. **The rules on privileged actions**, especially `privileged_source_allowlist`.
6. **Speed.** Every prompt and every memory write Via makes passes through `check()`.
7. **Presidio readiness.** Send the install steps.

No handoff is needed for refactors that don't change behaviour, for new tests or red-team cases, or for 3B, unless Via will run a project that uses it.

**The handoff itself** follows the 2026-10-24 re-pin pattern:
- the full 40-character SHA (never a branch name)
- what changed for a caller: what is newly redacted or no longer redacted, and what is newly allowed or denied
- the known limits that come with the change
- every place the old pin appears in Via
- a test to write before the change (red, then green)
- a statement that the install was verified in a throwaway venv
