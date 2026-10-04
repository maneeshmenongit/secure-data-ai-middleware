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

## 5. Via-related work
Via (`~/PycharmProjects/via-skelton`) is a host running many projects (e.g. `paper-trader`, LangGraph) with its own skills in `.claude/skills/`. **Never edit Via from this repo** — read it (read-only) to design, then hand the Via-side work over as a prompt: `docs/handoffs/YYYY-MM-DD-PROMPT_<topic>.md`, first line `# [YYYY-MM-DD] <context>`, self-contained for a fresh Via thread (read order, pinned datasec API + install, tasks, done-criteria/tests, traps). The user runs it in a Via thread. Never start Via runs (they spend the user's budget).
