---
name: datasec-onboard
description: Use when starting a fresh thread on the secure-data-ai-middleware (DataSec) repo — the user says "continue datasec", "new thread", "where are we", "what's next", pastes a handoff, or asks for status — before touching code or answering from memory.
---

# Onboarding a new DataSec thread

A fresh thread inherits nothing; the durable record does. Turn it into verified state, in this order, then report.

## 0. Name the thread
First line of your first reply: `[YYYY-MM-DD] <one-line context>`.

## 1. Read the record
1. Memory: `datasec-build-status.md` (phases, merge/push state, **declined items**, run conventions).
2. **`docs_to_claude/` — gitignored, so `git log` cannot show it.** The user drops design-thread docs here (new specs, rulings, revised DESIGN.md). List newest first and read anything newer than the latest report:
   `ls -lt docs_to_claude/*/ | head -20`
3. The latest report, which is what the design thread was told: `ls -t reports/*.md reports/*/*.md | head -3`. Since 2026-10-17 there is one folder per feature, `reports/<feature>/`. and open specs/plans in `docs/superpowers/`.
4. **Paused designs: `docs/superpowers/brainstorms/*.md`.** A file marked `PAUSED` is a brainstorm a previous thread stopped mid-way. Its decisions are made, so don't re-ask them. Resume at the step and the next question it names. Treat its file:line facts about external repos as dated, and re-check them read-only before relying on them.

## 2. Verify state mechanically — never trust memory's numbers
```bash
git status -sb && git branch -vv && git log origin/master..master --oneline | wc -l   # branch, clean?, unpushed
uv run python -c "import presidio_analyzer,spacy;print(spacy.util.is_package('en_core_web_lg'))"  # Presidio present?
uv run pytest -q | tail -1                  # record passed / xfailed (xfail = known gaps)
uv run python -m redteam.runner | tail -1   # 0 unexpected; skipped>0 means Presidio missing
```
If Presidio is missing the red team shows fewer defended + some skipped — say which, don't report it as a regression. To restore: `uv sync --extra presidio --group presidio-model --group webapp` (**never a bare `uv sync`**; it uninstalls those).

## 3. In-flight work — look before acting
- `lsof -nP -iTCP:8000 -sTCP:LISTEN` — the demo console the user may be viewing over an SSH tunnel. Don't stop it without asking. **Port 8765 belongs to an unrelated process: never use or kill it.**
- Unmerged branches here (`git branch --no-merged master`) and, for Via work, `git -C ~/PycharmProjects/via-skelton branch --no-merged` (Via is another active project: read-only unless the user approved a branch).

## 4. Report, then act
One compact message: verified-state table (branch, unpushed count, tests, red team, Presidio), in-flight items (including any paused brainstorm and the question it resumes at), what the record says is next — and, separated, what needs the user (push, merge, reviews, decisions). Items memory marks **declined** (e.g. the out-of-band attack harness, deliberately vulnerable apps) are not "open work" — don't re-propose them.
