---
name: datasec-closeout
description: Use when finishing DataSec work in the secure-data-ai-middleware repo — the user says "wrap up", "close out", "we're done", "share with the design thread", or a feature/phase/fix is complete — before claiming it is done or ending the thread.
---

# Closing out DataSec work

Done means a fresh thread could continue from the durable record alone. Mirror of datasec-onboard: that skill reads the record, this one writes it.

## 1. Verify fresh — never close on a remembered green
```bash
git status -sb
uv run python -c "import presidio_analyzer,spacy;print(spacy.util.is_package('en_core_web_lg'))"
uv run pytest -q | tail -1
uv run python -m redteam.runner | tail -1      # 0 unexpected; skipped must be 0 when Presidio is present
uv run python demo.py | tail -1
```
If the work touched `webapp/`, smoke a real server **on port 8799** (8000 may be the user's live console; 8765 is an unrelated process — never touch either), then **stop the server you started**. Red anything = not done; fix first (superpowers:systematic-debugging).

## 2. Review and branch
Whole-branch review by a fresh reviewer (most capable model) if not done; Critical/Important fixed with RED→GREEN tests. Then superpowers:finishing-a-development-branch — the user picks merge / push+PR / keep. Never push or merge unasked.

## 3. Write the record
- **Report** for the design thread: `reports/<feature>/YYYY-MM-DD-<topic>-report.md`. Use one folder per feature, named after the branch topic (`feat/langgraph-adapter` → `reports/langgraph-adapter/`). Reports dated 2026-10-16 or earlier stay at the top level of `reports/`. Shape the report like the latest one — TL;DR, what shipped (merge refs), red-team scorecard (fresh numbers), review findings + fixes, known gaps (why open, path forward), decisions for the design thread, still open, reproduce. When handing it over, start your message with "Written for: the design thread."
- **DESIGN.md** §8 phase line and §10 decisions (`[implemented, Phase N]` / `[open, owner: …]`).
- **Memory** `datasec-build-status.md`: update (don't duplicate) — what merged, pushed or not (`git log origin/master..master --oneline | wc -l`), fresh numbers, next step, and **declined/blocked items with why** (e.g. work Claude cannot author) so the next thread doesn't re-propose them.
- Commits: explicit paths (no `-A`), trailer copied verbatim from the session's system reminder.

## 3b. Closing mid-design (brainstorm not finished)
Conversation context doesn't survive the thread, so write it down: `docs/superpowers/brainstorms/YYYY-MM-DD-datasec-<topic>.md`, marked `PAUSED`. Include:
- the path (spike, bounded or architectural) and the branch
- each decision made, **with the rejected options and why**
- the facts gathered, with dates and file:line references (mark external-repo facts as read-only)
- the questions still to ask, in order, with your leaning on each
- any candidate shape, labelled not approved
- one **Resume** line naming the step and the next question

Once the spec is written, the spec supersedes the brainstorm file. Mark the file `SUPERSEDED by <spec path>`.

## 3c. External projects: does this need a handoff?
Check every merged change against the Via triggers in `datasec-new-feature` §5 (the API, the exception contract, egress redaction, audit format, privileged rules, speed, Presidio).
- **If any trigger is hit, write the re-pin handoff before closing:** `docs/handoffs/YYYY-MM-DD-PROMPT_via_<topic>.md`.
- Pin it to the full SHA of the code commit, and install that SHA into a throwaway venv in the scratchpad to prove it.
- For the audit format, state whether an old log still verifies.
- For speed, give the measured timings near the 1 MB cap.
- Hand-backs from Via land in `docs_to_claude/handoff_from_via/`; read them first.

## 3d. Prepare the next thread
The next thread inherits only the record. Before the closing message:
- **Memory.** It must name the single next step and every open user decision, such as pending pushes, merges, and branches kept for external pins. Branches kept for external pins (a SHA another repo installs) must never be squashed, rebased or deleted.
- **In-flight work.** If something is in flight, a `PAUSED` brainstorm (§3b) or a plan must say exactly where to resume.
- **Workspace.** Leave the working tree clean. Park empty feature branches at `master`. Leave untracked files the user put there alone, and mention them.
- **Starter prompt.** End the closing message with a one-line starter prompt for the new thread, for example: `continue datasec — resume the paused <topic> brainstorm at <step>`. The `datasec-onboard` skill then finds the record.

## 4. Closing message
Verified-state table · what shipped (commit refs) · honest tally incl. your own defects · rulings and deferred minors · what's next · separated: what only the user can do (push, merge, decisions). If something is unfinished, say so — it goes in the report and memory as unfinished.
