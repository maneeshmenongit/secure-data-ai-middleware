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
- **Report** for the design thread: `reports/YYYY-MM-DD-<topic>-report.md`, shaped like the latest one — TL;DR, what shipped (merge refs), red-team scorecard (fresh numbers), review findings + fixes, known gaps (why open, path forward), decisions for the design thread, still open, reproduce. When handing it over, start your message with "Written for: the design thread."
- **DESIGN.md** §8 phase line and §10 decisions (`[implemented, Phase N]` / `[open, owner: …]`).
- **Memory** `datasec-build-status.md`: update (don't duplicate) — what merged, pushed or not (`git log origin/master..master --oneline | wc -l`), fresh numbers, next step, and **declined/blocked items with why** (e.g. work Claude cannot author) so the next thread doesn't re-propose them.
- Commits: explicit paths (no `-A`), trailer copied verbatim from the session's system reminder.

## 4. Closing message
Verified-state table · what shipped (commit refs) · honest tally incl. your own defects · rulings and deferred minors · what's next · separated: what only the user can do (push, merge, decisions). If something is unfinished, say so — it goes in the report and memory as unfinished.
