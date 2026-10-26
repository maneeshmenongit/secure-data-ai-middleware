# [2026-10-24] DataSec re-pin: fix for the egress false positives found in the 3A trial

You are in a **via-skelton** thread, on the user's DataSec branch (`feat/datasec`) or a branch the user created from it. This is a **small task**: move Via's DataSec pin from `cf62c48` to `1a1eb54c0993c96241f66d195086b874270d47ce`. That commit fixes the three egress false positives your 3A trial reported in `via-data/projects/datasec-3a-trial/FOR_DATASEC_DESIGN_THREAD.md` (findings 1, 2 and 2b). **The API is unchanged.** Only redaction behaviour changes.

## 0. Read first, in order
1. Your own `via-onboard` skill (verify state mechanically) and your `via-code` skill.
2. This prompt, in full.
3. For reference only, the original 3A handoff. It is in another repo; read it but do not edit it: `/Users/maneeshmenon/PycharmProjects/secure-data-ai-middleware/docs/handoffs/2026-10-05-PROMPT_via_datasec_3A.md`. Its §2 exception contract still holds word for word.

## 1. Verified DataSec state (new pin)
| | |
|---|---|
| datasec commit | `1a1eb54c0993c96241f66d195086b874270d47ce` |
| previous pin | `cf62c48472424a67ff573776a1fd06b06dba7a6b` |
| datasec tests | 491 passed, 2 deselected, 14 xfailed |
| datasec red team | 87 passed, 14 known gaps, 0 skipped, 0 unexpected / 101 attacks |
| source changed since `cf62c48` | `src/datasec/redaction.py` only |

Install into Via's run venv, the same way as before:
```
/Users/maneeshmenon/PycharmProjects/via-data/.venv-run/bin/python -m pip install --force-reinstall --no-deps \
  "datasec[crypto] @ git+file:///Users/maneeshmenon/PycharmProjects/secure-data-ai-middleware@1a1eb54c0993c96241f66d195086b874270d47ce"
```
- If that venv has no pip, run `uv pip install --python <that python> --reinstall --no-deps "<same spec>"`.
- `--no-deps` is deliberate. `cryptography` is already installed, and the datasec core has no dependencies.
- Then confirm the install with `<that python> -c "import datasec.redaction as r; print(hasattr(r, '_mask_host_numbers'))"`, which must print `True`.

## 2. What changes in the egress redaction you see

**No longer redacted:**

| Input | Before (`cf62c48`) | Now |
|---|---|---|
| Loopback and unspecified addresses: `127.0.0.1`, any `127.x.x.x`, `0.0.0.0` | `[IPV4]` | Unchanged text |
| UUID-shaped ids (8-4-4-4-12 hex with at least one a–f letter), e.g. `mem_01a15cc8-8c5e-71bb-a771-3638710e24e6`, including `<uuid>-v2` and `<uuid>-<uuid>` | Tripped PHONE, SSN or CREDIT_CARD in about 3.9% of random ids | Unchanged. Measured 0 of 10,000 random ids in each form |
| Long decimal fractions (9 or more digits after the point), e.g. Python float costs like `$0.4111111111111111` | CREDIT_CARD in about 9.9% of float reprs | Unchanged. Measured 0 of 10,000 |

**Still redacted, on purpose:**
- **Private IPs** (`10.x`, `172.16–31.x`, `192.168.x`) and public IPs. Private ranges map an internal network, and exempting them is left to the DataSec design thread.
- **Real PII written next to an id or a decimal**, e.g. `mem_<uuid> card 4111 1111 1111 1111`, or `2.123-45-6789` in list numbering.

**Known limits (DataSec's documented gaps R2g.5 and R2g.6):**
- A card, SSN or phone number that someone deliberately formats as a UUID with hex letters, or as a bare decimal fraction, is no longer caught.
- This is the price of the exemption. Ordinary text isn't affected.

**Not fixed. Report counts back if Via emits these in prompts:**
- **Epoch-second timestamps** such as `1729771234` are still redacted as PHONE every time. They are 10 bare digits, so the regex can't tell them from a phone number. **Epoch milliseconds** trip a detector about 10% of the time.
- **Dashless 32-hex ids** (`uuid.hex`) still trip a detector about 9.5% of the time. This fix doesn't change that.
- **Long decimals inside a string that also contains an address** are still redacted by the location rule. That is deliberate.

**Finding 3, the guessable email:** DataSec has no code change for this. It is now documented as a limit: redaction hides a value, not a value the model can guess. Use Presidio where names matter.

## 3. Tasks (TDD: failing test, run red, implement, run green, commit)

1. **Write the failing test first.** Add a flag-on bridge test (`VIA_DATASEC=1`, regex redactor) that sends one `llm` payload through the bridge's egress hook and asserts that all three of these come through **unchanged**:
   - Via's real planner sentence: "no `requests` to 127.0.0.1. This environment blocks loopback…"
   - a `mem_<uuid4>` evidence id
   - a float cost written with `repr()`

   Add a second assertion that a real email in the same payload still comes back as `[EMAIL]`. Run it against the **old** pin and watch it fail.
2. **Move the pin everywhere it appears.** Use the full SHA `1a1eb54c0993c96241f66d195086b874270d47ce`. Find every place with `git grep -n cf62c48`; on `feat/datasec` at `313802c` they were:
   - `via/pyproject.toml:19` (the `datasec` optional extra)
   - `via/via/security/datasec_bridge.py:22` (the docstring "THE EXCEPTION CONTRACT (datasec @ …)")
   - `via/via/security/datasec_bridge.py:54` (`INSTALL_HINT`)
   - `INTEGRATION.md:15` (the install line)
   - `INTEGRATION.md:138` (the "Exception contract (datasec @ …)" heading)
3. **Reinstall** as in §1. The new test should now pass.
4. **Run Via's full suite twice: flag off, then flag on.** With the flag off it must be unchanged from before the re-pin.
5. **Record the change** in `INTEGRATION.md`, in one short paragraph: the new pin, what no longer gets redacted, and the known limits above.

## 4. Done
- The new test is green on `1a1eb54c0993c96241f66d195086b874270d47ce` and was red on `cf62c48`.
- No `cf62c48` remains (`git grep cf62c48` is empty), apart from history notes you add on purpose.
- The full suite passes with the flag off and with it on, and both counts are reported.
- Nothing merged without the user's review.
- **No live runs.** Re-running the 3A trial costs money, so it's the principal's call.
- **Hand back:** the files changed, test counts with the flag off and on, and whether Via's prompts contain epoch-second timestamps or dashless hex ids, with examples.

## Traps
- **Pin the full 40-character SHA**, not a branch name or a short SHA. `git+file` resolves a branch at install time, so the install would move under you.
- **Don't edit the DataSec repo.** If something in it looks wrong, write it in your hand-back, and the user will bring it to the DataSec thread.
- **The exception contract is unchanged.** Keep catching `Blocked` by name, and keep `DataSecError("audit append failed")` fatal.
- **Don't loosen Via's own handling to fit these cases.** If a prompt is still rewritten after the re-pin, report the exact string. Never route egress around `check()`.
