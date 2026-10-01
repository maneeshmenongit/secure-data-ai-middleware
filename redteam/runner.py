"""Run the red-team corpus and write a scorecard: python -m redteam.runner"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from redteam.common import DEFENDED, Attack
from redteam.corpus import ATTACKS

SCORECARD_PATH = Path(__file__).with_name("scorecard.json")
STATUSES = ("pass", "known_gap", "fixed_gap", "unexpected", "skipped")


@dataclass(frozen=True)
class Result:
    id: str
    category: str
    owasp: str
    description: str
    expect: str
    observed: str
    requires: str | None = None

    @property
    def status(self) -> str:
        if self.observed == "skipped":
            # Only an attack that declares an optional dependency may skip; otherwise a
            # defended attack that started returning "skipped" would vanish from the scorecard.
            return "skipped" if self.requires else "unexpected"
        defended = self.observed in DEFENDED
        if self.expect == "known_gap":
            return "fixed_gap" if defended else "known_gap"
        return "pass" if self.observed == self.expect else "unexpected"


def run_attack(attack: Attack) -> Result:
    if attack.requires and importlib.util.find_spec(attack.requires) is None:
        observed = "skipped"
    else:
        try:
            observed = attack.run()
        except Exception as exc:
            observed = f"error:{type(exc).__name__}"
    return Result(
        attack.id, attack.category, attack.owasp, attack.description, attack.expect, observed, attack.requires
    )


def run_all(attacks: list[Attack] = ATTACKS) -> dict:
    results = [run_attack(a) for a in attacks]
    by_category: dict[str, dict[str, int]] = defaultdict(lambda: dict.fromkeys(STATUSES, 0))
    for r in results:
        by_category[r.category][r.status] += 1
    count = lambda s: sum(r.status == s for r in results)  # noqa: E731
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "passed": count("pass"),
        "known_gaps": count("known_gap"),
        "skipped": count("skipped"),
        # A fixed gap is unexpected too: the corpus label must be updated.
        "unexpected": count("unexpected") + count("fixed_gap"),
        "by_category": dict(by_category),
        "results": [{**asdict(r), "status": r.status} for r in results],
    }


def main(path: str | Path = SCORECARD_PATH) -> int:
    card = run_all()
    for r in card["results"]:
        print(f"{r['status']:<11} {r['id']:<7} {r['category']:<20} {r['description']}")
    print(
        f"\n{card['passed']} passed, {card['known_gaps']} known gaps, {card['skipped']} skipped, "
        f"{card['unexpected']} unexpected / {card['total']} attacks"
    )
    Path(path).write_text(json.dumps(card, indent=2) + "\n")
    return 1 if card["unexpected"] else 0


if __name__ == "__main__":
    sys.exit(main())
