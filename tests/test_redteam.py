import json

import pytest

from redteam.common import DEFENDED, Attack
from redteam.corpus import ATTACKS
from redteam.runner import main, run_all


def _param(attack):
    marks = []
    if attack.expect == "known_gap":
        marks.append(pytest.mark.xfail(strict=True, reason=f"known gap: {attack.description}"))
    return pytest.param(attack, id=attack.id, marks=marks)


@pytest.mark.parametrize("attack", [_param(a) for a in ATTACKS])
def test_attack(attack):
    observed = attack.run()
    if attack.expect == "known_gap":
        assert observed in DEFENDED  # xfail(strict): passes only once the gap is fixed
    else:
        assert observed == attack.expect


def test_attack_ids_are_unique():
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))


def test_bad_expectation_rejected():
    with pytest.raises(ValueError):
        Attack("X", "c", "o", "d", lambda: "blocked", "maybe")


def test_runner_classifies_results():
    fake = [
        Attack("F1", "c", "o", "d", lambda: "allowed", "blocked"),
        Attack("F2", "c", "o", "d", lambda: "blocked", "known_gap"),
        Attack("F3", "c", "o", "d", lambda: "allowed", "known_gap"),
        Attack("F4", "c", "o", "d", lambda: 1 / 0, "blocked"),
        Attack("F5", "c", "o", "d", lambda: "blocked", "blocked"),
    ]
    card = run_all(fake)
    assert [r["status"] for r in card["results"]] == [
        "unexpected", "fixed_gap", "known_gap", "unexpected", "pass",
    ]
    assert card["results"][3]["observed"] == "error:ZeroDivisionError"
    assert card["passed"] == 1
    assert card["known_gaps"] == 1
    assert card["unexpected"] == 3
    assert card["by_category"]["c"]["unexpected"] == 2


def test_main_writes_scorecard_and_returns_zero(tmp_path):
    path = tmp_path / "scorecard.json"
    assert main(path) == 0
    card = json.loads(path.read_text())
    assert card["unexpected"] == 0
    assert card["total"] == len(ATTACKS)
