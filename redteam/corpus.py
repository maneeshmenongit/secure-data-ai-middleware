"""Every attack the suite knows about."""

from redteam.attacks import exfiltration, failclosed, taint

ATTACKS = [*taint.ATTACKS, *exfiltration.ATTACKS, *failclosed.ATTACKS]
