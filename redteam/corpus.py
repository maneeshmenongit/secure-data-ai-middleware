"""Every attack the suite knows about."""

from redteam.attacks import audit_tamper, evasion, exfiltration, failclosed, resource, taint

ATTACKS = [
    *taint.ATTACKS,
    *evasion.ATTACKS,
    *exfiltration.ATTACKS,
    *audit_tamper.ATTACKS,
    *failclosed.ATTACKS,
    *resource.ATTACKS,
]
