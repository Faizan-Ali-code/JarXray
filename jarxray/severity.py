"""Shared severity ranking, used by both the JSON parser and the HTML report
(so CRITICAL/HIGH/MEDIUM/LOW sort the same way everywhere)."""

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def severity_rank(sev: str) -> int:
    return SEVERITY_RANK.get((sev or "").upper(), 0)
