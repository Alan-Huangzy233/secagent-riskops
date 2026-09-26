"""Stage 3: score an incident from its own evidence and decide whether to surface it.

Every input is something the logs show; nothing is learned from labels. The
weights were fixed before any evaluation run and are reported with the results.

* A login that succeeds after the failures is the strongest sign of compromise.
* Attempts against accounts that *exist* mean the source knows this
  organisation. sshd says so itself: it logs ``Invalid user`` for names that do
  not exist. ``root`` exists everywhere and is the default target of internet
  noise, so it does not count.
* Several hosts, persistence over hours and sheer volume add a little each.
* A success from a source that had already logged in cleanly as that user
  before the incident began is most likely the user mistyping, so it takes
  most of the success weight back.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..telemetry.sshd_parse import FAILURE_KINDS

SUCCESS = 50
EXISTING_ACCOUNT = 12
EXISTING_ACCOUNT_CAP = 3
SEVERAL_HOSTS = 10
PERSISTENT = 15
PERSISTENT_SECONDS = 2 * 3600
VOLUME = 5
VOLUME_RECORDS = 50
KNOWN_SOURCE = -40
SURFACE_THRESHOLD = 25
PRIORITIES = ((60, "P1"), (40, "P2"), (SURFACE_THRESHOLD, "P3"))


@dataclass(frozen=True)
class Assessment:
    score: int
    priority: str | None
    surfaced: bool
    reasons: tuple[str, ...]


def known_sources(records: list[dict]) -> dict[tuple[str, str], float]:
    """Earliest successful login per (source address, user) over the whole stream."""
    first: dict[tuple[str, str], float] = {}
    for row in records:
        if row["event_type"] == "auth_success" and row.get("ssh_user"):
            key = (row["src_ip"], row["ssh_user"])
            first[key] = min(first.get(key, row["event_ts"]), row["event_ts"])
    return first


def assess(evidence: list[dict], baseline: dict[tuple[str, str], float], *,
           threshold: int = SURFACE_THRESHOLD) -> Assessment:
    """Score one incident; ``evidence`` holds its normalized log records."""
    failures = [row for row in evidence if row["event_type"] in FAILURE_KINDS]
    successes = [row for row in evidence if row["event_type"] == "auth_success"]
    start = min(row["event_ts"] for row in evidence)
    span = max(row["event_ts"] for row in evidence) - start
    invalid = {row["ssh_user"] for row in failures if row["event_type"] == "invalid_user" and row["ssh_user"]}
    existing = sorted({row["ssh_user"] for row in failures if row["event_type"] == "auth_failure"
                       and row["ssh_user"] and row["ssh_user"] not in invalid and row["ssh_user"] != "root"})
    hosts = {row["source_id"] for row in evidence}
    return assess_summary(
        failure_count=len(failures), success_count=len(successes),
        existing_accounts=len(existing), host_count=len(hosts), span=span,
        all_successes_known=bool(successes) and all(
            baseline.get((row["src_ip"], row["ssh_user"]), start) < start for row in successes),
        threshold=threshold,
    )


def assess_summary(*, failure_count: int, success_count: int, existing_accounts: int,
                   host_count: int, span: float, all_successes_known: bool = False,
                   threshold: int = SURFACE_THRESHOLD) -> Assessment:
    """Same weights for batch evidence and durable SQL aggregates.

    Callers must aggregate complete incident evidence, never a paginated preview.
    The live adapter deliberately leaves all_successes_known false: a previous
    login alone is insufficient to trust a source on a partially observed host.
    """
    score, reasons = 0, []
    if success_count:
        score += SUCCESS
        reasons.append(f"+{SUCCESS} login succeeded after failed attempts")
        if all_successes_known:
            score += KNOWN_SOURCE
            reasons.append(f"{KNOWN_SOURCE} every success came from a source that had logged in as that user before")
    if existing_accounts:
        counted = min(existing_accounts, EXISTING_ACCOUNT_CAP)
        score += EXISTING_ACCOUNT * counted
        reasons.append(f"+{EXISTING_ACCOUNT * counted} attempts against {existing_accounts} existing non-root "
                       f"account(s)")
    if host_count >= 2:
        score += SEVERAL_HOSTS
        reasons.append(f"+{SEVERAL_HOSTS} activity on {host_count} hosts")
    if span >= PERSISTENT_SECONDS and failure_count >= 10:
        score += PERSISTENT
        reasons.append(f"+{PERSISTENT} persisted for {span / 3600:.1f} h")
    if failure_count >= VOLUME_RECORDS:
        score += VOLUME
        reasons.append(f"+{VOLUME} {failure_count} failed-authentication records")
    priority = next((name for floor, name in PRIORITIES if score >= floor and score >= threshold), None)
    return Assessment(score, priority, score >= threshold, tuple(reasons))
