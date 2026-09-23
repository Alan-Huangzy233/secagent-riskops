"""Stage 2: join alert groups that describe one piece of activity into an incident.

Two links, both explicit:

* **Shared evidence** — groups whose alerts rest on a common log record are one
  story, whatever the rule or host. This is the pilot's own merge rule.
* **Same source, close in time** — groups from one source address whose active
  periods are no more than ``gap_seconds`` apart. This joins, for example, a
  password spray's per-host bursts with the success that follows it.

Nothing else links groups. In particular two different source addresses are
never joined unless a log record ties them together, so a campaign spread over
many addresses stays fragmented; that is measured, not papered over.
"""
from __future__ import annotations

from datetime import datetime

from .dedup import AlertGroup, _Sets

DEFAULT_GAP_SECONDS = 3600


def _seconds(stamp: str) -> float:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def correlate(groups: list[AlertGroup], *, gap_seconds: int = DEFAULT_GAP_SECONDS) -> list[list[AlertGroup]]:
    """Return incidents as lists of groups, each list and the whole ordered by first group."""
    if gap_seconds < 0:
        raise ValueError("gap_seconds cannot be negative")
    groups = sorted(groups, key=lambda group: group.group_id)
    sets = _Sets(len(groups))
    owner: dict[str, int] = {}
    for index, group in enumerate(groups):
        for record in group.evidence:
            seen = owner.setdefault(record, index)
            if seen != index:
                sets.union(seen, index)
    by_source: dict[str, list[int]] = {}
    for index, group in enumerate(groups):
        by_source.setdefault(group.src_ip, []).append(index)
    for members in by_source.values():
        members.sort(key=lambda index: (_seconds(groups[index].first_ts), groups[index].group_id))
        # Sweep in start order; ``reach`` is the latest activity of the current run.
        anchor, reach = members[0], _seconds(groups[members[0]].last_ts)
        for index in members[1:]:
            start, end = _seconds(groups[index].first_ts), _seconds(groups[index].last_ts)
            if start - reach <= gap_seconds:
                sets.union(anchor, index)
                reach = max(reach, end)
            else:
                anchor, reach = index, end
    return [[groups[index] for index in members] for members in sets.components()]
