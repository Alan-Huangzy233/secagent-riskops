"""Slice the LANL authentication data into the evaluation's input format.

Source: A. D. Kent, "Comprehensive, Multi-Source Cyber-Security Events", Los
Alamos National Laboratory, 2015, doi:10.17021/1179829. The data is dedicated
to the public domain (CC0); download requires registering an intended use at
https://csr.lanl.gov/data/cyber1/.

    auth.txt     time,src user@domain,dst user@domain,src computer,dst computer,
                 auth type,logon type,orientation,Success|Fail
    redteam.txt  time,user@domain,src computer,dst computer

The slice rule was fixed before any evaluation run:

* **Window** — the ``WINDOW_DAYS`` consecutive days holding the most red-team
  events.
* **Events** — ``LogOn`` records only (LogOff, TGS, TGT and AuthMap are session
  ends and ticket operations, not authentication attempts).
* **Sources** — every record whose source computer is a red-team source inside
  the window, plus every record from the other source computers chosen by
  hashing ``seed:name`` (a fixed fraction, one pass). A chosen source keeps its
  whole trail, which is what per-source rules and correlation need.

Slice version 1 kept every record touching any red-team computer instead. A
count-only dry run showed that meant 15.3 million of the window's 25.8 million
logons, because several red-team targets are hubs (one destination alone had
3.7 million); it was replaced by sampling sources before any evaluation ran.

Mapping: destination computer -> ``source_id`` (the host that logged it),
source computer -> ``src_ip`` (the peer), destination user -> ``ssh_user``,
``Success``/``Fail`` -> ``auth_success``/``auth_failure``. There is no
``Invalid user`` concept here and ``time`` is seconds from the dataset start.

Ground truth: a record is ``attack:<episode>`` when it matches a red-team event
on time, source and destination computer and either user field. An *episode* is
one red-team account on one day — deliberately not "one source close in time",
which would mirror the pipeline's own correlation rule. Red-team events with no
matching ``LogOn`` record are counted per episode so a miss caused by the data
is reported rather than silently dropped.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
from typing import Iterable, Iterator, TextIO

SLICE_VERSION = 2
WINDOW_DAYS = 3
DEFAULT_SEED = 20261115
DEFAULT_SAMPLE_PER_MILLE = 20
DAY = 86400


def red_team(lines: Iterable[str]) -> list[tuple[int, str, str, str]]:
    events = []
    for line in lines:
        time, user, source, destination = line.strip().split(",")
        events.append((int(time), user, source, destination))
    return sorted(events)


def busiest_window(events: list[tuple[int, str, str, str]], days: int = WINDOW_DAYS) -> tuple[int, int]:
    """First day and count of the ``days`` consecutive days with the most red-team events."""
    per_day = Counter(time // DAY for time, *_ in events)
    last = max(per_day)
    best = max(range(0, last + 1), key=lambda first: (sum(per_day[first + k] for k in range(days)), -first))
    return best, sum(per_day[best + k] for k in range(days))


def sampled(name: str, seed: int, per_mille: int) -> bool:
    digest = hashlib.sha256(f"{seed}:{name}".encode()).digest()
    return int.from_bytes(digest[:4], "big") % 1000 < per_mille


def slice_auth(auth: TextIO, events: list[tuple[int, str, str, str]], *, seed: int = DEFAULT_SEED,
               per_mille: int = DEFAULT_SAMPLE_PER_MILLE) -> dict:
    """Stream ``auth`` once and return records, labels, episodes and counts."""
    first_day, window_events = busiest_window(events)
    start, end = first_day * DAY, (first_day + WINDOW_DAYS) * DAY
    inside = [event for event in events if start <= event[0] < end]
    red_sources = {source for _, _, source, _ in inside}
    episode_of: dict[tuple[str, int], str] = {}
    for time, user, *_ in inside:
        episode_of.setdefault((user, time // DAY), "")
    for number, key in enumerate(sorted(episode_of, key=lambda item: (item[1], item[0])), start=1):
        episode_of[key] = f"EP-{number:03d}"
    wanted: dict[tuple[int, str, str], list[str]] = {}
    for time, user, source, destination in inside:
        wanted.setdefault((time, source, destination), []).append(user)
    matched: set[tuple[int, str, str, str]] = set()
    records, labels = [], []
    counts: Counter[str] = Counter()
    for number, line in enumerate(auth, start=1):
        time_text, _, _ = line.partition(",")
        time = int(time_text)
        if time < start:
            continue
        if time >= end:
            break
        counts["window_lines"] += 1
        fields = line.rstrip("\n").split(",")
        if len(fields) != 9 or fields[7] != "LogOn" or fields[8] not in ("Success", "Fail"):
            continue
        counts["window_logons"] += 1
        _, src_user, dst_user, source, destination, *_ = fields
        if not (source in red_sources or sampled(source, seed, per_mille)):
            continue
        event_id = f"L{number}"
        label = "benign"
        for user in wanted.get((time, source, destination), ()):
            if user in (src_user, dst_user):
                label = f"attack:{episode_of[(user, time // DAY)]}"
                matched.add((time, user, source, destination))
                break
        records.append({"source_id": destination, "event_id": event_id, "event_ts": float(time),
                        "event_type": "auth_success" if fields[8] == "Success" else "auth_failure",
                        "src_ip": source, "ssh_user": dst_user})
        labels.append({"event_id": event_id, "label": label})
    episodes = []
    for (user, day), episode_id in sorted(episode_of.items(), key=lambda item: item[1]):
        own = [event for event in inside if event[1] == user and event[0] // DAY == day]
        episodes.append({"episode_id": episode_id, "scenario": "lanl_red_team", "synthetic": False,
                         "account": user, "day": day, "red_team_events": len(own),
                         "unmatched_red_team_events": sum(event not in matched for event in own),
                         "source_computers": sorted({event[2] for event in own}),
                         "hosts": sorted({event[3] for event in own})})
    return {"records": records, "labels": labels, "episodes": episodes,
            "window": {"first_day": first_day, "days": WINDOW_DAYS, "red_team_events": window_events},
            "red_team_sources": sorted(red_sources), "counts": dict(counts)}


def _jsonl(rows: list[dict]) -> bytes:
    return b"".join(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n" for row in rows)


def _lines(path: Path) -> Iterator[str]:
    """Read plain or gzip text from a file or ``-`` (stdin).

    A leading prefix of the gzip archive is enough: the stream simply ends where
    the prefix does, and the window is closed long before that.
    """
    raw = sys.stdin.buffer if str(path) == "-" else path.open("rb")
    try:
        head = raw.peek(2)[:2] if hasattr(raw, "peek") else b""
        handle = io.TextIOWrapper(gzip.GzipFile(fileobj=raw) if head == b"\x1f\x8b" else raw, encoding="utf-8")
        try:
            yield from handle
        except EOFError:
            return
    finally:
        if raw is not sys.stdin.buffer:
            raw.close()


def write(auth: Path, redteam: Path, out: Path, *, seed: int = DEFAULT_SEED,
          per_mille: int = DEFAULT_SAMPLE_PER_MILLE) -> dict:
    result = slice_auth(_lines(auth), red_team(_lines(redteam)), seed=seed, per_mille=per_mille)
    out.mkdir(parents=True, exist_ok=True)
    payloads = {"records.jsonl": _jsonl(result["records"]), "labels.jsonl": _jsonl(result["labels"]),
                "episodes.json": json.dumps(result["episodes"], indent=2, sort_keys=True).encode() + b"\n"}
    for name, data in payloads.items():
        (out / name).write_bytes(data)
    kinds = Counter(label["label"] != "benign" for label in result["labels"])
    manifest = {
        "synthetic": False, "source": "LANL Comprehensive, Multi-Source Cyber-Security Events (CC0)",
        "citation": "A. D. Kent, Los Alamos National Laboratory, 2015, doi:10.17021/1179829",
        "slicer": "app.evaluation.lanl", "slice_version": SLICE_VERSION, "seed": seed,
        "sample_per_mille": per_mille, "window": result["window"],
        "red_team_sources": result["red_team_sources"], "counts": result["counts"],
        "records": len(result["records"]), "attack_records": kinds[True], "benign_records": kinds[False],
        "episodes": len(result["episodes"]),
        "unmatched_red_team_events": sum(e["unmatched_red_team_events"] for e in result["episodes"]),
        "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--auth", required=True, type=Path, help="auth.txt or auth.txt.gz, or - for stdin (a leading prefix of the archive is enough)")
    parser.add_argument("--redteam", required=True, type=Path, help="redteam.txt or redteam.txt.gz")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--sample-per-mille", type=int, default=DEFAULT_SAMPLE_PER_MILLE)
    args = parser.parse_args(argv)
    manifest = write(args.auth, args.redteam, args.out, seed=args.seed, per_mille=args.sample_per_mille)
    print(json.dumps({key: manifest[key] for key in ("window", "records", "attack_records", "episodes",
                                                     "unmatched_red_team_events")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
