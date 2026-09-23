"""Seeded, labelled synthetic sshd logs for the reproducible evaluation.

Everything here is synthetic and marked as such. The generator writes raw sshd
journal messages, exactly the text the production parser reads, and keeps the
ground truth in separate files so nothing downstream of the parser can see it:

    events.jsonl    one sshd message per line: event_id, host, ts, message
    labels.jsonl    event_id -> "benign" or "attack:<episode_id>"
    episodes.json   the injected attack campaigns and their parameters
    manifest.json   seed, generator version, counts and SHA-256 of every file

Ground truth. An *episode* is a campaign injected from the scenario catalogue
below: it targets this organisation's real accounts or ends in a successful
login. Opportunistic internet scanning against generic usernames that never
succeeds is background noise and is labelled benign, as are users mistyping
passwords, automation and a monitor retrying a stale password. Two scenarios
(distributed spray, low-and-slow) are deliberately shaped to sit near or below
the per-source rule thresholds, so a rule set can miss them.

Addresses come from 198.18.0.0/15 (RFC 2544 benchmarking), drawn from one
shuffled pool for every role, so an address range never reveals a label.
The same seed always produces byte-identical files.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import random
from typing import Iterator

GENERATOR_VERSION = 1
DEFAULT_SEED = 20261115
DEFAULT_START = datetime(2026, 1, 5, tzinfo=timezone.utc)  # a Monday
DAY = 86400.0

INTERNET_FACING = ("bastion-01", "web-01", "web-02", "web-03", "web-04", "api-01", "api-02", "mail-01")
INTERNAL_ONLY = ("db-01", "db-02", "ci-01", "backup-01")
HOSTS = INTERNET_FACING + INTERNAL_ONLY
PEOPLE = ("amara", "bjorn", "chen", "dalia", "emeka", "farah", "goran", "hana", "ines", "jonas", "keiko",
          "lars", "maya", "nikos", "oksana", "pavel", "quinn", "rosa", "sanjay", "tomas", "ulla", "vikram",
          "wen", "yusuf")
COMMON_NAMES = ("root", "admin", "ubuntu", "test", "user", "oracle", "postgres", "git", "pi", "guest", "ftpuser",
                "support", "centos", "debian", "deploy", "mysql", "www", "hadoop", "nagios", "administrator")
LEAKED_NAMES = ("jsmith", "mjones", "a.kumar", "l.garcia", "tnguyen", "sbrown", "kwilliams", "dmiller", "rdavis",
                "p.wilson", "cmoore", "jtaylor", "e.anderson", "hthomas", "mjackson", "swhite", "charris", "amartin")
SCENARIOS = ("brute_force_success", "password_spray", "low_and_slow", "distributed_spray", "stuffing_then_success")


@dataclass(frozen=True)
class Config:
    seed: int = DEFAULT_SEED
    days: int = 7
    start: datetime = DEFAULT_START
    episodes_per_scenario_per_week: int = 12
    scanners_per_hour: tuple[int, int] = (30, 90)
    scanner_pool: int = 3000


@dataclass
class _Record:
    ts: float
    host: str
    message: str
    label: str


@dataclass
class _Episode:
    episode_id: str
    scenario: str
    start: float
    end: float = 0.0
    ips: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    attempts: int = 0
    succeeded: bool = False


class _World:
    """Everything the scenarios draw from, all derived from one seeded RNG."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.rng = random.Random(config.seed)
        self.origin = config.start.timestamp()
        self.span = config.days * DAY
        self._pool = self.rng.sample(range(2, (1 << 17) - 2), 20000)
        network = int(ipaddress.ip_address("198.18.0.0"))
        self._net = network
        self.records: list[_Record] = []
        self.episodes: list[_Episode] = []
        self.password_users = sorted(self.rng.sample(PEOPLE, 10))
        self.user_hosts = {user: sorted(self.rng.sample(HOSTS, self.rng.randint(1, 3))) for user in PEOPLE}
        self.user_ips = {user: self.ips(self.rng.randint(1, 2)) for user in PEOPLE}
        self.scanners = self.ips(config.scanner_pool)

    def ips(self, count: int) -> list[str]:
        taken, self._pool = self._pool[:count], self._pool[count:]
        return [str(ipaddress.ip_address(self._net + value)) for value in taken]

    def port(self) -> int:
        return self.rng.randint(1024, 65535)

    def emit(self, ts: float, host: str, message: str, label: str) -> None:
        if 0 <= ts - self.origin < self.span:
            self.records.append(_Record(round(ts, 3), host, message, label))

    def fingerprint(self) -> str:
        return "".join(self.rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                       for _ in range(43))

    # -- building blocks ---------------------------------------------------
    def login(self, ts: float, host: str, user: str, ip: str, label: str, *, method: str,
              session_minutes: tuple[int, int] = (5, 120)) -> float:
        port = self.port()
        tail = f" ssh2: ED25519 SHA256:{self.fingerprint()}" if method == "publickey" else " ssh2"
        self.emit(ts, host, f"Accepted {method} for {user} from {ip} port {port}{tail}", label)
        self.emit(ts + 0.02, host, f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)", label)
        end = ts + 60 * self.rng.randint(*session_minutes)
        self.emit(end, host, f"Received disconnect from {ip} port {port}:11: disconnected by user", label)
        self.emit(end + 0.01, host, f"pam_unix(sshd:session): session closed for user {user}", label)
        return ts

    def failed_connection(self, ts: float, host: str, user: str, ip: str, label: str, *, valid: bool,
                          attempts: int, gap: tuple[float, float] = (1.0, 4.0), close: float = 0.8) -> float:
        """One TCP connection with ``attempts`` wrong passwords; returns its end time."""
        port = self.port()
        if not valid:
            self.emit(ts, host, f"Invalid user {user} from {ip} port {port}", label)
        for _ in range(attempts):
            ts += self.rng.uniform(*gap)
            invalid = "" if valid else "invalid user "
            self.emit(ts, host, f"Failed password for {invalid}{user} from {ip} port {port} ssh2", label)
        if self.rng.random() < close:
            kind = "authenticating" if valid else "invalid"
            self.emit(ts + 0.2, host, f"Connection closed by {kind} user {user} {ip} port {port} [preauth]", label)
        return ts + 0.2

    def in_hours(self, day: int, first: float, last: float) -> float:
        return self.origin + day * DAY + self.rng.uniform(first, last) * 3600


# -- benign background ------------------------------------------------------

def _people(world: _World) -> None:
    rng = world.rng
    for day in range(world.config.days):
        weekday = (world.config.start + timedelta(days=day)).weekday() < 5
        for user in PEOPLE:
            sessions = rng.randint(1, 5) if weekday else (1 if rng.random() < 0.2 else 0)
            for _ in range(sessions):
                ts = world.in_hours(day, 7.5, 19.5)
                host = rng.choice(world.user_hosts[user])
                ip = rng.choice(world.user_ips[user])
                if user in world.password_users:
                    roll = rng.random()
                    mistakes = rng.randint(3, 5) if roll < 0.01 else rng.randint(1, 2) if roll < 0.08 else 0
                    if mistakes:
                        ts = world.failed_connection(ts, host, user, ip, "benign", valid=True, attempts=mistakes,
                                                     gap=(2.0, 9.0), close=0.3) + rng.uniform(3, 20)
                    world.login(ts, host, user, ip, "benign", method="password")
                else:
                    world.login(ts, host, user, ip, "benign", method="publickey")


def _automation(world: _World) -> None:
    rng = world.rng
    ci_ips, backup_ip, monitor_ip = world.ips(2), world.ips(1)[0], world.ips(1)[0]
    targets = [host for host in HOSTS if host.startswith(("web", "api"))]
    for day in range(world.config.days):
        ts = world.origin + day * DAY + 6 * 3600
        while ts < world.origin + day * DAY + 22 * 3600:
            ts += rng.uniform(20, 90) * 60
            for host in rng.sample(targets, rng.randint(1, len(targets))):
                world.login(ts + rng.uniform(0, 30), host, "deploy", rng.choice(ci_ips), "benign",
                            method="publickey", session_minutes=(1, 4))
        for host in ("db-01", "db-02"):
            world.login(world.origin + day * DAY + 2 * 3600 + rng.uniform(0, 600), host, "backup", backup_ip,
                        "benign", method="publickey", session_minutes=(20, 60))
        ts = world.origin + day * DAY
        while ts < world.origin + (day + 1) * DAY:
            ts += rng.uniform(540, 660)
            world.login(ts, rng.choice(HOSTS), "monitor", monitor_ip, "benign", method="publickey",
                        session_minutes=(1, 1))


def _stale_monitor(world: _World) -> None:
    """A legacy monitor retrying an expired password: noisy, harmless, repetitive."""
    rng = world.rng
    ip = world.ips(1)[0]
    for day in sorted(rng.sample(range(world.config.days), min(2, world.config.days))):
        ts = world.in_hours(day, 0, 16)
        end = ts + rng.uniform(3, 8) * 3600
        while ts < end:
            ts = world.failed_connection(ts, "db-02", "nagios", ip, "benign", valid=True, attempts=1,
                                         gap=(0.1, 0.3), close=1.0) + rng.uniform(55, 65)


def _internet_noise(world: _World) -> None:
    rng = world.rng
    for hour in range(world.config.days * 24):
        for _ in range(rng.randint(*world.config.scanners_per_hour)):
            ip = rng.choice(world.scanners)
            ts = world.origin + hour * 3600 + rng.uniform(0, 3600)
            for host in rng.sample(INTERNET_FACING, rng.randint(1, 3)):
                for _ in range(rng.randint(1, 3)):
                    roll = rng.random()
                    if roll < 0.25:
                        port = world.port()
                        world.emit(ts, host, rng.choice([
                            f"Connection closed by {ip} port {port} [preauth]",
                            f"Did not receive identification string from {ip} port {port}",
                            f"Received disconnect from {ip} port {port}:11: Bye Bye [preauth]"]), "benign")
                        ts += rng.uniform(1, 30)
                        continue
                    user = rng.choice(COMMON_NAMES)
                    ts = world.failed_connection(ts, host, user, ip, "benign", valid=user in ("root", "git"),
                                                 attempts=rng.randint(1, 3)) + rng.uniform(1, 40)
    # A few commodity bots hammer root for a while and never get in.
    for day in range(world.config.days):
        for _ in range(rng.randint(3, 6)):
            ip, host = rng.choice(world.scanners), rng.choice(INTERNET_FACING)
            ts = world.in_hours(day, 0, 24)
            end = ts + rng.uniform(10, 60) * 60
            while ts < end:
                ts = world.failed_connection(ts, host, "root", ip, "benign", valid=True,
                                             attempts=rng.randint(3, 6), gap=(0.5, 2.0)) + rng.uniform(1, 8)


# -- attack scenarios -------------------------------------------------------

def _new_episode(world: _World, scenario: str) -> _Episode:
    episode = _Episode(f"EP-{len(world.episodes) + 1:03d}", scenario,
                       world.origin + world.rng.uniform(0.02, 0.9) * world.span)
    world.episodes.append(episode)
    return episode


def _finish(world: _World, episode: _Episode, first: int) -> None:
    mine = world.records[first:]
    episode.end = max((record.ts for record in mine), default=episode.start)
    episode.attempts = sum(record.message.startswith("Failed password") for record in mine)


def _brute_force_success(world: _World, episode: _Episode) -> None:
    rng, label = world.rng, f"attack:{episode.episode_id}"
    ip, host, user = world.ips(1)[0], rng.choice(INTERNET_FACING), rng.choice(world.password_users)
    episode.ips, episode.hosts, episode.users = [ip], [host], [user]
    ts, remaining = episode.start, rng.randint(25, 160)
    while remaining > 0:
        attempts = min(remaining, rng.randint(3, 6))
        ts = world.failed_connection(ts, host, user, ip, label, valid=True, attempts=attempts,
                                     gap=(0.5, 4.0)) + rng.uniform(1, 10)
        remaining -= attempts
    world.login(ts, host, user, ip, label, method="password", session_minutes=(2, 45))
    episode.succeeded = True


def _password_spray(world: _World, episode: _Episode) -> None:
    rng, label = world.rng, f"attack:{episode.episode_id}"
    ip = world.ips(1)[0]
    hosts = sorted(rng.sample(INTERNET_FACING, rng.randint(2, 5)))
    users = sorted(rng.sample(PEOPLE, rng.randint(8, 20)))
    episode.ips, episode.hosts, episode.users = [ip], hosts, users
    pace = rng.uniform(20, 240)
    ts = episode.start
    for user in users:
        for host in hosts:
            ts = world.failed_connection(ts, host, user, ip, label, valid=True, attempts=1) + rng.uniform(0.5, 1.5) * pace
    if rng.random() < 1 / 3:
        winner = rng.choice([user for user in users if user in world.password_users] or users)
        world.login(ts, rng.choice(hosts), winner, ip, label, method="password", session_minutes=(2, 30))
        episode.succeeded = True


def _low_and_slow(world: _World, episode: _Episode) -> None:
    rng, label = world.rng, f"attack:{episode.episode_id}"
    ip, host, user = world.ips(1)[0], rng.choice(INTERNET_FACING), rng.choice(PEOPLE)
    episode.ips, episode.hosts, episode.users = [ip], [host], [user]
    interval = rng.uniform(600, 2400)
    ts, end = episode.start, episode.start + rng.uniform(6, 20) * 3600
    while ts < end:
        ts = world.failed_connection(ts, host, user, ip, label, valid=True, attempts=1) + rng.uniform(0.8, 1.2) * interval


def _distributed_spray(world: _World, episode: _Episode) -> None:
    rng, label = world.rng, f"attack:{episode.episode_id}"
    ips = world.ips(rng.randint(12, 40))
    users = sorted(rng.sample(PEOPLE, rng.randint(10, 20)))
    episode.ips, episode.users = ips, users
    hosts: set[str] = set()
    duration = rng.uniform(1, 4) * 3600
    for ip in ips:
        for _ in range(rng.randint(1, 2)):
            host, user = rng.choice(INTERNET_FACING), rng.choice(users)
            hosts.add(host)
            world.failed_connection(episode.start + rng.uniform(0, duration), host, user, ip, label,
                                    valid=True, attempts=1)
    episode.hosts = sorted(hosts)


def _stuffing_then_success(world: _World, episode: _Episode) -> None:
    rng, label = world.rng, f"attack:{episode.episode_id}"
    ip = world.ips(1)[0]
    hosts = sorted(rng.sample(INTERNET_FACING, rng.randint(1, 2)))
    total = rng.randint(30, 90)
    episode.ips, episode.hosts = [ip], hosts
    tried: list[str] = []
    ts, pace = episode.start, rng.uniform(10, 40) * 60 / total
    for _ in range(total):
        user = rng.choice(PEOPLE) if rng.random() < 0.3 else rng.choice(LEAKED_NAMES)
        tried.append(user)
        ts = world.failed_connection(ts, rng.choice(hosts), user, ip, label, valid=user in PEOPLE,
                                     attempts=1) + rng.uniform(0.5, 1.5) * pace
    winner = rng.choice(world.password_users)
    world.login(ts, rng.choice(hosts), winner, ip, label, method="password", session_minutes=(2, 30))
    episode.users = sorted(set(tried) | {winner})
    episode.succeeded = True


_SCENARIO_BUILDERS = {
    "brute_force_success": _brute_force_success,
    "password_spray": _password_spray,
    "low_and_slow": _low_and_slow,
    "distributed_spray": _distributed_spray,
    "stuffing_then_success": _stuffing_then_success,
}


def generate(config: Config) -> tuple[list[dict], list[dict], list[dict]]:
    """Return (events, labels, episodes) in their final, deterministic order."""
    world = _World(config)
    for builder in (_people, _automation, _stale_monitor, _internet_noise):
        builder(world)
    per_scenario = max(1, round(config.episodes_per_scenario_per_week * config.days / 7))
    for scenario in SCENARIOS:
        for _ in range(per_scenario):
            episode = _new_episode(world, scenario)
            first = len(world.records)
            _SCENARIO_BUILDERS[scenario](world, episode)
            _finish(world, episode, first)
    ordered = sorted(enumerate(world.records), key=lambda item: (item[1].ts, item[1].host, item[0]))
    events, labels = [], []
    for number, (_, record) in enumerate(ordered, start=1):
        event_id = f"E{number:07d}"
        stamp = datetime.fromtimestamp(record.ts, timezone.utc).isoformat(timespec="milliseconds")
        events.append({"event_id": event_id, "host": record.host, "ts": stamp.replace("+00:00", "Z"),
                       "message": record.message})
        labels.append({"event_id": event_id, "label": record.label})
    episodes = [{
        "episode_id": e.episode_id, "scenario": e.scenario, "synthetic": True,
        "start": datetime.fromtimestamp(e.start, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "end": datetime.fromtimestamp(e.end, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source_ips": e.ips, "hosts": e.hosts, "target_users": len(e.users), "failed_passwords": e.attempts,
        "succeeded": e.succeeded} for e in sorted(world.episodes, key=lambda item: item.episode_id)]
    return events, labels, episodes


def _jsonl(rows: list[dict]) -> bytes:
    return b"".join(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n" for row in rows)


def write(config: Config, directory: Path) -> dict:
    """Write the four files and return the manifest."""
    events, labels, episodes = generate(config)
    directory.mkdir(parents=True, exist_ok=True)
    payloads = {"events.jsonl": _jsonl(events), "labels.jsonl": _jsonl(labels),
                "episodes.json": json.dumps(episodes, indent=2, sort_keys=True).encode() + b"\n"}
    for name, data in payloads.items():
        (directory / name).write_bytes(data)
    counts: dict[str, int] = {}
    for row in labels:
        kind = "benign" if row["label"] == "benign" else "attack"
        counts[kind] = counts.get(kind, 0) + 1
    manifest = {
        "synthetic": True, "generator": "app.evaluation.synthetic", "generator_version": GENERATOR_VERSION,
        "seed": config.seed, "days": config.days,
        "start": config.start.isoformat().replace("+00:00", "Z"),
        "events": len(events), "benign_events": counts.get("benign", 0), "attack_events": counts.get("attack", 0),
        "episodes": len(episodes), "episodes_by_scenario": {s: sum(e["scenario"] == s for e in episodes)
                                                            for s in SCENARIOS},
        "hosts": list(HOSTS), "address_space": "198.18.0.0/15 (RFC 2544, synthetic)",
        "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()},
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def iter_events(directory: Path) -> Iterator[dict]:
    with (directory / "events.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            yield json.loads(line)


def mismatches(manifest: dict, expected: dict) -> list[str]:
    """Names whose content differs from a published manifest; empty means identical."""
    keys = ("seed", "days", "generator_version")
    problems = [key for key in keys if manifest.get(key) != expected.get(key)]
    return problems + sorted(name for name, digest in expected.get("sha256", {}).items()
                             if manifest["sha256"].get(name) != digest)


def write_example(directory: Path, scratch: Path) -> None:
    """Refresh the committed example: both manifests, the 7-day episode list and
    one brute-force campaign with the background around it, labels kept apart."""
    directory.mkdir(parents=True, exist_ok=True)
    for days in (1, 7):
        manifest = write(Config(days=days), scratch / f"{days}d")
        (directory / f"manifest-{days}d.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (directory / "episodes-7d.json").write_bytes((scratch / "7d" / "episodes.json").read_bytes())
    events, labels, episodes = generate(Config(days=1))
    chosen = next(e for e in episodes if e["scenario"] == "brute_force_success")
    low = datetime.fromisoformat(chosen["start"].replace("Z", "+00:00")) - timedelta(minutes=2)
    high = datetime.fromisoformat(chosen["end"].replace("Z", "+00:00")) + timedelta(minutes=2)
    keep = [i for i, e in enumerate(events)
            if e["host"] in chosen["hosts"] and low <= datetime.fromisoformat(e["ts"].replace("Z", "+00:00")) <= high]
    (directory / "excerpt-events.jsonl").write_bytes(_jsonl([events[i] for i in keep]))
    (directory / "excerpt-labels.jsonl").write_bytes(_jsonl([labels[i] for i in keep]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, type=Path, help="directory to write the dataset into")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--verify", type=Path, default=None,
                        help="published manifest the written files must match byte for byte")
    parser.add_argument("--write-example", type=Path, default=None, metavar="DIR",
                        help="maintainers: refresh the committed example files in DIR (uses --out as scratch)")
    args = parser.parse_args(argv)
    if args.days < 1:
        parser.error("--days must be at least 1")
    if args.write_example is not None:
        write_example(args.write_example, args.out)
        return 0
    manifest = write(Config(seed=args.seed, days=args.days), args.out)
    summary = {key: manifest[key] for key in ("seed", "days", "events", "attack_events", "episodes")}
    if args.verify is not None:
        problems = mismatches(manifest, json.loads(args.verify.read_text()))
        summary["matches_published_manifest"] = not problems
        if problems:
            summary["differs"] = problems
            print(json.dumps(summary, sort_keys=True))
            return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
