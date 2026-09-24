"""Typed executor for ``harden_ssh_access``, confined to a lab copy of a host.

The executor takes validated parameters, never text from a model, and works on
one directory that stands in for a host's filesystem. That directory must carry
a ``.riskops-lab`` marker naming the asset, so a plan for one host can never be
run against another host or against a real ``/``. Nothing is reloaded: there is
no daemon in a lab copy.

It makes the smallest edit to the one file it owns, ``etc/ssh/sshd_config``:
the first global line for each setting is rewritten in place, and a missing
setting is added before the first ``Match`` block (or at the end). It does not
move an operator's ``Include`` lines or edit drop-ins other packages own, so a
drop-in read earlier can still win. That is exactly what verification is for:
:func:`verify` re-reads the host with :mod:`.sshd_config`, independently of
the edit, and any setting sshd would not use as planned fails the check.

Every change keeps a byte-for-byte backup; :func:`rollback` puts it back
atomically and proves the file hashes to what it was before.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import difflib
import hashlib
import os
from pathlib import Path
import tempfile

from . import sshd_config

ACTION_TYPE = "harden_ssh_access"
MARKER = ".riskops-lab"
BACKUPS = "var/backups/riskops"
PARAMETERS = ("disable_root_login", "enforce_key_auth")


class ExecutorRefused(RuntimeError):
    """The executor would not start: bad parameters, target or host state. Nothing was changed."""


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def desired(parameters: dict) -> dict[str, str]:
    """Typed parameters -> the sshd settings they require. Anything else is refused."""
    unknown = sorted(set(parameters) - set(PARAMETERS))
    if unknown:
        raise ExecutorRefused(f"unknown parameters {unknown}")
    if any(not isinstance(parameters.get(name, False), bool) for name in PARAMETERS):
        raise ExecutorRefused("parameters must be true or false")
    wanted: dict[str, str] = {}
    if parameters.get("disable_root_login"):
        wanted["permitrootlogin"] = "no"
    if parameters.get("enforce_key_auth"):
        wanted.update(passwordauthentication="no", kbdinteractiveauthentication="no", pubkeyauthentication="yes")
    if not wanted:
        raise ExecutorRefused("the parameters ask for no change")
    return wanted


@dataclass(frozen=True)
class Check:
    setting: str
    expected: str
    effective: str
    source: str
    ok: bool


@dataclass(frozen=True)
class Verification:
    ok: bool
    checks: tuple[Check, ...]
    problems: tuple[str, ...]
    file_sha256: str

    def to_dict(self) -> dict:
        return {"ok": self.ok, "checks": [asdict(check) for check in self.checks],
                "problems": list(self.problems), "file_sha256": self.file_sha256}


@dataclass(frozen=True)
class Change:
    file: str
    before_sha256: str
    after_sha256: str
    backup: str
    edits: tuple[dict, ...]
    diff: tuple[str, ...]


class HardenSshExecutor:
    action_type = ACTION_TYPE

    def __init__(self, host_root: Path, asset_id: str) -> None:
        root = host_root.resolve()
        marker = root / MARKER
        if root == Path(root.anchor) or not marker.is_file() or marker.is_symlink():
            raise ExecutorRefused(f"{host_root} is not a marked lab copy of a host")
        if marker.read_text(encoding="utf-8").strip() != asset_id:
            raise ExecutorRefused(f"the lab copy at {host_root} is not {asset_id}")
        self.root, self.asset_id = root, asset_id
        self.config = root / sshd_config.MAIN

    def state(self) -> dict[str, dict[str, str]]:
        """What sshd would use for every managed setting, and from where."""
        config = sshd_config.read(self.root)
        state = {}
        for name, label in sshd_config.CANONICAL.items():
            value, source = config.effective(name)
            state[label] = {"value": value, "from": source}
        return state

    def apply(self, plan_id: str, parameters: dict) -> Change:
        wanted = desired(parameters)
        if self.config.is_symlink() or not self.config.is_file():
            raise ExecutorRefused("sshd_config is missing or not a regular file")
        before = self.config.read_bytes()
        if sshd_config.read(self.root).problems:
            raise ExecutorRefused("sshd_config cannot be read as it is; refusing to edit it")
        lines = before.decode("utf-8").splitlines(keepends=True)
        edits = _edit(lines, wanted)
        after = "".join(lines).encode("utf-8")
        backup = self.root / BACKUPS / plan_id / f"sshd_config.{_sha256(before)[7:19]}"
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_bytes(before)
        _replace(self.config, after)
        rel = self.config.relative_to(self.root).as_posix()
        diff = difflib.unified_diff(before.decode().splitlines(), after.decode().splitlines(),
                                    f"a/{rel}", f"b/{rel}", n=1, lineterm="")
        return Change(file=rel, before_sha256=_sha256(before), after_sha256=_sha256(after),
                      backup=backup.relative_to(self.root).as_posix(), edits=tuple(edits), diff=tuple(diff))

    def verify(self, parameters: dict) -> Verification:
        """Re-read the host and check every setting the parameters require."""
        wanted = desired(parameters)
        config = sshd_config.read(self.root)
        checks = []
        for name, value in wanted.items():
            label = sshd_config.CANONICAL[name]
            effective, source = config.effective(name)
            checks.append(Check(label, value, effective, source, effective == value))
            for directive in config.conditional(name):
                if directive.value.lower() != value:
                    checks.append(Check(label, value, directive.value.lower(),
                                        f"{directive.where} ({directive.match})", False))
        ok = not config.problems and all(check.ok for check in checks)
        return Verification(ok, tuple(checks), tuple(config.problems), _sha256(self.config.read_bytes()))

    def rollback(self, change: Change) -> dict:
        """Restore the backup and prove the file is byte-identical to before the change."""
        saved = (self.root / change.backup).read_bytes()
        if _sha256(saved) != change.before_sha256:
            raise ExecutorRefused("the backup does not match the recorded pre-change hash")
        _replace(self.config, saved)
        restored = _sha256(self.config.read_bytes())
        return {"file": change.file, "restored_sha256": restored,
                "matches_before": restored == change.before_sha256}


def _edit(lines: list[str], wanted: dict[str, str]) -> list[dict]:
    """Rewrite ``lines`` in place; return what changed."""
    first: dict[str, int] = {}
    first_match = None
    for index, raw in enumerate(lines):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        word = sshd_config.keyword(text.replace("=", " ").split()[0])
        if word == "match":
            first_match = index
            break
        first.setdefault(word, index)
    edits, added = [], []
    for name, value in wanted.items():
        label = sshd_config.CANONICAL[name]
        if name in first:
            index = first[name]
            old = lines[index].strip()
            if old.replace("=", " ").split()[1:] == [value]:
                continue
            lines[index] = f"{label} {value}\n"
            edits.append({"line": index + 1, "from": old, "to": f"{label} {value}"})
        else:
            added.append(f"{label} {value}\n")
    if added:
        at = first_match if first_match is not None else len(lines)
        if at and not lines[at - 1].endswith("\n"):
            lines[at - 1] += "\n"
        lines[at:at] = added
        edits.extend({"line": at + offset + 1, "from": None, "to": line.strip()} for offset, line in enumerate(added))
    return edits


def _replace(path: Path, data: bytes) -> None:
    """Write next to the file, keep its mode, then swap it in atomically."""
    mode = path.stat().st_mode & 0o7777
    handle, temporary = tempfile.mkstemp(prefix=".sshd_config.", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
