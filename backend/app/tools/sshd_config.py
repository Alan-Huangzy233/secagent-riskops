"""Read the settings sshd would actually use from a host's sshd_config.

This is the verifier's view of a host, written independently of the executor
that edits the file: it re-reads everything from disk and applies sshd's own
precedence rules instead of trusting what the executor says it wrote.

- For each keyword the **first** value sshd reads is the one it uses, and an
  ``Include`` is read in place, its files in lexical order. A drop-in included
  near the top of the file therefore beats a line further down.
- Lines after a ``Match`` apply only to matching connections and can override
  the global value for them. The verifier does not evaluate the criteria; it
  reports every conditional value so a check can refuse any that weakens it.
  A ``Match`` in an included file ends with that file.
- A keyword that is never set has sshd's compiled-in default (OpenSSH 9).

Paths are read inside a host root: ``/etc/ssh/...`` in the file means
``<root>/etc/ssh/...``. An include that leaves the root, a symbolic link, or a
line sshd could not read is reported as a problem, never skipped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import glob
from pathlib import Path
import re

MAIN = "etc/ssh/sshd_config"
ALIASES = {"challengeresponseauthentication": "kbdinteractiveauthentication"}
CANONICAL = {"permitrootlogin": "PermitRootLogin", "passwordauthentication": "PasswordAuthentication",
             "kbdinteractiveauthentication": "KbdInteractiveAuthentication",
             "pubkeyauthentication": "PubkeyAuthentication"}
DEFAULTS = {"permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
            "kbdinteractiveauthentication": "yes", "pubkeyauthentication": "yes"}
_LINE = re.compile(r"\s*([A-Za-z][A-Za-z0-9]*)\s*(?:=\s*|\s+)(.*?)\s*$")


def keyword(word: str) -> str:
    """Lower-case keyword with sshd's aliases folded in."""
    word = word.lower()
    return ALIASES.get(word, word)


@dataclass(frozen=True)
class Directive:
    keyword: str  # folded, lower case
    value: str
    file: str  # relative to the host root
    line: int
    match: str | None  # the Match line this falls under, None in the global section

    @property
    def where(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class Config:
    directives: list[Directive] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def effective(self, name: str) -> tuple[str, str]:
        """(value, where it came from) for the global section; ``default`` when unset."""
        name = keyword(name)
        for directive in self.directives:
            if directive.keyword == name and directive.match is None:
                return directive.value.lower(), directive.where
        return DEFAULTS.get(name, ""), "default"

    def conditional(self, name: str) -> list[Directive]:
        name = keyword(name)
        return [d for d in self.directives if d.keyword == name and d.match is not None]


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def read(root: Path, main: str = MAIN) -> Config:
    """Parse ``<root>/<main>`` and everything it includes, in sshd's reading order."""
    config = Config()
    _read_file(root, root / main, config, match=None, depth=0)
    return config


def _read_file(root: Path, path: Path, config: Config, *, match: str | None, depth: int) -> None:
    rel = path.relative_to(root).as_posix() if _inside(root, path) else str(path)
    if depth > 16:
        config.problems.append(f"{rel}: includes nested too deeply")
        return
    if path.is_symlink() or not _inside(root, path) or not path.is_file():
        config.problems.append(f"{rel}: not a regular file inside the host root")
        return
    config.files.append(rel)
    current = match
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        parsed = _LINE.fullmatch(text)
        if parsed is None or not parsed.group(2):
            config.problems.append(f"{rel}:{number}: sshd could not read {text!r}")
            continue
        word, value = keyword(parsed.group(1)), parsed.group(2)
        if word == "match":
            current = f"Match {value}"
            continue
        if word == "include":
            for pattern in value.split():
                _include(root, pattern, config, match=current, depth=depth, where=f"{rel}:{number}")
            continue
        config.directives.append(Directive(word, value.strip('"'), rel, number, current))


def _include(root: Path, pattern: str, config: Config, *, match: str | None, depth: int, where: str) -> None:
    if pattern.startswith("~"):
        config.problems.append(f"{where}: include {pattern!r} depends on a home directory")
        return
    base = root / (pattern.lstrip("/") if pattern.startswith("/") else f"etc/ssh/{pattern}")
    if not _inside(root, base.parent):
        config.problems.append(f"{where}: include {pattern!r} leaves the host root")
        return
    found = sorted(glob.glob(str(base)))
    if not found and not glob.has_magic(pattern):
        config.problems.append(f"{where}: include {pattern!r} does not exist")
    for name in found:
        _read_file(root, Path(name), config, match=match, depth=depth + 1)
