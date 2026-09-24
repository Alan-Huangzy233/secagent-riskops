"""The verifier's reading of sshd_config follows sshd's precedence, and refuses what it cannot read."""
from __future__ import annotations

from pathlib import Path

from app.tools import sshd_config


def host(tmp_path: Path, main: str, dropins: dict[str, str] | None = None) -> Path:
    ssh = tmp_path / "etc" / "ssh"
    (ssh / "sshd_config.d").mkdir(parents=True)
    (ssh / "sshd_config").write_text(main)
    for name, text in (dropins or {}).items():
        (ssh / "sshd_config.d" / name).write_text(text)
    return tmp_path


def test_the_first_value_sshd_reads_is_the_one_it_uses(tmp_path):
    config = sshd_config.read(host(tmp_path, "PasswordAuthentication no\nPasswordAuthentication yes\n"))
    assert config.effective("PasswordAuthentication") == ("no", "etc/ssh/sshd_config:1")


def test_an_include_is_read_in_place_in_lexical_order(tmp_path):
    root = host(tmp_path, "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n",
                {"60-b.conf": "PasswordAuthentication no\n", "50-a.conf": "PasswordAuthentication yes\n"})
    config = sshd_config.read(root)
    assert config.effective("passwordauthentication") == ("yes", "etc/ssh/sshd_config.d/50-a.conf:1")
    assert config.files == ["etc/ssh/sshd_config", "etc/ssh/sshd_config.d/50-a.conf",
                            "etc/ssh/sshd_config.d/60-b.conf"]


def test_a_relative_include_is_relative_to_etc_ssh(tmp_path):
    root = host(tmp_path, "Include sshd_config.d/*.conf\n", {"x.conf": "PermitRootLogin no\n"})
    assert sshd_config.read(root).effective("PermitRootLogin")[0] == "no"


def test_unset_settings_have_sshds_defaults_and_aliases_fold(tmp_path):
    config = sshd_config.read(host(tmp_path, "ChallengeResponseAuthentication=no\n"))
    assert config.effective("PermitRootLogin") == ("prohibit-password", "default")
    assert config.effective("KbdInteractiveAuthentication") == ("no", "etc/ssh/sshd_config:1")


def test_match_blocks_are_conditional_and_end_with_an_included_file(tmp_path):
    root = host(tmp_path, "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n"
                          "Match Address 10.0.0.0/8\n  PasswordAuthentication yes\n",
                {"10-x.conf": "Match User deploy\n  PermitRootLogin yes\n"})
    config = sshd_config.read(root)
    assert config.effective("PasswordAuthentication") == ("no", "etc/ssh/sshd_config:2")
    assert config.effective("PermitRootLogin")[1] == "default"
    [conditional] = config.conditional("PasswordAuthentication")
    assert conditional.match == "Match Address 10.0.0.0/8" and conditional.line == 4
    assert config.conditional("PermitRootLogin")[0].match == "Match User deploy"


def test_what_sshd_could_not_read_is_reported_not_skipped(tmp_path):
    root = host(tmp_path, "Include /etc/ssh/missing.conf\nPermitRootLogin\nInclude ../../../etc/passwd\n")
    problems = sshd_config.read(root).problems
    assert any("missing.conf' does not exist" in p for p in problems)
    assert any("could not read 'PermitRootLogin'" in p for p in problems)
    assert any("leaves the host root" in p for p in problems)


def test_a_symbolic_link_is_not_followed(tmp_path):
    outside = tmp_path / "outside.conf"
    outside.write_text("PasswordAuthentication yes\n")
    root = host(tmp_path / "h", "Include /etc/ssh/sshd_config.d/*.conf\n")
    (root / "etc/ssh/sshd_config.d/10-link.conf").symlink_to(outside)
    config = sshd_config.read(root)
    assert config.effective("PasswordAuthentication")[1] == "default"
    assert any("not a regular file" in p for p in config.problems)
