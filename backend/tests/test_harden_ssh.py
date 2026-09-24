"""The harden_ssh_access executor: typed, confined to a marked lab copy, verified, reversible."""
from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from app.tools.harden_ssh import MARKER, ExecutorRefused, HardenSshExecutor, desired

FIXTURES = Path(__file__).resolve().parents[2] / "examples" / "safety-demo" / "lab"
BOTH = {"disable_root_login": True, "enforce_key_auth": True}


def lab(tmp_path: Path, name: str) -> Path:
    return Path(shutil.copytree(FIXTURES / name, tmp_path / name))


def make_host(tmp_path: Path, text: str, asset: str = "lab-01") -> Path:
    root = tmp_path / asset
    (root / "etc/ssh").mkdir(parents=True)
    (root / "etc/ssh/sshd_config").write_text(text)
    (root / MARKER).write_text(asset + "\n")
    return root


def test_only_a_marked_lab_copy_of_the_named_asset_is_accepted(tmp_path):
    root = lab(tmp_path, "bastion-01")
    HardenSshExecutor(root, "bastion-01")
    with pytest.raises(ExecutorRefused, match="is not web-02"):
        HardenSshExecutor(root, "web-02")
    (root / MARKER).unlink()
    with pytest.raises(ExecutorRefused, match="not a marked lab copy"):
        HardenSshExecutor(root, "bastion-01")
    with pytest.raises(ExecutorRefused):
        HardenSshExecutor(Path("/"), "bastion-01")


@pytest.mark.parametrize("parameters", [{"shell": "rm -rf /"}, {"enforce_key_auth": "yes"},
                                        {"disable_root_login": False, "enforce_key_auth": False}])
def test_parameters_are_typed(parameters):
    with pytest.raises(ExecutorRefused):
        desired(parameters)


def test_apply_edits_in_place_adds_before_match_and_keeps_a_backup(tmp_path):
    root = lab(tmp_path, "bastion-01")
    config = root / "etc/ssh/sshd_config"
    config.chmod(0o600)
    before = config.read_bytes()
    executor = HardenSshExecutor(root, "bastion-01")
    change = executor.apply("AP-0001", BOTH)
    text = config.read_text()
    assert "PermitRootLogin no\n" in text and "PermitRootLogin yes" not in text
    assert text.index("PubkeyAuthentication yes") < text.index("Match User backup")
    assert [edit["to"] for edit in change.edits] == ["PermitRootLogin no", "PasswordAuthentication no",
                                                     "PubkeyAuthentication yes"]
    assert (root / change.backup).read_bytes() == before
    assert config.stat().st_mode & 0o777 == 0o600
    assert "-PermitRootLogin yes" in change.diff and "+PermitRootLogin no" in change.diff
    assert executor.verify(BOTH).ok
    assert executor.apply("AP-0002", BOTH).edits == ()  # already as planned: nothing to change


def test_a_drop_in_read_first_fails_verification_and_rollback_restores_every_byte(tmp_path):
    root = lab(tmp_path, "web-02")
    config = root / "etc/ssh/sshd_config"
    before = config.read_bytes()
    executor = HardenSshExecutor(root, "web-02")
    change = executor.apply("AP-0001", BOTH)
    report = executor.verify(BOTH)
    [failed] = [check for check in report.checks if not check.ok]
    assert (failed.setting, failed.effective, failed.source) == (
        "PasswordAuthentication", "yes", "etc/ssh/sshd_config.d/50-cloud-init.conf:1")
    restored = executor.rollback(change)
    assert restored["matches_before"] and config.read_bytes() == before


def test_a_match_block_that_weakens_a_setting_fails_verification(tmp_path):
    root = make_host(tmp_path, "PermitRootLogin yes\nMatch Address 10.0.0.0/8\n  PasswordAuthentication yes\n")
    executor = HardenSshExecutor(root, "lab-01")
    executor.apply("AP-0001", BOTH)
    report = executor.verify(BOTH)
    assert not report.ok
    assert any(check.source.endswith("(Match Address 10.0.0.0/8)") for check in report.checks if not check.ok)


def test_a_config_sshd_could_not_read_is_left_untouched(tmp_path):
    root = make_host(tmp_path, "PermitRootLogin yes\nPasswordAuthentication\n")
    before = (root / "etc/ssh/sshd_config").read_bytes()
    with pytest.raises(ExecutorRefused, match="cannot be read"):
        HardenSshExecutor(root, "lab-01").apply("AP-0001", BOTH)
    assert (root / "etc/ssh/sshd_config").read_bytes() == before


def test_rollback_refuses_a_backup_that_was_altered(tmp_path):
    root = lab(tmp_path, "bastion-01")
    executor = HardenSshExecutor(root, "bastion-01")
    change = executor.apply("AP-0001", BOTH)
    (root / change.backup).write_text("PermitRootLogin yes\n")
    with pytest.raises(ExecutorRefused, match="does not match"):
        executor.rollback(change)
