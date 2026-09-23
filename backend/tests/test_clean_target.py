"""Developer cleanup must preserve operational records and runtime data."""
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.mark.skipif(shutil.which("make") is None, reason="make is required")
def test_clean_preserves_private_data_and_does_not_follow_symlinks(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    shutil.copyfile(Path(__file__).parents[2] / "Makefile", workspace / "Makefile")
    protected = [
        ".local-audit/progress/task.md",
        ".local-audit/__pycache__/retained-record",
        "runtime-data/retained-data",
        "evidence/retained-evidence",
        "docs/private-notes.md",
        "backend/app/module.py",
        "scripts/tool.py",
        ".venv/lib/__pycache__/dependency.pyc",
    ]
    for name in protected:
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("keep " + name)
    caches = [".pytest_cache", "backend/__pycache__",
              "backend/app/__pycache__", "scripts/nested/__pycache__"]
    for name in caches:
        path = workspace / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "generated").write_text("cache")

    external = tmp_path / "external" / "__pycache__"
    external.mkdir(parents=True)
    (external / "keep").write_text("outside the project")
    (workspace / "backend" / "linked").symlink_to(external.parent, target_is_directory=True)
    (workspace / "scripts" / "__pycache__").symlink_to(external, target_is_directory=True)

    for _ in range(2):
        subprocess.run(["make", "clean"], cwd=workspace, check=True, capture_output=True)
    for name in protected:
        assert (workspace / name).read_text() == "keep " + name
    assert all(not (workspace / name).exists() for name in caches)
    assert (external / "keep").read_text() == "outside the project"
    assert (workspace / "backend" / "linked").is_symlink()
    assert (workspace / "scripts" / "__pycache__").is_symlink()
