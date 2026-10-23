"""A network recovery set preserves original pending ACKs and both notice queues."""

from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import json
import os
import tempfile
from pathlib import Path

import pytest

from app.telemetry import network_store
from app.telemetry.network_protocol import encode, fingerprint
from app.telemetry.network_store import NetworkStore
from app.telemetry.network_worker import publish
from app.telemetry.store import TelemetryStore
from test_network_detection import event, profile
from test_network_incidents import NOW, drain, payload
from test_recovery_package import (
    build,
    needs_gpg,
    recovery,
    signing_key as signing_key,
    verify,
)

helper = recovery.network_helper()
collector = helper.collector


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    monkeypatch.setattr(network_store, "_now_us", lambda: int(NOW * 1_000_000))
    network = NetworkStore(tmp_path / "network.sqlite")
    console = TelemetryStore(tmp_path / "console.sqlite")
    components = [
        dict(name="network", kind="sqlite", path=network.path),
        dict(name="telemetry", kind="sqlite", path=str(console.path)),
    ]
    collectors, configs = [], []
    for index in range(3):
        state = tmp_path / f"collector-{index}"
        state.mkdir(mode=0o700)
        ssh = tmp_path / f"source-{index}.conf"
        ssh.write_text(
            f"Host synthetic-{index}\n HostName 192.0.2.{index + 1}\n User network-export\n"
        )
        ssh.chmod(0o600)
        config = {
            "version": 1,
            "endpoint": "http://127.0.0.1:8088/api/network/batches",
            "state_dir": str(state),
            "ssh_config": str(ssh),
            "ssh_host": f"synthetic-{index}",
            "token": "synthetic-secret-1234567890",
            "profile": asdict(profile(source_id=f"sensor-{index}")),
        }
        filename = tmp_path / f"collector-{index}.json"
        filename.write_text(json.dumps(config))
        filename.chmod(0o600)
        configs.append(json.loads(filename.read_text()))
        components.append(
            dict(
                name=f"collector-{index}",
                kind="state_dir",
                path=str(state),
                patterns=["*.state.json", "*.pending.json"],
            )
        )
        collectors.append(dict(state=f"collector-{index}", config=str(filename)))
    config = tmp_path / "package.json"
    config.write_text(
        json.dumps(
            dict(
                host_id="network-test",
                components=components,
                network_recovery=dict(
                    network_database="network",
                    console_database="telemetry",
                    collectors=collectors,
                    lock_timeout_seconds=1,
                ),
            )
        )
    )
    return dict(
        config=config,
        store=tmp_path / "packages",
        network=network,
        console=console,
        collectors=configs,
    )


def change_config(deployment, mutate):
    config = json.loads(deployment["config"].read_text())
    mutate(config)
    deployment["config"].write_text(json.dumps(config))


def seed(deployment, *, phase="complete", index=1, before=None):
    config = deployment["collectors"][0]
    source_profile = helper.profile_from_dict(config["profile"])
    body = payload(
        index,
        [event(n, source_profile=source_profile) for n in range(10)],
        before=before,
        source_profile=source_profile,
    )

    def send(_endpoint, _token, batch, _timeout):
        if phase == "before_commit":
            raise collector.CollectorError("test_no_commit")
        ack = deployment["network"].ingest(
            batch, source_profile, now_us=int(NOW * 1_000_000)
        )
        if phase == "lost_ack":
            raise collector.CollectorError("test_lost_ack")
        return ack

    result = collector.run_once(config, fetch=lambda *_: encode(body), send=send)
    if phase == "complete":
        assert result["status"] == "acknowledged"
    else:
        assert result["status"] == "error"
    if phase == "after_state":
        raise AssertionError("use complete then construct original pending")
    return body


@pytest.mark.parametrize(
    "change",
    [
        lambda c: c["network_recovery"].update(console_database="network"),
        lambda c: c["network_recovery"].update(collectors=[]),
        lambda c: c["network_recovery"].update(lock_timeout_seconds=True),
        lambda c: c["network_recovery"]["collectors"].append(
            c["network_recovery"]["collectors"][0]
        ),
        lambda c: c["network_recovery"]["collectors"][0].update(config="relative.json"),
        lambda c: c["components"][2].update(patterns=["*.state.json"]),
    ],
)
def test_bad_cohort_config_fails_before_capture(deployment, change):
    change_config(deployment, change)
    with pytest.raises(recovery.PackageError):
        recovery.load_config(deployment["config"])


def test_legacy_network_capture_is_rejected(deployment):
    change_config(deployment, lambda c: c.pop("network_recovery"))
    assert (
        recovery.main(
            [
                "build",
                "--config",
                str(deployment["config"]),
                "--output-dir",
                str(deployment["store"]),
                "--allow-unencrypted",
            ]
        )
        == 2
    )
    assert list(deployment["store"].iterdir()) == []


def test_combined_http_and_network_cohort_is_explicitly_rejected(deployment):
    change_config(
        deployment,
        lambda c: c.update(
            http_recovery=dict(
                http_database="network",
                console_database="telemetry",
                collector_states=["collector-0"],
            )
        ),
    )
    with pytest.raises(recovery.PackageError, match="Combined"):
        recovery.load_config(deployment["config"])


@pytest.mark.parametrize(
    "phase", ["complete", "before_commit", "lost_ack", "after_state"]
)
def test_exact_pending_and_cursor_restore_and_replay(deployment, tmp_path, phase):
    body = seed(deployment, phase="complete" if phase == "after_state" else phase)
    config = deployment["collectors"][0]
    if phase == "after_state":
        collector.atomic_write(
            Path(config["state_dir"]) / "network.pending.json",
            dict(
                version=1,
                identity=collector.identity(config),
                payload_hash=fingerprint(body),
                batch=body,
            ),
        )
    result = build(deployment, "--allow-unencrypted")
    restored = tmp_path / "restored"
    verify(result["package"], "--into", str(restored))
    saved = NetworkStore(restored / "network.sqlite")
    config = {**config, "state_dir": str(restored / "collector-0")}
    if phase != "complete":

        def never_fetch(*_args):
            pytest.fail("a pending original must replay without any remote fetch")

        replayed = collector.run_once(
            config,
            fetch=never_fetch,
            send=lambda _e, _t, batch, _s: saved.ingest(
                batch,
                helper.profile_from_dict(config["profile"]),
                now_us=int(NOW * 1_000_000),
            ),
        )
        assert replayed["status"] == "acknowledged"
    with saved.connection() as db:
        assert db.execute("SELECT count(*) FROM network_receipts").fetchone()[0] == 10
        assert db.execute("SELECT count(*) FROM network_batches").fetchone()[0] == 1
    assert (
        json.loads((restored / "collector-0/network.state.json").read_text())["cursor"]
        == body["cursor_after"]
    )
    assert "synthetic-secret" not in json.dumps(result["manifest"])


@pytest.mark.parametrize(
    "damage", ["cursor", "pending", "mapping", "omitted_collector"]
)
def test_mismatched_network_recovery_is_not_published(deployment, damage):
    seed(deployment, phase="lost_ack" if damage == "pending" else "complete")
    config = deployment["collectors"][0]
    if damage == "cursor":
        path = Path(config["state_dir"]) / "network.state.json"
        data = json.loads(path.read_text())
        data["cursor"] = "wrong-cursor"
        collector.atomic_write(path, data)
    elif damage == "pending":
        path = Path(config["state_dir"]) / "network.pending.json"
        data = json.loads(path.read_text())
        data["batch"]["batch_id"] = "different-batch"
        data["payload_hash"] = fingerprint(data["batch"])
        collector.atomic_write(path, data)
    elif damage == "mapping":
        with Path(config["ssh_config"]).open("a") as file:
            file.write(" Port 2222\n")
    else:
        change_config(deployment, lambda c: c["network_recovery"]["collectors"].pop(0))
    assert (
        recovery.main(
            [
                "build",
                "--config",
                str(deployment["config"]),
                "--output-dir",
                str(deployment["store"]),
                "--allow-unencrypted",
            ]
        )
        == 2
    )
    assert list(deployment["store"].iterdir()) == []


def test_locks_span_state_capture_and_pin_but_network_reader_closes_before_console_copy(
    deployment, monkeypatch
):
    seed(deployment)
    pin, snapshot = recovery.pinned_http_databases, recovery.snapshot_database
    order = []

    @contextmanager
    def check_pin(specs, timeout):
        for config in deployment["collectors"]:
            with (Path(config["state_dir"]) / "collector.lock").open("a+b") as lock:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        order.append("locked")
        with pin(specs, timeout) as result:
            yield result

    def check_copy(spec, *args, **kwargs):
        for config in deployment["collectors"]:
            with (Path(config["state_dir"]) / "collector.lock").open("a+b") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if spec["name"] == "telemetry":
            # A new network write truncates WAL successfully while the slow
            # console copy is still pending; its snapshot remains at batch 1.
            config = deployment["collectors"][0]
            source_profile = helper.profile_from_dict(config["profile"])
            batch = payload(
                2,
                [event(20, source_profile=source_profile)],
                before="test-cursor-9",
                source_profile=source_profile,
            )
            deployment["network"].ingest(
                batch, source_profile, now_us=int(NOW * 1_000_000)
            )
            with deployment["console"]._connection(write=True) as db:
                db.execute("INSERT INTO notification_meta VALUES('test-later','1')")
        order.append(spec["name"])
        return snapshot(spec, *args, **kwargs)

    monkeypatch.setattr(recovery, "pinned_http_databases", check_pin)
    monkeypatch.setattr(recovery, "snapshot_database", check_copy)
    result = build(deployment, "--allow-unencrypted")
    assert order == ["locked", "network", "telemetry"]
    verify(result["package"], "--deep")


def test_busy_collector_preserves_old_package(deployment):
    kept = build(deployment, "--allow-unencrypted")["package"]
    with (Path(deployment["collectors"][1]["state_dir"]) / "collector.lock").open(
        "a+b"
    ) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        assert (
            recovery.main(
                [
                    "build",
                    "--config",
                    str(deployment["config"]),
                    "--output-dir",
                    str(deployment["store"]),
                    "--allow-unencrypted",
                ]
            )
            == 2
        )
    assert list(deployment["store"].iterdir()) == [kept]


@pytest.mark.parametrize("checkpoint", [0, 2])
def test_cross_database_notification_mismatch_rejected(deployment, checkpoint):
    seed(deployment)
    drain(deployment["network"])
    publish(deployment["network"], deployment["console"], NOW)
    with deployment["console"]._connection(write=True) as db:
        db.execute(
            "UPDATE notification_meta SET value=? WHERE name LIKE 'network-import:%'",
            (str(checkpoint),),
        )
    assert (
        recovery.main(
            [
                "build",
                "--config",
                str(deployment["config"]),
                "--output-dir",
                str(deployment["store"]),
                "--allow-unencrypted",
            ]
        )
        == 2
    )


@needs_gpg
def test_encrypted_restore_retries_notice_once_and_rejects_mixed_state(
    deployment, signing_key, tmp_path
):
    seed(deployment)
    drain(deployment["network"])

    def crash():
        raise RuntimeError("test crash after console commit")

    with pytest.raises(RuntimeError):
        publish(deployment["network"], deployment["console"], NOW, after_import=crash)
    result = build(deployment, "--recipient", signing_key, "--sign-key", signing_key)
    restored = tmp_path / "restore"
    verify(result["package"], "--into", str(restored))
    saved = NetworkStore(restored / "network.sqlite")
    console = TelemetryStore(restored / "telemetry.sqlite")
    assert saved.incidents()["total"] == 1
    assert publish(saved, console, NOW + 1) == 1
    console.run_notifications([], now=NOW + 1000)
    total = console.list_notifications(kind="network_incident")["total"]
    assert total == 1
    assert publish(saved, console, NOW + 1001) == 0
    console.run_notifications([], now=NOW + 2000)
    assert console.list_notifications(kind="network_incident")["total"] == total
    # Verification is performed before starting writers. Check a separately
    # extracted set, then prove a foreign cursor cannot pass the cohort check.
    untouched = tmp_path / "untouched"
    verify(result["package"], "--into", str(untouched))
    path = untouched / "collector-0/network.state.json"
    state = json.loads(path.read_text())
    state["identity"] = "0" * 64
    collector.atomic_write(path, state)
    with pytest.raises(recovery.PackageError, match="network recovery"):
        recovery.inspect_network_recovery(result["manifest"], untouched)


def test_deep_inspection_refuses_network_snapshot_without_cohort(deployment, tmp_path):
    result = build(deployment, "--allow-unencrypted")
    restored = tmp_path / "restore"
    verify(result["package"], "--into", str(restored))
    result["manifest"]["consistency"].pop("network_recovery")
    with pytest.raises(recovery.PackageError, match="explicit matching"):
        recovery.inspect_network_recovery(result["manifest"], restored)


def test_original_pending_after_previous_ack_is_replayable(deployment, tmp_path):
    first = seed(deployment)
    second = seed(deployment, phase="lost_ack", index=2, before=first["cursor_after"])
    result = build(deployment, "--allow-unencrypted")
    restored = tmp_path / "restore"
    verify(result["package"], "--into", str(restored))
    config = {**deployment["collectors"][0], "state_dir": str(restored / "collector-0")}
    saved = NetworkStore(restored / "network.sqlite")
    replay = collector.run_once(
        config,
        fetch=lambda *_: pytest.fail("must replay original pending"),
        send=lambda _e, _t, batch, _s: saved.ingest(
            batch,
            helper.profile_from_dict(config["profile"]),
            now_us=int(NOW * 1_000_000),
        ),
    )
    assert replay["status"] == "acknowledged"
    assert (
        json.loads((restored / "collector-0/network.state.json").read_text())[
            "last_batch_id"
        ]
        == second["batch_id"]
    )
    with saved.connection() as db:
        assert db.execute("SELECT count(*) FROM network_receipts").fetchone()[0] == 10
        assert db.execute("SELECT count(*) FROM network_batches").fetchone()[0] == 2


@pytest.mark.skipif(
    os.geteuid() != 0, reason="cross-account recovery ownership needs root"
)
def test_root_backup_of_service_owned_config_creates_usable_service_lock(deployment):
    uid, gid = 65534, 65534
    with tempfile.TemporaryDirectory(prefix="network-recovery-owner-") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        state = root / "state"
        state.mkdir(mode=0o700)
        os.chown(state, uid, gid)
        ssh = root / "ssh.conf"
        ssh.write_text("Host synthetic\n HostName 192.0.2.1\n User network-export\n")
        ssh.chmod(0o600)
        os.chown(ssh, uid, gid)
        config = {
            **deployment["collectors"][0],
            "state_dir": str(state),
            "ssh_config": str(ssh),
            "ssh_host": "synthetic",
        }
        filename = root / "collector.json"
        filename.write_text(json.dumps(config))
        filename.chmod(0o600)
        os.chown(filename, uid, gid)
        change_config(
            deployment,
            lambda c: (
                c["components"][2].update(path=str(state)),
                c["network_recovery"]["collectors"][0].update(config=str(filename)),
            ),
        )
        result = build(deployment, "--allow-unencrypted")
        expected = result["manifest"]["consistency"]["network_recovery"]["mappings"][0][
            "identity"
        ]
        assert (state / "collector.lock").stat().st_uid == uid
        # Fork inherits the actual collector helpers, so the unprivileged child
        # needs no access to the repository checkout under /root.
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
                loaded = collector.load_config(filename)
                assert collector.identity(loaded) == expected
                collector._secure_directory(state)
                with collector.collector_lock(state):
                    pass
            except BaseException:
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        os.chown(filename, uid + 1, gid)
        loaded = recovery.load_config(deployment["config"])
        with pytest.raises(helper.RecoveryError, match="mapping"):
            helper.mappings(loaded["network_recovery"], loaded["components"])


def test_network_lock_cannot_be_a_symlink_or_shared_inode(deployment, tmp_path):
    state = Path(deployment["collectors"][0]["state_dir"])
    target = tmp_path / "target"
    target.write_text("keep")
    target.chmod(0o600)
    lock = state / "collector.lock"
    lock.symlink_to(target)
    with pytest.raises(helper.RecoveryError):
        with helper.locked_collectors([{"path": str(state)}]):
            pytest.fail("must reject a symlink")
    lock.unlink()
    lock.hardlink_to(target)
    with pytest.raises(helper.RecoveryError):
        with helper.locked_collectors([{"path": str(state)}]):
            pytest.fail("must reject a shared inode")
    assert target.read_text() == "keep"
