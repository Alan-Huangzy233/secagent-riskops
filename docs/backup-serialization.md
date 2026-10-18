# Serialize local backup jobs

The plain SQLite backup and encrypted recovery package can each create a large
working copy. Calendar times do not prevent their disk usage from overlapping:
a long backup can reach the next timer, and both `Persistent=true` timers can
catch up when the host starts.

The two services now wrap **each** heavy `ExecStart` with the same exclusive
`flock`: telemetry, additional control/AI snapshots, recovery-package `build`,
and recovery-package `prune`. The lock stays with the command until it exits
(`--no-fork`). Commands may interleave between separate `ExecStart` lines, but
normal wrapped command executions cannot overlap. The timers and their randomized delays
are unchanged; neither scheduled nor catch-up execution guarantees plain-first
order. This is process coordination, not a paired database snapshot guarantee.

The plain service still runs as `riskops:riskops`; recovery-package still runs
as root to read components owned by several service accounts. A root-owned local
lock directory (`0750`, group `riskops`) contains a pre-created lock file
(`0660`, `root:riskops`). Neither service manages it with `RuntimeDirectory` or
`StateDirectory`, and the pulling backup account gets no access. `PrivateTmp`
remains enabled: `/tmp` is not a shared lock location. `ProtectSystem=strict`
permits writing **only the existing lock file**, not its parent directory.
Missing files fail unit setup; pre-start checks also refuse symlinks and files
that the service account cannot read and write. The services do not create the
lock or repair its ownership.

## Install or upgrade

Changing a release symlink or the repository templates does **not** update
installed systemd units, drop-ins or tmpfiles configuration. Prepare and review
the following changes as a separate maintenance operation. Commands below are
for a root operator, with the repository checkout as the current directory.

1. Record the effective configuration before editing it:

   ```sh
   systemctl cat secagent-riskops-backup.service secagent-riskops-recovery-package.service
   systemctl show secagent-riskops-backup.service secagent-riskops-recovery-package.service \
     -p User -p Group -p ExecStart -p Environment -p ReadWritePaths -p KillMode -p TimeoutStartUSec
   systemctl is-enabled secagent-riskops-backup.timer secagent-riskops-recovery-package.timer
   systemctl list-timers --all secagent-riskops-backup.timer secagent-riskops-recovery-package.timer
   ```

   Save copies of the installed service files and **all** their drop-ins in a
   private operator-chosen directory. Inventory every `ExecStart`, database path,
   destination, additional permission and retention override. Do not replace
   locally customized paths with the example defaults.

2. Stop **only the timers** so no new scheduled work enters during the change:

   ```sh
   systemctl stop secagent-riskops-backup.timer secagent-riskops-recovery-package.timer
   systemctl show secagent-riskops-backup.service secagent-riskops-recovery-package.service \
     -p ActiveState -p SubState -p Result
   ```

   Wait for both services and any manually started backup command to finish on
   their own. `activating` is normal while a oneshot is working or waiting; do
   not stop/kill a running backup to install the lock. Verify that both services
   are inactive and inspect any previous failure. Do not unlink, truncate or
   recreate a lock file while any holder or waiter exists: a new inode would
   allow two independent locks. Stop and investigate an unexpected existing
   symlink or an incorrectly owned lock directory before installation.

3. Install the tmpfiles rule and create the protected lock before loading the
   services. The `riskops` account and group must already exist:

   ```sh
   install -m 0644 deploy/tmpfiles.d/secagent-riskops-backup.conf \
     /etc/tmpfiles.d/secagent-riskops-backup.conf
   systemd-tmpfiles --create /etc/tmpfiles.d/secagent-riskops-backup.conf
   stat -c '%a %U:%G %n' /run/secagent-riskops-backup \
     /run/secagent-riskops-backup/maintenance.lock
   ```

   Expect `750 root:riskops` for the directory and `660 root:riskops` for the
   regular lock file. The rule uses `f`, not `f+`; it does not truncate an existing
   file. Install the reviewed service templates to their existing unit paths,
   preserving any local adaptations, then migrate the extra commands below.
   Keep the timer calendar values and existing enabled/disabled policy.

4. Update every additional `ExecStart` in the effective plain service. For
   example, an existing `20-manual-control.conf` that adds the control snapshot
   must have its command replaced with this wrapped equivalent:

   ```ini
   [Service]
   ExecStart=/usr/bin/flock --exclusive --timeout 10800 --conflict-exit-code 75 --no-fork /run/secagent-riskops-backup/maintenance.lock /usr/bin/python3 /opt/secagent-riskops/current/scripts/backup_telemetry.py --database /var/lib/secagent-riskops/control.sqlite --directory /var/backups/secagent-riskops/control
   ```

   Replace that existing drop-in; **do not append a second copy** while leaving
   the old command active. The [extra database example](../deploy/systemd/backup-extra-databases.conf.example)
   also shows an optional AI snapshot. Only enable it if that database exists,
   its actual path is correct and `riskops` already has the necessary access.
   A drop-in containing a blank `ExecStart=` clears the base command list: if
   using that approach, explicitly re-list **all** original commands, including
   telemetry, once each with the wrapper. Never lose an existing backup while
   consolidating drop-ins. Recovery-package's `build` **and** `prune` must also
   retain the wrapper when locally overridden.

   Keep retention overrides unchanged. For example, a separate
   `30-retention.conf` containing `Environment=RISKOPS_BACKUP_KEEP=3` still applies
   through `flock` to every plain snapshot; do not reset it to the template's
   default of seven. Preserve all original recovery `build` arguments, recipients
   and `prune --keep 2 --require-confirmations 1 --apply` (or the installation's
   explicitly configured stricter policy).

5. Validate and inspect the effective units before re-enabling scheduled work:

   ```sh
   systemd-analyze verify /etc/systemd/system/secagent-riskops-backup.service \
     /etc/systemd/system/secagent-riskops-recovery-package.service
   systemctl daemon-reload
   systemctl show secagent-riskops-backup.service secagent-riskops-recovery-package.service \
     -p User -p Group -p ExecStartPre -p ExecStart -p Environment -p ReadWritePaths \
     -p KillMode -p TimeoutStartUSec
   ```

   Adapt the validation paths if the installed unit files live elsewhere. Check
   **every expanded command**, including control/AI drop-ins, for the identical
   `/run/secagent-riskops-backup/maintenance.lock` path and bounded wait. Ensure
   `ReadWritePaths` includes that exact file, `KillMode=control-group`, and the
   original service accounts and backup parameters remain intact. No command
   should prefix `-` to ignore failure or list `75` as a success exit status.

   Restore only the timers that were previously active/enabled. Starting a
   persistent timer can immediately queue missed work; do so after validation
   and after checking space for one complete backup job. Observe the journal
   and verify newly published outputs. For a manual verification, use
   `systemctl start secagent-riskops-backup.service` or
   `systemctl start secagent-riskops-recovery-package.service` and inspect its
   result. Do not run real backup jobs merely to check whether the lock exists.

## Waiting, failure and retained copies

A command waits at most 10,800 seconds (three hours) for the lock. Timeout exits
with status `75` and runs no backup body. Other command exit statuses propagate
unchanged. A failed `ExecStart` fails the service and prevents later commands,
including recovery pruning, from running. There is no automatic retry added by
this change. The job's overall startup timeout remains explicitly infinite so
waiting plus a legitimately long backup is not killed by a short default;
operators can still inspect a stuck unit and use the stop procedure below.

### Interrupting a stuck job

Normal backup commands synchronously wait for compression/encryption to finish
before returning, so their working sets remain inside the lock lifetime. This
wrapper does **not** guarantee mutual exclusion throughout forced termination:
the Python holder can exit before its `zstd`/`gpg` children finish reacting to
SIGTERM, releasing the lock early. `KillMode=control-group` signals all service
processes, but does not make their exits simultaneous.

For an intentional interruption, first pause both timers. Identify the holder
and any waiting service using `systemctl status` and `lslocks`; cancel the
**waiter first**, then stop the holder. Wait until both service cgroups are empty
and both services have finished stopping before restarting either service or
its timer. Check failed-unit results and leftover temporary files separately.
Do not leave an already waiting successor eligible to start while stopping the
holder. Do not kill only one PID or switch to `KillMode=process`; that can leave
compression/encryption children alive. If the holder/waiter cannot be identified,
keep the timers paused and investigate before interrupting the job.

`Persistent=true` remembers a timer's **last trigger**, not its last success.
It coalesces missed calendar triggers while the timer was inactive into a
catch-up run (subject to the configured randomized delay). It does not promise
an immediate retry after failure or after a machine dies during an already
triggered run. Resolve the failure and explicitly start the service, or wait for
the next scheduled trigger; the other waiting job can continue when the lock is
released. A service already active is not started as a second instance.

Retention is unchanged: plain copies are verified and atomically published
before their existing generation limit rotates old copies. Recovery packages
are built and published before the separate prune command; pruning still
requires matching independent-copy confirmations and retains its minimum local
generations. Lock contention or backup failure must not delete older verified
copies to make room. Interrupted temporary files are not promoted to verified
backups; investigate leftover temporary files separately without widening the
retention deletion rules.

During normal command execution, the lock removes the **overlapping** working
sets of cooperating commands. A single job can still exhaust space, and normal
ingest continues consuming disk.
Check headroom for the job's snapshots plus compressed/encrypted staging; do not
claim this lock solves all ENOSPC failures. It does not coordinate NAS pulls or
arbitrary commands that bypass the wrapper. A direct invocation of
`backup_telemetry.py` or `recovery_package.py` does not acquire the service lock:
prefer the service entry points, or use the identical `flock` wrapper and
pre-existing protected lock for an explicitly planned manual command.

## Rollback

Pause the two timers, wait for active services/manual backup commands to finish,
restore the saved unit files and drop-ins, reload systemd, inspect the expanded
commands, and restore the prior timer policy. Do not mix wrapped and unwrapped
backup commands while accepting new work. The lock and its tmpfiles rule can
remain when no service uses them; removing them is unnecessary. No backup files,
retention settings or application databases need to change for this rollback.
