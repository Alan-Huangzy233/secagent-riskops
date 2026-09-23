# Manual IP blocking

Manual controls are separate from SSH log collection. They do not grant shell
access to the collector key and do not authorize an AI model to execute actions.
The console records a manual operator request, and the controller sends bounded
requests through a separate SSH forced-command key to each selected source.
The current console uses one configured operator account. Its preview and
confirmation step is a manual safeguard, not a second-person approval workflow,
role-based access control, or authorization for autonomous model actions.

## Console workflow

1. Select explicit IP/source pairs from alerts, or enter an IP and select its
   destination servers. Changing pages preserves the selection; it does not
   select every matching historical alert.
2. Choose SSH, TCP and/or UDP, a duration, and a reason of 1–300 characters. The
   durations are 5, 15 or 30 minutes, 1 hour, 24 hours, or permanent. The default
   is SSH for 1 hour.
3. Preview the expanded target list, check every source, address and channel,
   then confirm that plan. A plan expires after 5 minutes; changing a selection
   requires another preview. A batch contains at most 100 expanded operations.
4. Read the per-target results. Submission queues a durable job on the central
   server; it does not mean every target has applied the change. An uncertain
   result requires checking the target state before creating a new request.
5. To remove a block, choose its unban preview, review it, then confirm. Removing
   one channel does not remove another channel's block for the same IP.
6. Once a ban on the SSH or TCP channel is verified, the alerts for that peer whose
   participating sources all hold a verified SSH-covering block move to the
   "resolved" triage state, with the job ID and the reason as the record. A
   partially covered alert, a UDP-only ban and an unban never change triage.
   See "处置状态" in `ssh-detection.md`.

The console shows the last verified state and the latest source check. When a
source is unavailable, the last confirmed entries remain visible with a failed
or stale check; they are not proof of the current firewall state. The central
worker refreshes source observations approximately every minute when it is not
processing queued work. These observations do not repair a missing table.

## Scope and expiry

Each operation targets one IPv4 or IPv6 address and one channel:

| Channel | Packets affected on the selected server |
| --- | --- |
| `ssh` | Incoming TCP from that address to the configured local SSH ports |
| `tcp` | All incoming TCP from that address to local services |
| `udp` | All incoming UDP from that address to local services |

The console can expand a selection into separate source/address/channel
operations. Selecting TCP already covers SSH; the console should remove that
redundant selection. Removing an SSH block does not override a remaining TCP
block. Each channel has its own persisted state and result.

Only the local `input` hook is modified. Forwarded traffic and the `output` hook
are not filtered by this helper. However, replies to connections initiated by
the server arrive through `input`: a TCP/UDP block also prevents those replies
from the blocked address. It can therefore interrupt existing connections and
services used by that peer. This is not a cloud security-group rule.

The console offers finite durations or permanent blocking. A timed request
contains a fixed Unix deadline, at most 86,400 seconds in the future. Kernel
element timeouts remove timed entries even when the central server is offline.
Permanent entries use `expires_at: null`: they have no automatic expiry and are
retained in the source's desired-state database until removed. This is not a
guarantee that rules survive an external firewall replacement without recovery;
see restart recovery below. No part of blocking depends on the operator's
desktop remaining powered on.

## Source installation

The source needs Python 3.11+, nftables with its JSON interface, iproute2, and
root privileges for this narrowly scoped helper. Install the standalone
`scripts/ssh_block_control.py` at the fixed path
`/usr/local/sbin/riskops-ssh-control`. Both the gateway and the restore service
invoke it as `/usr/bin/python3 -I /usr/local/sbin/riskops-ssh-control`.
Install `scripts/control_gateway.py` at
`/usr/local/libexec/riskops-control-gateway.py`. Both scripts must be root-owned
and neither file nor any parent directory may be writable by a non-root account.

The fixed configuration path is
`/etc/secagent-riskops/ssh-block-control.json`. Its contents and all deployment
credentials are private runtime configuration, not repository files. Example
using documentation addresses:

```json
{
  "source_id": "source-a",
  "ssh_ports": [22022],
  "protected_networks": ["198.51.100.10/32", "192.0.2.0/28", "2001:db8:1::/64"],
  "max_ttl_seconds": 86400
}
```

The configuration must have mode `0600`, root ownership, and trusted root-owned
parent directories. `protected_networks` must be nonempty and contain every
management peer or management network, including the central server, bastion,
inter-server administration paths, and an operator's management/VPN address.
These addresses must reflect the source addresses actually visible to the
target, including any NAT or relay. Do not use a catch-all network unless the
intention is to prevent all blocking.

The helper adds locally assigned IPs and the SSH connection's peer/local
addresses to protection. IPv4-mapped IPv6 inputs are normalized before checking
protection. Requests cannot supply protection exemptions, CIDRs, ports,
filesystem paths, or commands. Loopback, unspecified, multicast, and link-local
targets are rejected. Refresh protection by running the local restore command
after changing management networks or interface addresses.

The sample ports and addresses in this document are illustrative. Substitute
private runtime values during installation and keep those files out of Git.

## Restricted gateway and relay

Use a dedicated unprivileged SSH account and a separate control key; do not
extend the journal export key. Its `authorized_keys` entry must use `restrict`
and the fixed forced command
`/usr/bin/python3 -I /usr/local/libexec/riskops-control-gateway.py`. Restrict the
key's allowed source with `from=` to the actual connecting central or relay
address where practical. The gateway refuses any SSH remote command or command
line arguments, so clients send only protocol JSON on standard input. It cannot
be used as an interactive shell or a general command dispatcher.

The gateway reads the root-owned fixed file
`/etc/riskops-control/gateway.json`. The file and its parent directories must
not be writable by the control account, group or other users. A root-owned
`0750` directory and `0640` file readable by the control account's dedicated
group are suitable. A relay that also represents `source-a` can use:

```json
{
  "local_source_id": "source-a",
  "ssh_config": "/etc/riskops-control/ssh_config",
  "relays": {"source-b": "source-b-control"}
}
```

On `source-b`, set `local_source_id` to `source-b` and `relays` to `{}`. The
`ssh_config` field remains required, but it is only read for a relayed request.
Each destination needs its own helper configuration with the corresponding
source ID and locally protected SSH ports.

The gateway dispatches its local source only through this fixed sudo command:

```text
/usr/bin/sudo -n /usr/bin/python3 -I /usr/local/sbin/riskops-ssh-control
```

Grant the dedicated account sudo permission for that exact executable and
argument sequence, with no wildcard arguments. Validate the sudoers entry with
`visudo`. Preserve the sshd-provided `SSH_CONNECTION` for that command so the
helper can protect the current control connection. The mandatory management
allowlist remains the primary protection; do not rely on that environment
variable alone. Do not grant sudo for the gateway itself or an arbitrary Python
script path.

For a relayed request, the gateway selects a fixed alias from `relays` and runs
SSH without a remote command. Keep relay SSH configuration and private keys
root-owned and readable only by the dedicated control account/group. Use a
dedicated restricted key on the destination and pin its host key in a private
`known_hosts` file, verified through an already trusted channel. For example:

```sshconfig
Host source-b-control
    HostName 198.51.100.21
    Port 22022
    User riskops-control
    IdentityFile /etc/riskops-control/source-b.key
    IdentitiesOnly yes
    UserKnownHostsFile /etc/riskops-control/known_hosts
    StrictHostKeyChecking yes
    BatchMode yes
    RequestTTY no
    ForwardAgent no
    ClearAllForwardings yes
```

Never interpolate a request into a shell command. Only administrator-pinned
source IDs and aliases are routable. The gateway checks the response identity
before returning it to the central server.

## Central configuration

Set `RISKOPS_CONTROL_CONFIG` to an absolute private JSON file path, for example
`/etc/secagent-riskops/control.json`, and restart the central service after
changing configuration. Without the variable, manual controls stay disabled.
With the variable set, an invalid configuration prevents service startup.

```json
{
  "database_path": "/var/lib/secagent-riskops/control.sqlite",
  "ssh_config": "/etc/secagent-riskops/control/ssh_config",
  "sources": [
    {"source_id": "source-a", "ssh_host": "control-relay", "ssh_ports": [22022]},
    {"source_id": "source-b", "ssh_host": "control-relay", "ssh_ports": [22022]}
  ],
  "protected_networks": ["198.51.100.10/32", "192.0.2.0/28", "2001:db8:1::/64"]
}
```

Source IDs must exactly match the telemetry source IDs. `ssh_host` is a fixed
alias in the private central SSH configuration; both sources can use one relay,
which dispatches by `source_id`. Direct connections can use separate aliases.
The displayed `ssh_ports` must agree with each target helper's actual configured
ports. The central server does not send port choices to the target.

Configure `control-relay` like the SSH example above, using its destination
address, its own dedicated key and a verified host key. Make the configuration
and key readable by the central service account, with root-owned files and
directories that the service account cannot modify. The control database is
separate from telemetry storage and must be writable by the service account.
Keep database permissions private and include it in consistent SQLite backups:
plans, jobs, operational addresses and the audit chain are sensitive runtime
data. The local hash chain helps detect changes when compared against a trusted
copy; it is not an independent, tamper-proof audit service.

Use HTTPS or a trusted encrypted tunnel for the authenticated console. The
control API uses the existing Basic operator credentials. `GET /api/controls`
returns capabilities, source observations, recent jobs, blocks and a CSRF token.
Writes require `Content-Type: application/json` and `X-RiskOps-CSRF`; foreign
origins are rejected. The preview request is:

```json
{
  "action": "ban",
  "targets": [{"source_id": "source-a", "ip": "203.0.113.30"}],
  "channels": ["ssh"],
  "duration_seconds": 3600,
  "reason": "Operator reviewed the matching authentication evidence"
}
```

Send it to `POST /api/controls/preview`, then confirm the returned immutable
plan with `POST /api/controls/execute` and `{"plan_id":"<returned-plan-id>"}`.
Execution returns HTTP 202 and a job ID; poll `GET /api/controls/jobs/{job_id}`.
Confirming the same plan again returns its existing job. For an unban use
`action: "unban"` with the explicit channels; the duration field is still
required by the request schema but does not set an unban deadline. Permanent
bans use `duration_seconds: null`.

Run one central control worker. It processes durable jobs in order, retries
transport uncertainty with the same request IDs and original deadlines, and
records per-target success, rejection or uncertainty. This is a single-operator
deployment, not a distributed job/approval service.

## Wire protocol

One JSON object is read from standard input, limited to 4,096 bytes. Every
request specifies `version: 1`, the exact configured `source_id`, an action and
a request ID. IDs allow ASCII letters, digits, underscore, period, colon and
hyphen, at most 128 characters; the first character must be alphanumeric.

```json
{
  "version": 1,
  "source_id": "source-a",
  "request_id": "operation-001",
  "action": "add",
  "ip": "203.0.113.30",
  "channel": "ssh",
  "expires_at": 2000003600
}
```

The example timestamp is illustrative; the controller generates a deadline from
the selected duration. The same request ID and deadline must be retained across
transport retries. The optional `ttl_seconds` is a validated integer from 1 to
the configured maximum; `expires_at` is the authoritative deadline.

- `add`: requires `ip`, `channel`, and an integer `expires_at` or `null`.
- `delete`: requires `ip` and `channel`; expiry fields are forbidden.
- `status`: optionally filters by `ip` and/or `channel`; otherwise lists entries.
- `check`: same read-only observation plus capability/readiness fields. It does
  not create the table. `table_present: false` is distinct from installed helper
  readiness.

Responses echo identity/target fields and include `status`, `code`, and either
`blocked`/`expires_at` for a single target or `blocks` for a list. Status values
are `ok`, `rejected`, `uncertain`, or `error`. A positive mutation result is sent
only after reading back the reserved table, its protection sets and block
entries. A timeout or failed readback is not success. Do not show a requested
block as applied before receiving verified results.

The remote SQLite receipt store deduplicates mutating requests. Reusing an ID
for a different payload is rejected. Replaying a completed request reports the
current state without reapplying the historical action. If a process died
between saving intent and applying it, replay reconciles the latest persisted
intent: a later deletion remains authoritative and an old add cannot resurrect
it. A definite atomic nftables rejection rolls the persisted intent back; an
uncertain result retains intent for reconciliation. The controller must preserve
these distinctions in its audit trail and per-target batch results.

## Firewall ownership and restart recovery

The helper owns only `table inet riskops_ssh_guard`, containing its own input
chain, management protection sets and six address/channel sets. It checks a
schema marker and exact chain/rule structure before modifying an existing table.
Unexpected changes fail closed with `firewall_schema_mismatch` rather than
modifying an administrator's policy. Changing SSH ports requires an explicit
schema migration, not editing an active table behind the helper's back.

Operations update only the helper's sets in one nftables batch. They never
flush the system ruleset or modify other tables. Management acceptance exits
this table's chain but cannot bypass a drop in another firewall chain.
Existing firewalls remain authoritative for the traffic they already filter.
These semantics follow the [nftables ruleset evaluation
documentation](https://www.netfilter.org/projects/nftables/manpage.html) and
[element timeout documentation](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts).

The dedicated state directory `/var/lib/riskops-control` must be root-owned with
mode `0700`. The helper creates a private SQLite database and file lock there.
Keep it outside application-writable directories. Back it up with a consistent
SQLite backup; it contains operational addresses and must not be published.

Install `deploy/systemd/secagent-riskops-control-restore.service` into
`/etc/systemd/system/` on each controlled source after preparing the root-owned
state directory, helper and configuration. Then run as root:

```sh
systemctl daemon-reload
systemctl enable --now secagent-riskops-control-restore.service
```

The supplied oneshot runs the fixed helper with `--restore`, after
`nftables.service` and `network-online.target`, with `CAP_NET_ADMIN` and write
access restricted to the state directory. `--restore` is local-only and is
rejected for an SSH invocation. Include the actual firewall manager in the unit
ordering when it differs. The service does not remain active after a successful
run; inspect `ExecMainStatus` and its journal rather than treating an inactive
oneshot as a failure.

The supplied unit restores at boot; it has no reload hook or recurring timer.
After an external firewall manager flushes or replaces the ruleset, run:

```sh
systemctl start secagent-riskops-control-restore.service
```

Integrate that action after firewall reloads in the deployment, or add a bounded
reconciliation timer if the manager has no reliable hook. Central status polling
is observation only and is not a substitute for restoration. Do not add
`flush ruleset` to any generated unit or config.

Restore recreates the reserved table if absent, removes expired/protected
persisted entries, reapplies permanent entries and calculates timed entries
from their original deadlines. Reboot or retry does not grant a fresh duration.
During a reboot or a firewall manager's ruleset replacement, blocks can be absent
until restore succeeds. Monitor restore failures and table presence instead of
assuming a historical success means a rule is still active. Clock correctness
matters when restoring wall-clock deadlines; keep the hosts synchronized.

## Validation

`backend/tests/test_ssh_block_control.py` covers typed input, protected addresses,
fixed deadlines, permanent restoration, pending-request recovery, stale retries,
readback failure, foreign schema rejection and restricted command generation.
Run it with the project's development dependencies. Before production activation,
also validate the helper against the installed nftables/kernel in isolated Linux
network namespaces: confirm TCP/UDP/channel scope, IPv4/IPv6 behavior, protected
source connectivity, expiry, deletion and boot restoration. Mock tests alone do
not establish packet-filter behavior.
