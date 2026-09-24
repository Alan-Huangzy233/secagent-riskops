# Web demo

`docker compose up`, then open <http://127.0.0.1:8000/>. Without Docker,
`make install && make run` serves the same page. It needs no API key and no
network, and it never touches a real system.

## What it shows

The page replays the labelled synthetic week behind the headline numbers:
169,649 sshd log lines, seed 20261115, addresses in 198.18.0.0/15.

1. **Detection.** Sampled log lines scroll past while the counters and the
   hourly chart fill in. The rules run every 300 s over a sliding window, so
   an attack that keeps going keeps raising alerts.
2. **Reduction.** Alerts are merged into incidents by dedup and correlation.
   Each surfaced incident appears in the list when its last alert arrives.
   Its bar shows the score against the threshold of 25.
3. **Scoring.** An open incident shows its score built up reason by reason,
   for example `+50 login succeeded after failed attempts`. Next to it are the
   rules that fired, the accounts tried, and the raw log lines.
4. **Triage.** Claude's verdict, confidence and rationale are shown, and the
   log lines it cited are highlighted. These are the recorded calls from the
   evaluation, looked up by request fingerprint and replayed. The model read a
   dossier of the logs; it never saw the score or the labels.
5. **Response.** When a password was guessed, a fixed playbook proposes
   `harden_ssh_access` on that host. The page has two buttons:
   - **Request without approval.** The policy engine refuses the plan with
     `APPROVAL_REQUIRED`.
   - **Approve as security-operator and run.** The approval is recorded and
     bound to the plan's hash, and the policy engine allows the plan. The
     executor then works on a fresh temporary lab copy of the host:
     - on bastion-01 the change is verified;
     - on web-02 a cloud-init drop-in overrides it, so verification fails and
       the change is rolled back automatically;
     - on a host with no lab copy the executor refuses to run.

     The audit trail comes back as a hash-chained timeline, which can be
     downloaded and checked with
     `python -m app.audit_timeline verify <file>`.

   A small form evaluates the approved plan under a scope you type. Try `*`,
   `*.internal`, `10.0.0.0/8`, an empty list, or `end of November` as the end
   date: each is refused with a reason code.
6. **What it missed.** At the end, the 19 missed attacks are broken down by
   scenario. 18 never raised a single alert, and one raised alerts that
   stayed below the threshold.

The **Show ground truth** switch marks each incident as attack or benign.
Truth is attached to the snapshot after the pipeline has run; nothing upstream
reads it.

## What is real and what is replayed

| On the page | Where it comes from |
|---|---|
| Counters, chart, incidents, scores, reasons, evidence, missed attacks | `docs/eval/web-demo-synthetic-7d.json`, built by `python -m app.webdemo.snapshot` running the evaluation pipeline on the rebuilt week. It is computed independently of `results-synthetic-7d.json`; tests check that the two agree, and CI rebuilds the file and compares it byte for byte. |
| Claude's verdicts | The recorded calls in `docs/eval/triage-tape-synthetic-7d.jsonl`, replayed. No call is made. |
| Policy decisions, approval, execution, verification, rollback, audit trail | Computed live on each click by the same code as `make safety`, on a temporary copy of `examples/safety-demo/lab/<host>`. Each click starts a fresh chain with a deterministic clock, so the same click gives the same trail. |
| Replay timing | Presentation only. The pipeline is a batch run; an incident is drawn when its last alert arrives. |

The page's own code is plain HTML, CSS and JavaScript in
`backend/app/webdemo/static/`, with no build step and no third-party code. It
computes nothing: it displays the snapshot and the API's answers. Log text is
inserted as text, never as HTML, and the page is served under a strict
Content-Security-Policy.

## Links for a recording

- `/demo?at=end`: start at the end of the week.
- `/demo?at=end#INC-A0004561`: open that incident.
- `/demo?at=end&respond=approve#INC-A0003598`: open that incident and press
  "Approve and run", which shows the rollback.
- `/demo?autoplay=1`: start the replay on load.

The replay lasts about 45 s at 1×, and 2× and 4× are available.
