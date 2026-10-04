# AegisQ load tests (k6)

```bash
make loadtest          # full size (~6 minutes)
make loadtest-smoke    # a few seconds per scenario; what CI runs
SCENARIOS="api approvals" loadtest/run.sh
```

`run.sh` does the following:
1. Seeds a throwaway workspace with a synthetic fleet (2,000 services, a 20,000-entry audit log and 200 pending approvals by default; override with `SERVICES`, `AUDIT` and `APPROVALS`).
2. Starts `aegisq serve` with two approvers' tokens.
3. Runs each scenario with a local `k6` binary, or the `grafana/k6` Docker image when none is installed.
4. Verifies the workspace afterwards.

Summaries are written to `loadtest/out/*-summary.json`.

| Scenario | Script | What it proves |
|---|---|---|
| `api` | `api-read.js` | 50 people with the dashboard open, polling the way the page does (approvals every 3 s, audit + chain check every 5 s, overview every 15 s). Thresholds: < 1% errors, p95 under 300 ms for approvals, 500 ms for audit, 1 s for the chain check and 1.5 s for the overview. |
| `approvals` | `approvals.js` | Two approvers hit **every** pending approval at the same moment. Exactly one decision per approval may win (200) and the other must get 409. After the run, `seed.py verify` checks three things: every approval was decided once, there is exactly one audit entry per decision, and the hash chain is intact. |
| `tls` | `tls-handshake.js` | 200 new TLS connections per second to the post-quantum demo server and to a classical-only one, with no connection reuse, so every request is a full handshake. k6's Go TLS stack offers X25519MLKEM768 first, as browsers do. Needs `make demo-up`; otherwise it is skipped. |
| `auth` | `auth.js` | 20 attackers guessing tokens. No guess is ever accepted, failures are throttled to 429 after 20, throttled replies stay under 100 ms, and `/healthz` keeps answering. |

`run.sh` exits non-zero if any threshold or integrity check fails.

The throttle is per client address, so during the 5-minute window it also blocks legitimate users behind the same address. This is deliberate: letting valid tokens through would tell a blocked attacker which guess was right (200 vs 429).

## Results

The first run of the `api` scenario failed: `/api/approvals` p95 was **25 s**, with 31 requests timing out. Four causes were fixed:

| Problem | Fix |
|---|---|
| Every approvals *read* took the SQLite write lock (`BEGIN IMMEDIATE` plus an expiry `UPDATE`), so readers queued | Reads use a plain read transaction and compute expiry in the query; only writers persist it |
| `/api/audit` parsed the entire log to return the last 60 entries | The log is read backwards in 64 KB chunks, so cost tracks the page size, not the log size |
| `/api/audit/verify` re-hashed the whole chain on every poll | Incremental verification: the verified prefix is re-hashed (cheap) and only new entries are checked in full; any change to an earlier byte triggers a full re-verification |
| `/api/overview` re-parsed the 2,000-service scan on every request | The parsed scan is cached until the file changes, and the overview is memoized per Z value |

See the commit message for the measured numbers before and after.
