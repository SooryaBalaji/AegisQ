# AegisQ: presentation checklist and demo script

There are two ways to run AegisQ. Both give the same results; pick one and rehearse with it.

| | **Native** (pip) | **All-Docker** |
|---|---|---|
| Works on | Windows, macOS, Linux | Windows, macOS, Linux |
| Needs | Python 3.10+, Docker Desktop (for the demo servers only) | Docker Desktop only |
| Run a command | `aegisq scan demo/fleet.yaml` | `aq scan fleet.docker.yaml` (shortcut below) |
| Dashboard | `aegisq serve --inventory demo/fleet.yaml` | already running at http://localhost:8000 |

Commands below are shown for **native**. For all-Docker, replace `aegisq` with `aq` and `demo/fleet.yaml` with `fleet.docker.yaml`. The PowerShell shortcut is:

```powershell
function aq { docker compose -f demo/docker-compose.yml run --rm --no-deps aegisq @args }
```

---

## A. The day before

**1. Latest code.** Run `git checkout main` then `git pull`. On GitHub → Actions, the latest `ci` run on `main` should be green on all jobs (Linux 3.10–3.13, Windows, macOS, quantum, integration).

**2. Install (native only).** In a fresh virtual environment:
- Windows: `py -m venv .venv` then `.venv\Scripts\activate`
- macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`

Then run `pip install -e ".[dev,agent,quantum]"` and `aegisq doctor`.

**3. Demo servers.**
- **Native:** start only the 7 servers, because the native dashboard uses port 8000:

  ```
  docker compose -f demo/docker-compose.yml up -d --build app-modern app-legacy app-tls12 app-ready app-plain ssh-pq ssh-legacy
  ```
- **All-Docker:** `docker compose -f demo/docker-compose.yml up -d --build` starts the servers and the dashboard.

`docker ps` should list `aegisq-app-modern`, `-app-legacy`, `-app-tls12`, `-app-ready`, `-app-plain`, `-ssh-pq` and `-ssh-legacy`.

**4. Full test suite. Everything must pass.**

| Check | Native | All-Docker |
|---|---|---|
| Unit tests | `pytest` | `docker compose -f demo/docker-compose.yml --profile test run --rm --no-deps tests -q` |
| Against the real servers | `pytest -m integration` | same as above plus `-m integration` |
| Lint and types (optional) | `ruff check src tests` and `python -m mypy` | (CI runs these) |

**5. A full dry run** of section B below, end to end, then reset (step 9).

**6. Results that take time or internet: produce them now and show the saved ones on stage.**
- **IBM hardware:** set `QISKIT_IBM_TOKEN`, then run `aegisq entropy run --source ibm`. Write down the **IBM job ID**. Queue time varies.
- **Real-world gap:** `aegisq realworld --download` takes a few minutes and needs normal internet; venue Wi-Fi may block it. Sanity check first: put `cloudflare.com` in a file `h.txt` and run `aegisq scan h.txt`; it must say `PQ READY`.
- **Benchmark:**
  - Native: `aegisq benchmark https://localhost:8446/ -n 1000 --method native`.
  - All-Docker: `aq benchmark https://app-ready/ -n 1000 --method curl` (full handshakes with curl on OpenSSL 3.5).
- **Shor:** `aegisq shor` on the simulator. Optionally run `aegisq shor --backend ibm` to show a noisy hardware result.

All of these are saved in the workspace and appear on the dashboard automatically.

**7. AI planner (optional): Claude or Gemma 4.**
- **Claude:** set `ANTHROPIC_API_KEY`, then rehearse once with `--planner claude`.
- **Gemma 4:** set `GEMINI_API_KEY`, then rehearse once with `--planner local`. On the free tier a full run takes about 10 minutes because of Google's rate limit, so for a live demo run it with `--service app-modern` (about 3 minutes) or show a run you recorded earlier.
- **Setting the key:** PowerShell `$env:GEMINI_API_KEY="..."`, macOS/Linux `export GEMINI_API_KEY=...`. For all-Docker, put it in `demo/.env` and re-run `up -d`.
- **Fallback:** `--planner rules` gives identical outcomes with no network.

**8. Dashboard login.** Set your own token before starting the dashboard:
- **Native:** `AEGISQ_API_TOKENS=you:<16+ chars>` in the environment.
- **All-Docker:** the same line in `demo/.env`.

Open the dashboard in the browser you'll present from and sign in once. The browser remembers the token for that tab.

**9. Reset the fleet** to its starting state, keeping the saved entropy/benchmark/real-world results:

```
python demo/setup.py --configs-only
docker compose -f demo/docker-compose.yml restart app-modern app-legacy app-tls12 app-ready app-plain
```
In all-Docker mode, run the first line as `docker compose -f demo/docker-compose.yml run --rm --no-deps --entrypoint /opt/aegisq/bin/python aegisq /demo/setup.py --configs-only`.

Then confirm with `aegisq scan demo/fleet.yaml`. The expected starting point is **2 PQ ready, 3 classical, 1 TLS 1.2, 1 plaintext**.

---

## B. On the day: 3-minute demo

Open three things before you start:
- the dashboard (signed in);
- terminal 1 for commands;
- terminal 2 with `aegisq serve --inventory demo/fleet.yaml` running (native only).

| Time | What you do | What the audience sees |
|---|---|---|
| **0:00–0:30 Problem** | Talk over the headline and the real-world gap card. | Recorded traffic can be decrypted later. Big sites migrated, the long tail did not; show the measured gap from the Tranco scan. |
| **0:30–1:00 Scan** | `aegisq scan demo/fleet.yaml`, then `aegisq cbom --out cbom.json`, then refresh the dashboard. | Real ML-KEM handshakes; a valid CycloneDX 1.6 CBOM; the risk ranking. **Move the Z slider**: services drop in and out of risk, and app-plain stays critical at every Z. |
| **1:00–2:00 Fix** | `aegisq migrate demo/fleet.yaml --planner rules` (or `claude` / `local`). Approve on the dashboard as each diff appears. | **app-modern:** patch passes `nginx -t`, reloads, verified PQ. **app-legacy (OpenSSL 3.0):** test fails → config restored automatically → agent names OpenSSL 3.0 as the root cause. |
| **2:00–2:30 Quantum** | Scroll to Quantum entropy. | IBM job ID, measured readout bias, min-entropy bound, Toeplitz output at ε = 2^-64, the "what is and isn't guaranteed" table. One line on Shor (N = 15, period 4, factors 3 × 5, honestly a toy) and the resource-estimate table beside the slider. |
| **2:30–3:00 Close** | Handshake cost card; click **Get the report**; `aegisq audit verify`. | +2.3 KB per handshake and measured latency; the migration report; "audit log intact". Pitch: *AegisQ finds the servers that are still classical, proves which ones matter most, and fixes them safely with a human in the loop.* |

## C. If something goes wrong

| Problem | Fix |
|---|---|
| Dashboard says "Invalid token" | Use the token you set, or the one printed by `aegisq serve`. In all-Docker mode the default is `aegisq-demo-token-change-me`. |
| A server shows UNREACHABLE | `docker ps`; start the stopped one with `docker compose -f demo/docker-compose.yml up -d`. |
| app-modern already PQ READY before the demo | You didn't reset: run step A9. |
| Claude or Gemma planner errors / no network | Re-run with `--planner rules`: same tools, same guardrails, same outcomes. |
| Gemma run is slow ("rate limited, retrying") | Normal on the Gemini free tier; AegisQ waits it out. Limit the run with `--service app-modern`. |
| IBM or Tranco unavailable at the venue | Show the saved results from step A6; the dashboard reads them from the workspace. |
| Port 8000 in use | `aegisq serve --port 8001 ...` |

## D. Likely questions

| Question | Short answer |
|---|---|
| Why fix key exchange before certificates? | Recorded key exchanges can be broken later; signatures only need to hold at handshake time. |
| Why hybrid instead of pure ML-KEM? | Secure if either algorithm holds, so a future ML-KEM flaw doesn't break it. |
| Does it need Claude? | No. `--planner local` runs Gemma 4 (or any model behind an OpenAI-compatible API, including one on your own laptop), and `--planner rules` needs no AI at all. The guardrails are the same for all three. |
| What stops the AI from breaking a server? | Code, not the prompt: only two nginx directives can change, values are allowlisted, every change needs a named human's approval bound to that exact diff, `nginx -t` runs before reload, and failures roll back automatically. The audit log is hash-chained. |
| Is the quantum randomness overkill? | We measured the hardware's bias, bounded its min-entropy, and extracted with a Toeplitz hash at ε = 2^-64. IBM sees the raw bits, so we mix with local randomness and the key is never weaker than normal. |
| Where does Z come from? | Nobody knows, so it's a slider. The ranking shows which services stay at risk across assumptions. |
| Does it scale? | Load-tested with k6: 50 dashboard viewers at p95 ≤ 29 ms, a concurrent-approval race with exactly-once decisions, 200 TLS handshakes/s with no failures. |
| Does it run everywhere? | CI runs the suite on Linux (Python 3.10–3.13), Windows and macOS, and the integration tests against real OpenSSL 3.0/3.5 and OpenSSH 10 servers. |
