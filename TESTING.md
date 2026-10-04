# Testing AegisQ

This guide covers every part of AegisQ, with the command to run and what you should see. The expected outputs are from real runs against the demo fleet.

## Docker only (Windows, or no Python setup)

AegisQ uses Linux-only system calls (file locking), so on **Windows** run it in Docker rather than from PyCharm or `pip`. You need only Docker Desktop. Run these from the repo root in PowerShell, cmd or a terminal:

```bash
docker compose -f demo/docker-compose.yml up -d --build
```
This one command:
1. builds the images (the first build takes a few minutes);
2. generates the demo nginx configs and certificates;
3. starts the 7 demo servers and the dashboard on http://localhost:8000.

Sign in with the token `aegisq-demo-token-change-me`. To use your own token, put `AEGISQ_API_TOKENS=you:<at least 16 characters>` in a file called `demo/.env` before `up`.

Run any `aegisq` command through Docker. This shorthand is used below; it's PowerShell syntax, so use the full command in other shells:
```powershell
function aq { docker compose -f demo/docker-compose.yml run --rm --no-deps aegisq @args }
```

| Step | Command | Expect |
|---|---|---|
| Scan | `aq scan fleet.docker.yaml` | 2 PQ ready, 3 classical, 1 TLS1.2, 1 plaintext |
| CBOM | `aq cbom --out /var/lib/aegisq/workspace/cbom.json` | "30 cryptographic assets (valid CycloneDX 1.6)" |
| Risk | `aq risk --sweep 0,10,20` | ssh-legacy and app-modern critical |
| Agent | `aq migrate fleet.docker.yaml --planner rules`, then approve each change at http://localhost:8000 | app-modern and app-tls12 fixed; app-legacy fails, is restored, and is diagnosed as OpenSSL 3.0 |
| Approve from a 2nd terminal instead | `aq approvals list --status pending`, then `aq approve <ID> --by alice` | "approved by alice" |
| Audit and report | `aq audit verify` then `aq report` | "audit log intact" |
| Quantum | `aq entropy run --source simulated` then `aq shor` | h ≈ 0.92; period r = 4, factors 3 × 5 |
| Unit tests | `docker compose -f demo/docker-compose.yml --profile test run --rm --no-deps tests -q` | 207 passed |
| Integration tests | add `-m integration` to the line above | 2 passed |

Use `fleet.docker.yaml`, not `fleet.yaml`, inside Docker: it addresses the demo servers by container name.

Where things live:
- **Results:** scans, the audit log and reports are in the Docker volume `aegisq-demo_aegisq-data`, shared by the dashboard and every `aq` command.
- **Configs the agent patches:** `demo/fleet/` on your disk.

To reset or remove the demo:
```bash
docker compose -f demo/docker-compose.yml down -v     # stop and wipe the workspace
```
Then delete `demo/fleet/` and run `up` again for pristine configs.

For the Claude planner, the Gemma 4 planner or IBM hardware, put `ANTHROPIC_API_KEY=...`, `GEMINI_API_KEY=...` or `QISKIT_IBM_TOKEN=...` in `demo/.env`.

The AegisQ container mounts the Docker socket so the agent can run `nginx -t` and reload inside the demo containers. That gives it control of Docker on your machine, so keep this setup to the demo.

---

## 0. Setup (once, Linux/macOS without Docker for AegisQ)

You need:
- Python 3.10+ and git.
- Docker with Compose v2 (Docker Desktop on Mac/Windows; on Windows run everything inside WSL2).
- `make` (optional). Every `make` target below also has the plain command.

```bash
git clone https://github.com/SooryaBalaji/QShield && cd QShield
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,agent,quantum]"
aegisq doctor
```
`doctor` lists what is available. `ok` means ready; `--` means optional and not set up yet (for example no Anthropic key).

Start the demo fleet:

```bash
python3 demo/setup.py
docker compose -f demo/docker-compose.yml up -d --build
docker ps --format '{{.Names}}'
```
You should see seven containers: `aegisq-app-modern`, `-app-legacy`, `-app-tls12`, `-app-ready`, `-app-plain`, `-ssh-pq` and `-ssh-legacy`.

Use a scratch workspace so test runs don't mix with real data:

```bash
export AEGISQ_HOME=/tmp/aegisq-test
```

---

## 1. Automated tests

| What | Command | Expect |
|---|---|---|
| Unit tests (fake servers, no Docker) | `pytest` | ~210 passed in about 30 s |
| Quantum tests (Qiskit simulator) | included in `pytest` when Qiskit is installed | they skip automatically without it |
| Integration tests (real containers) | `pytest -m integration` | `2 passed` (real scan + full migration with the planned failure) |
| Lint and types | `ruff check src tests && python -m mypy` | `All checks passed!` / `Success: no issues found` |
| Coverage | `pytest --cov` | about 83% |

## 2. Scanner

```bash
aegisq scan demo/fleet.yaml
```
Expected:

| Service | Status | Detail |
|---|---|---|
| app-modern, app-legacy | `CLASSICAL` | TLSv1.3 x25519 |
| app-tls12 | `TLS1.2 ONLY` | |
| app-ready | `PQ READY` | X25519MLKEM768 |
| app-plain | `PLAINTEXT` | |
| ssh-pq | `PQ READY` | mlkem768x25519-sha256 |
| ssh-legacy | `CLASSICAL` | curve25519-sha256 |

Other things to try:
- **Raw JSON:** `aegisq scan demo/fleet.yaml --json | head -50` shows probe details: group, cipher, key-share sizes (1216 / 1120 bytes), certificate.
- **CI gate:** `aegisq scan demo/fleet.yaml --fail-on classical; echo $?` prints `2`, because some services are not PQ ready.
- **Plain host list:** put `127.0.0.1:8446` and `127.0.0.1:2222 ssh` in `hosts.txt` and run `aegisq scan hosts.txt`.
- **Bad input is refused:** a host of `-oProxyCommand=x` in an inventory gives a clean error, and nothing runs.

**Cross-check with the stock `openssl` 3.5 and `ssh` 10 tools** (inside the AegisQ image; Linux, because it needs `--network host`):

```bash
docker build -t aegisq .
docker run --rm --network host -v "$PWD/demo:/demo:ro" aegisq \
  scan /demo/fleet.yaml --tls-backend openssl --ssh-backend openssh --cross-check
```
Expect the same statuses as above and **no** "backends disagree" messages.

## 3. CBOM

```bash
aegisq cbom --out cbom.json        # "30 cryptographic assets (valid CycloneDX 1.6)"
aegisq cbom-validate cbom.json     # "is valid CycloneDX 1.6"
```

Look inside the file:
- `kex-app-ready` is `X25519MLKEM768` with `nistQuantumSecurityLevel: 3`.
- `kex-app-modern` is `X25519` with level `0`.
- Each entry has an `aegisq:host` property.

To see validation fail, change `"specVersion"` in `cbom.json` to `"9.9"`. `aegisq cbom-validate cbom.json` then exits `2`.

## 4. Risk scoring

```bash
aegisq risk --sweep 0,5,10,15,20,25
```

At Z = 10, expect:
- ssh-legacy and app-modern `critical` (health data, X = 25).
- app-plain `critical` at every Z, because plaintext is readable today.
- app-tls12 `high`.
- app-ready and ssh-pq `none`.

The sweep table shows who stays at risk across different Z assumptions. Try `--z 30` and watch app-modern stay at risk.

## 5. Migration agent (the core demo)

Two terminals, same `AEGISQ_HOME`.

**Terminal 1: the dashboard**
```bash
aegisq serve --inventory demo/fleet.yaml
```
Copy the printed token, open http://127.0.0.1:8000 and sign in.

**Terminal 2: the agent**
```bash
aegisq migrate demo/fleet.yaml --planner rules
```

Approve each change on the dashboard's Approvals panel as it appears.

Expected outcome:

| Service | Outcome |
|---|---|
| app-modern | **fixed**: patched to `X25519MLKEM768:X25519:prime256v1`, `nginx -t` ok, reloaded, verified |
| app-tls12 | **fixed**: TLS 1.3 enabled plus the hybrid group |
| app-legacy | **failed**: `nginx -t` rejects the group, the old config is restored automatically, and the agent says *"nginx is linked against OpenSSL 3.0.x, which has no ML-KEM"* with an upgrade recommendation |
| app-plain, ssh-legacy | **skipped**, with advice (needs TLS / sshd_config change) |

Afterwards, check the results:
```bash
aegisq scan demo/fleet.yaml                 # app-modern and app-tls12 now PQ READY; app-legacy still CLASSICAL and serving
grep ssl_ecdh_curve demo/fleet/*/conf.d/site.conf
git --git-dir "$AEGISQ_HOME/patches/repo.git" branch     # one branch per proposal
```

Variations:
- **Reject a change** on the dashboard. The outcome becomes `rejected`, and the config file is unchanged.
- **Approve from the CLI instead:** run `aegisq approvals list --status pending`, then `aegisq approve <ID> --by alice`.
- **Approve in the terminal:** `aegisq migrate demo/fleet.yaml --approve-in terminal` shows each diff and asks y/N.
- **Agent names are refused as approvers:** `aegisq approve <ID> --by agent` fails.
- **Claude as the planner:**

  ```bash
  export ANTHROPIC_API_KEY=...
  aegisq migrate demo/fleet.yaml --planner claude
  ```
  Same outcomes, plus Claude's written summary at the end.
- **Gemma 4 as the planner** (Gemini API):

  ```bash
  export GEMINI_API_KEY=...            # PowerShell: $env:GEMINI_API_KEY="..."
  aegisq migrate demo/fleet.yaml --planner local
  ```
  The first line printed is `planner: local (gemma-4-31b-it @ generativelanguage.googleapis.com)`. Expect "rate limited, retrying" warnings on the free tier; the run carries on.
- **A model on your own machine** (Ollama shown; LM Studio, llama.cpp and vLLM work the same way):

  ```bash
  ollama pull <model>                  # any model with tool calling
  export AEGISQ_LLM_BASE_URL=http://127.0.0.1:11434/v1
  export AEGISQ_LLM_MODEL=<model>
  aegisq migrate demo/fleet.yaml --planner local
  ```

Reset before re-running:
```bash
make demo-reset
rm -rf "$AEGISQ_HOME"
```
Without make, `demo-reset` is:
```bash
python3 demo/setup.py --configs-only
for c in modern legacy tls12 ready plain; do docker exec aegisq-app-$c nginx -s reload; done
```

## 6. Dashboard

With `aegisq serve` running:
- **Login:** the signed-out screen shows only the wordmark and the sign-in form. A wrong token gets "Invalid token"; the right one shows the dashboard.
- **Headline:** reads "N% of your fleet is quantum-safe." with the at-risk count under it, both from the latest scan. The tiles beside it match `aegisq scan`'s summary.
- **Nav links** (Risk ranking, Approvals, Quantum entropy, Audit log) jump to their sections; **Get the report** downloads the HTML report.
- **Z slider:** moving it re-ranks services live, and the "already at risk" tile changes.
- **Rows:** click a row to expand its findings.
- **Rescan fleet:** runs a new scan (requires `--inventory`).
- **Download CBOM** and **Report:** both download files.
- **Audit badge** (top right): "audit intact · N".
- **Narrow screen:** shrink the browser to phone width; there should be no sideways scrolling.

API checks with curl:
```bash
TOKEN=...      # the token printed by serve
curl -s localhost:8000/api/overview -H "Authorization: Bearer $TOKEN" | head -c 300
curl -s -o /dev/null -w "%{http_code}\n" localhost:8000/api/overview   # 401 without a token
```

## 7. Report and audit log

```bash
aegisq report                 # writes $AEGISQ_HOME/reports/migration-report.{md,html}
aegisq audit verify           # "audit log intact: N entries"
aegisq audit tail -n 20
```

**Tamper test:** edit any line in `$AEGISQ_HOME/audit.jsonl` (change a status, for example). `aegisq audit verify` then reports the altered entry and exits `2`, and the dashboard badge turns red. To make the chain an HMAC chain, set `AEGISQ_AUDIT_KEY` before writing.

## 8. Quantum entropy module

| What | Command | Expect |
|---|---|---|
| Simulated, fast (default) | `aegisq entropy run --source simulated` | ~5 s. Prints `SIMULATED RUN` warning, h ≈ 0.92, ~910,000 extracted bits at ε = 2^-64, monobit/runs pass for both extracted bits and `os.urandom` |
| Simulated, full device noise | `aegisq entropy run --source simulated --noise full` | ~45 s, h ≈ 0.93 |
| Real IBM hardware | `QISKIT_IBM_TOKEN=... aegisq entropy run --source ibm` | prints the **IBM job ID**; time depends on IBM's queue. No `SIMULATED` warning |
| Re-analyse a saved run and write a key | `aegisq entropy analyze --key-out key.bin` | key file created with mode 0600; only its fingerprint is printed |
| Shor demo | `aegisq shor` | `period r = 4; factors of 15: [3, 5]` plus the "toy" disclaimer |
| Shor on hardware | `aegisq shor --backend ibm` | the noisy hardware result, shown as measured |

The dashboard's Quantum entropy section shows the charts, the heatmap and the guarantees table for the latest run.

With the quantum Docker image (Qiskit preinstalled):
```bash
make image-quantum      # or: docker build --build-arg EXTRAS=agent,quantum -t aegisq:quantum .
docker run --rm aegisq:quantum entropy run --source simulated      # ~7 s including container start
docker run --rm aegisq:quantum shor
docker run --rm -e QISKIT_IBM_TOKEN aegisq:quantum entropy run --source ibm
```
To keep results from a container run, add a workspace volume, e.g. `-v "$PWD/.aegisq:/var/lib/aegisq/workspace"`.

## 9. Handshake benchmark

```bash
aegisq benchmark https://localhost:8446/ -n 300 --method native
```
Expect X25519MLKEM768 and x25519 rows with p50/p99, and key shares of client 1216 vs 32 bytes and server 1120 vs 32 bytes (+2272 bytes per handshake).

Against `https://localhost:8443/` before migration, the PQ row says *"every handshake failed: the server does not accept X25519MLKEM768"*, which is correct for a classical server.

For full handshakes with curl, which needs curl built with OpenSSL 3.5:
```bash
docker run --rm --network host aegisq benchmark https://localhost:8446/ -n 300 --method curl
```

## 10. Real-world adoption gap (Tranco)

```bash
aegisq realworld --download        # top 500 vs random 500 from ranks 100k-1M; a few minutes
```
This needs normal internet access. A corporate proxy that intercepts TLS makes every site look like the proxy. Sanity check first: `echo cloudflare.com > h.txt && aegisq scan h.txt` should say `PQ READY`.

## 11. Load tests (k6)

```bash
make loadtest-smoke      # seconds per scenario
make loadtest            # ~6 minutes, full size
```
Expect each scenario to report `thresholds passed`. The workspace check should print `OK: every approval decided exactly once; audit chain intact`. The TLS scenario needs the demo fleet running. Details are in [loadtest/README.md](loadtest/README.md).

## 12. Cleanup

```bash
docker compose -f demo/docker-compose.yml down
rm -rf "$AEGISQ_HOME"
```

## What can't be tested offline

- **Claude and Gemma planners:** need `ANTHROPIC_API_KEY` or `GEMINI_API_KEY`. The offline tests use scripted fake models that try to bypass the guardrails, plus a local HTTP server for the Gemma client's retries.
- **IBM hardware:** needs `QISKIT_IBM_TOKEN`. Offline, use `--source simulated`.
- **Real-world scan:** needs internet without TLS interception.
