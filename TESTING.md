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

Sign in as `admin` with the password `aegisq-demo-change-me`. To choose your own, put `AEGISQ_ADMIN_USER=you` and `AEGISQ_ADMIN_PASSWORD=<at least 12 characters>` in a file called `demo/.env` before the first `up`.

Run any `aegisq` command through Docker. This shorthand is used below; it's PowerShell syntax, so use the full command in other shells:
```powershell
function aq { docker compose -f demo/docker-compose.yml run --rm --no-deps aegisq @args }
```

| Step | Command | Expect |
|---|---|---|
| Scan | `aq scan fleet.docker.yaml` | 2 PQ ready, 3 classical, 1 TLS1.2, 1 plaintext |
| CBOM | `aq cbom --out /var/lib/aegisq/workspace/cbom.json` | "30 cryptographic assets (valid CycloneDX 1.6)" |
| Risk | `aq risk --sweep 0,10,20` | ssh-legacy and app-modern critical |
| Agent | `aq migrate fleet.docker.yaml --planner rules`, then approve each change at http://localhost:8000 | app-modern, app-tls12 and ssh-legacy fixed; app-legacy fails, is restored, and is diagnosed as OpenSSL 3.0 |
| Approve from a 2nd terminal instead | `aq approvals list --status pending`, then `aq approve <ID> --by alice` | "approved by alice" |
| Audit and report | `aq audit verify` then `aq report` | "audit log intact" |
| Unit tests | `docker compose -f demo/docker-compose.yml --profile test run --rm --no-deps tests -q` | about 220 passed |
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

For the Gemma 4 planner on Google's Gemini API, put `GEMINI_API_KEY=...` in `demo/.env`. For Gemma 4 on your own computer, install Ollama, run `ollama pull gemma4:e4b`, and set `AEGISQ_LLM_BASE_URL=http://host.docker.internal:11434/v1` there instead.

The AegisQ container mounts the Docker socket so the agent can run `nginx -t` / `sshd -t` and reload inside the demo containers. That gives it control of Docker on your machine, so keep this setup to the demo.

---

## 0. Setup (once, Linux/macOS without Docker for AegisQ)

You need:
- Python 3.10+ and git.
- Docker with Compose v2 (Docker Desktop on Mac/Windows; on Windows run everything inside WSL2).
- `make` (optional). Every `make` target below also has the plain command.

```bash
git clone https://github.com/SooryaBalaji/QShield && cd QShield
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
aegisq doctor
```
`doctor` lists what is available. `ok` means ready; `--` means optional and not set up yet (for example no Gemini key).

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
| Unit tests (fake servers, no Docker) | `pytest` | about 220 passed in about 30 s |
| Real OpenSSH migration | included in `pytest` when `sshd` is installed (`apt install openssh-server`) | a real sshd is scanned, migrated, verified and rolled back; skipped without it |
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
Open http://127.0.0.1:8000 on the same computer and create the first admin when asked (or run `aegisq users add alice --role admin` first). With separation of duties on, also add an approver (`aegisq users add priya --role approver`) and approve as them, or set `agent.separation_of_duties: false` for a one-person test.

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
| ssh-legacy | **fixed**: `KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256` (the weak SHA-1 method is dropped), `sshd -t` ok, reloaded, verified with a fresh connection |
| app-plain | **skipped**, with advice (needs TLS first) |

Afterwards, check the results:
```bash
aegisq scan demo/fleet.yaml                 # app-modern, app-tls12 and ssh-legacy now PQ READY; app-legacy still CLASSICAL and serving
grep ssl_ecdh_curve demo/fleet/*/conf.d/site.conf
grep KexAlgorithms demo/fleet/ssh-legacy/sshd/sshd_config
git --git-dir "$AEGISQ_HOME/patches/repo.git" branch     # one branch per proposal
```

Variations:
- **Reject a change** on the dashboard. The outcome becomes `rejected`, and the config file is unchanged.
- **Approve from the CLI instead:** run `aegisq approvals list --status pending`, then `aegisq approve <ID> --by alice`.
- **Approve in the terminal:** `aegisq migrate demo/fleet.yaml --approve-in terminal` shows each diff and asks y/N.
- **Agent names are refused as approvers:** `aegisq approve <ID> --by agent` fails.
- **Gemma 4 as the planner, on Google's Gemini API:**

  ```bash
  export GEMINI_API_KEY=...            # PowerShell: $env:GEMINI_API_KEY="..."
  aegisq migrate demo/fleet.yaml --planner gemma
  ```
  The first line printed is `planner: gemma (gemma-4-31b-it @ generativelanguage.googleapis.com (native API))`. Expect "rate limited, retrying" warnings on the free tier; the run carries on, with Gemma's written summary at the end.
- **Gemma 4 on your own computer** (no key):

  ```bash
  ollama pull gemma4:e4b
  aegisq doctor                        # "Gemma 4 planner: gemma4:e4b on this machine (Ollama)"
  aegisq migrate demo/fleet.yaml --planner gemma
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
docker kill --signal=HUP aegisq-ssh-legacy
```

### Gemma 4: live check, red team, claim check, owner brief

```bash
aegisq gemma-check --api both        # pass/fail for a tool call, an image and a claim extraction, per API
aegisq redteam                       # scripted hostile model; must print four "pass" lines
aegisq redteam --planner gemma       # the same sandbox, driven by Gemma 4
aegisq claims check --image docs/demo/console-claim.png --yes   # demo fleet running
aegisq brief app-legacy              # after a scan; --template works without a model
```

Expected for the claim check: `127.0.0.1:8443` CONTRADICTED (the screenshot says enabled, the server is classical), `127.0.0.1:8445` and `127.0.0.1:8446` CONFIRMED. The brief lists its facts, keeps only sentences whose versions, numbers and names appear in the facts they cite, and lists anything it removed. `redteam` needs no key, network or Docker: it runs in a temporary folder.

## 6. Dashboard

With `aegisq serve` running:
- **Sign in:** a wrong password says "Wrong user name or password"; the right one opens Overview. After 20 wrong tries the form says to wait.
- **Overview:** the fleet map has one square per server, coloured by status, with counts beside it that match `aegisq scan`'s summary. Clicking a count filters the table; clicking a server opens its details (certificate, TLS versions, the risk sum, what to do).
- **Quantum computer slider:** moving it changes *Needs attention* and the risk column live.
- **Run:** pick *Inventory* and *Scan and fix*, start, and watch the four steps. A change you started shows "someone else must approve it"; approve it as another user on **Approvals**. The finished table shows each server before and after.
- **Rescan**, **Download report** and **Download CBOM** on Overview.
- **Audit log:** the chain check at the top says "intact"; events read as sentences, and clicking one shows its data.
- **Settings → Appearance:** Light, Dark and Match my system change the whole app and are remembered in this browser.
- **Narrow screen:** shrink the browser to phone width; the menu moves behind a **Menu** button and nothing scrolls sideways.

API checks with curl:
```bash
curl -s -c jar -H "X-AegisQ: 1" -H "Content-Type: application/json" \
  -d '{"name":"alice","password":"<password>"}' localhost:8000/api/login
curl -s -b jar localhost:8000/api/overview | head -c 300
curl -s -o /dev/null -w "%{http_code}\n" localhost:8000/api/overview   # 401 when not signed in
curl -s -b jar -o /dev/null -w "%{http_code}\n" -X POST localhost:8000/api/logout   # 403 without X-AegisQ
```

## 7. Report and audit log

```bash
aegisq report                 # writes $AEGISQ_HOME/reports/migration-report.{md,html}
aegisq audit verify           # "audit log intact: N entries"
aegisq audit tail -n 20
```

**Tamper test:** edit any line in `$AEGISQ_HOME/audit.jsonl` (change a status, for example). `aegisq audit verify` then reports the altered entry and exits `2`, and the dashboard badge turns red. To make the chain an HMAC chain, set `AEGISQ_AUDIT_KEY` before writing.

## 8. Teams, schedules and alerts

| What | How | Expect |
|---|---|---|
| Create users | `aegisq users add priya --role approver` and `aegisq users add vic --role viewer` (or **Settings → Users → Add user**) | each asks for a password; they can sign in at once |
| Roles | sign in as `vic` | Rescan, Start and Approve are disabled; Settings shows only Appearance and Your account |
| Separation of duties | as an admin or operator, start **Run → Scan and fix**; then sign in as `priya` in a private window and open **Approvals** | the starter sees "someone else must approve it" with Approve disabled; `priya` approves and the run continues |
| Passwords | as `priya`, change your password in **Settings → Your account**; as an admin, **Set password** for `vic` | `vic`'s open session is signed out at once |
| Last admin | try to remove or demote the only admin | refused: "at least one admin must remain" |
| Webhook | **Settings → Alerts**, add a Slack/Teams webhook (or `https://webhook.site` for a throwaway URL), then **Send a test alert** | the message arrives; "delivered: HTTP 200" |
| Approval alert | start a fix run with the webhook set | "a change to … is waiting for approval" within about 15 seconds |
| Schedule | **Settings → Scheduled scans → Every hour** | a "Scheduled scan" job appears in the audit log when it runs |

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

## 10. Load tests (k6)

```bash
make loadtest-smoke      # seconds per scenario
make loadtest            # ~6 minutes, full size
```
Expect each scenario to report `thresholds passed`. The workspace check should print `OK: every approval decided exactly once; audit chain intact`. The TLS scenario needs the demo fleet running. Details are in [loadtest/README.md](loadtest/README.md).

## 11. Other servers

The unit tests cover every server's patching, guardrails and STARTTLS with fakes (`pytest tests/test_servers.py`). To repeat the real-server run on an Ubuntu 24.04 machine or VM you can throw away (it changes `/etc/postfix`):

```bash
sudo apt-get install -y apache2 haproxy postfix dovecot-imapd dovecot-pop3d
# OpenSSL 3.5 next to the system's 3.0 (same ABI, so the distro servers can load it)
git clone --depth 1 --branch openssl-3.5.4 https://github.com/openssl/openssl.git && cd openssl
./Configure --prefix=/opt/ossl --libdir=lib shared no-tests && make -j4 && sudo make install_sw
```

1. Start one instance of each server with an explicit classical list (for example `SSLOpenSSLConfCmd Groups X25519:prime256v1`, `ssl-default-bind-curves X25519:P-256`, `curves x25519 secp256r1`, `ssl_curve_list = X25519:prime256v1`), some with `LD_LIBRARY_PATH=/opt/ossl/lib` and some without. Postfix and Dovecot clear their environment, so also add `LD_LIBRARY_PATH=/opt/ossl/lib` to `import_environment` in their configs.
2. List them in an inventory with `managed:` blocks. Give the OpenSSL 3.5 instances `tls_library: /opt/ossl/lib/libssl.so.3` and test/reload commands that set the same `LD_LIBRARY_PATH` (for example `[env, LD_LIBRARY_PATH=/opt/ossl/lib, apache2, -k, graceful, -f, FILE]`). Mail services need `starttls:`.
3. `aegisq scan fleet.yaml`, then `aegisq migrate fleet.yaml --planner rules` and approve each change as a second user.

Expected:

| Server | Outcome |
|---|---|
| Apache, HAProxy, Caddy 2.10, Dovecot on OpenSSL 3.5 | fixed; a rescan shows `PQ READY` |
| Postfix 3.10+ on OpenSSL 3.5 | fixed, verified over STARTTLS |
| Apache on OpenSSL 3.0 | failed before any change: "OpenSSL 3.0.13 ... rejects X25519MLKEM768"; no approval requested |
| HAProxy on OpenSSL 3.0 | `haproxy -c` fails, the old config is restored, diagnosis names OpenSSL 3.0.13 |
| Postfix 3.8 | failed before any change: needs Postfix 3.10 |

Every server keeps answering throughout (`curl -k https://127.0.0.1:PORT/`).

## 12. Cleanup

```bash
docker compose -f demo/docker-compose.yml down
rm -rf "$AEGISQ_HOME"
```

## What can't be tested offline

- **Gemma 4 itself:** needs `GEMINI_API_KEY` or Gemma 4 in Ollama. The offline tests use scripted fake models (including one that obeys a prompt injection) and local HTTP servers that speak both the OpenAI-compatible and the native Gemini API formats. Run `aegisq gemma-check --api both` to test the real model.
- **Scanning public sites:** needs internet without TLS interception.
