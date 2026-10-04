# AegisQ security model

AegisQ can change production server configuration, so its own safety properties are explicit, enforced in code, and tested.

## What the migration agent can and cannot do

- **Scope.** The agent can only touch services that have a `managed` block in the inventory, which is written by an operator. It receives service names, never file paths or commands. Commands are argv lists from the inventory and are never passed through a shell.
- **Content.** A patch may only add, remove or change `ssl_ecdh_curve` and `ssl_protocols` lines. Each changed line must be exactly one directive whose value contains none of `; { } ' " \ $ #`. Values come from an allowlist:
  - A post-quantum hybrid group must come first.
  - A classical fallback is required by default.
  - TLS 1.3 is required, and SSLv3/TLS 1.0/1.1 are refused.

  The diff is parsed strictly (exact context, checked hunk counts, one file), applied without fuzz, and the result is re-diffed independently. A mutation fuzzer in the test suite checks that no accepted patch changes any other line.
- **Approval.** Applying requires an approval that is:
  - decided by a named human (reserved names such as `agent` or `claude` are refused);
  - approved, unexpired and unused (single use);
  - bound to the SHA-256 of the exact diff.

  The agent has no tool that can approve anything.
- **Change safety.**
  - Applying is refused if the live file changed since the proposal.
  - The previous config is backed up first, the write is atomic, and `nginx -t` runs before any reload.
  - On a test or reload failure the old config is restored automatically.
  - A per-service lock prevents concurrent changes.
  - Only one change may be unverified at a time, and anything still unverified when the agent stops is rolled back.
- **The model.** Claude (`--planner claude`) or an open model such as Gemma 4 (`--planner local`) chooses which tool to call next. Both go through the same dispatcher and the same tools. Tool inputs are schema-validated, unknown tools and fields are rejected, and every call and result is written to the audit log. A refusal, turn limit or endpoint failure stops the run, and the safety-net rollback still happens.
- **What the model provider sees.** The tool results, which include the managed nginx configs and the scan results, are sent to whichever endpoint you choose: Anthropic, Google (Gemini API) or a model server you run yourself. For configs that must not leave the network, use a local model server (`AEGISQ_LLM_BASE_URL`) or `--planner rules`. API keys come only from the environment, are never logged, are sent only to the endpoint they belong to (a Gemini key is not sent to a custom `AEGISQ_LLM_BASE_URL`), and are never sent over plain HTTP except to localhost.

## Audit log

The audit log is an append-only JSON Lines file. Each entry contains the hash of the previous one, and entries are written under an exclusive lock, so concurrent CLI, dashboard and agent processes share one chain. Set `AEGISQ_AUDIT_KEY` to make the chain an HMAC chain, so an attacker who can edit the file cannot recompute it. `aegisq audit verify` exits with code 2 on any tampering. Keys named like secrets (`api_key`, `token`, `password`, ...) are redacted before writing.

## Dashboard and API

- Bearer-token authentication on every `/api` route, with constant-time comparison.
- Failed attempts are throttled per client.
- Approver identity comes from the token, never from the request body.
- Strict Content-Security-Policy (`script-src 'self'`, `frame-ancestors 'none'`), `nosniff`, no third-party code, and all server data rendered with `textContent`.
- The server binds to `127.0.0.1` by default. Put it behind TLS (a reverse proxy) before exposing it.

## Scanning

- Hosts are validated before use: no option-like or metacharacter-bearing names reach `openssl` or `ssh`.
- Scope allow/deny lists are checked after DNS resolution.
- The real-world scan denies private address space and sends one handshake per site, the same as a browser.
- External tools run with hard timeouts and process-group kill.

## Key material

The entropy module writes keys only when asked (`--key-out`), with mode 0600. Logs and the audit trail contain only a fingerprint. The HKDF mix with 32 bytes of `os.urandom` means a key is never weaker than a normally generated one, even though IBM sees the raw quantum bits.

## Reporting a vulnerability

Please open a private security advisory on the repository rather than a public issue.
