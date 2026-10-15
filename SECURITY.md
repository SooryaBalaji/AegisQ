# AegisQ security model

AegisQ can change production server configuration, so its own safety properties are explicit, enforced in code, and tested.

## What the migration agent can and cannot do

- **Scope.** The agent can only touch services that have a `managed` block in the inventory, which is written by an operator. It receives service names, never file paths or commands. Commands are argv lists from the inventory and are never passed through a shell.
- **Content.** A patch may only add, remove or change `ssl_ecdh_curve` and `ssl_protocols` lines. Each changed line must be exactly one directive whose value contains none of `; { } ' " \ $ #`. Values come from an allowlist:
  - A post-quantum hybrid group must come first.
  - A classical fallback is required by default.
  - TLS 1.3 is required, and SSLv3/TLS 1.0/1.1 are refused.

  For OpenSSH (`kind: sshd`), a patch may only change the global `KexAlgorithms` line: an explicit list of names from an allowlist (no `+`, `-` or `^` modifiers, no quotes or comments), never inside a `Match` block. A post-quantum hybrid must come first, a classical fallback is required by default, and known-weak methods (SHA-1 and 1024-bit Diffie-Hellman) are refused.

  For Apache, HAProxy, Caddy, Postfix and Dovecot, a patch may only change that server's one group-list line (`SSLOpenSSLConfCmd Groups`, `ssl-default-bind-curves` in `global`, `curves`, `tls_eecdh_auto_curves` without continuation lines, `ssl_curve_list`), with the same allowlist and ordering rules. Before approval is requested for Apache, Postfix or Dovecot, AegisQ loads the server's `libssl` in a separate Python process to confirm it accepts the list; the path comes from `ldd` on the server's own files or from `tls_library` in the inventory, which is trusted configuration like the test and reload commands.

  The diff is parsed strictly (exact context, checked hunk counts, one file), applied without fuzz, and the result is re-diffed independently. A mutation fuzzer in the test suite checks that no accepted patch changes any other line.
- **Approval.** Applying requires an approval that is:
  - decided by a named human (reserved names such as `agent` or `claude` are refused);
  - approved, unexpired and unused (single use);
  - bound to the SHA-256 of the exact diff.

  The agent has no tool that can approve anything. With separation of duties (on by default), the person who started the run cannot approve its changes either; the approval records who started it.
- **Roles.** Every API route checks the caller's role: viewers only read, operators start jobs, approvers decide approvals, admins manage users, schedules and alerts. Tokens are stored only as SHA-256 hashes, and the last admin cannot be removed or demoted.
- **Change safety.**
  - Applying is refused if the live file changed since the proposal.
  - The previous config is backed up first, the write is atomic, and the server's config test (`nginx -t`, `apachectl configtest`, `haproxy -c`, `caddy validate`, `postfix check`, `doveconf -n` or `sshd -t`) runs before any reload. Reloading sshd keeps existing sessions open, so an operator who is logged in stays logged in.
  - On a test or reload failure the old config is restored automatically.
  - A per-service lock prevents concurrent changes.
  - Only one change may be unverified at a time, and anything still unverified when the agent stops is rolled back.
- **The model.** Claude (`--planner claude`) or an open model such as Gemma 4 (`--planner local`) chooses which tool to call next. Both go through the same dispatcher and the same tools. Tool inputs are schema-validated, unknown tools and fields are rejected, and every call and result is written to the audit log. A refusal, turn limit or endpoint failure stops the run, and the safety-net rollback still happens.
- **What the model provider sees.** The tool results, which include the managed server configs and the scan results, are sent to whichever endpoint you choose: Anthropic, Google (Gemini API) or a model server you run yourself. For configs that must not leave the network, use a local model server (`AEGISQ_LLM_BASE_URL`) or `--planner rules`. API keys come only from the environment, are never logged, are sent only to the endpoint they belong to (a Gemini key is not sent to a custom `AEGISQ_LLM_BASE_URL`), and are never sent over plain HTTP except to localhost.

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
- External tools run with hard timeouts and process-group kill.

## Reporting a vulnerability

Please open a private security advisory on the repository rather than a public issue.
