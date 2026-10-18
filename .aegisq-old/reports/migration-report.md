# AegisQ post-quantum migration report

Generated 2026-10-15 05:50 UTC by AegisQ 1.0.0.
Audit log: **intact** (264 entries, HMAC-keyed hash chain).

## Summary

Scan `757c7444b89e` finished 2026-10-15 05:50 UTC: 7 services, 0 reachable.

| Status | Count |
|---|---|
| Post-quantum ready | 0 |
| Classical key exchange only | 0 |
| TLS 1.2 only | 0 |
| Legacy TLS 1.0/1.1 only | 0 |
| Plaintext HTTP | 0 |
| Unreachable / error | 7 |

**0.0%** of reachable services complete a hybrid ML-KEM key exchange.
At Z = 10.0 years, **0** services have data that is already at risk (X + Y > Z).

## Risk ranking (Mosca: margin = X + Y − Z, Z = 10.0)

| # | Service | Status | Data | X | Y | Margin | Severity | At risk for any Z below |
|---|---|---|---|---|---|---|---|---|
| 1 | app-modern | unreachable | health | 25.0 | 0.0 | +0.0 | unknown | - |
| 2 | ssh-legacy | unreachable | health | 25.0 | 0.0 | +0.0 | unknown | - |
| 3 | app-tls12 | unreachable | pii | 10.0 | 0.0 | +0.0 | unknown | - |
| 4 | app-legacy | unreachable | payments | 7.0 | 0.0 | +0.0 | unknown | - |
| 5 | app-plain | unreachable | internal | 3.0 | 0.0 | +0.0 | unknown | - |
| 6 | ssh-pq | unreachable | internal | 3.0 | 0.0 | +0.0 | unknown | - |
| 7 | app-ready | unreachable | marketing | 1.0 | 0.0 | +0.0 | unknown | - |

## Migration actions

### app-modern — fixed
- `2026-10-04 01:18:32` (agent) Proposed: `- ssl_ecdh_curve X25519:prime256v1;` `+ ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (branch aegisq/app-modern/9aaa3d471e)
- `2026-10-04 01:25:58` (agent) Approval approved by soorya
- `2026-10-04 01:26:30` (agent) Applied; config test passed; reloaded
- `2026-10-04 01:27:11` (agent) Verified: negotiated X25519MLKEM768 (1120-byte server share); health HTTP 200
- `2026-10-04 02:12:28` (agent) Proposed: `- ssl_ecdh_curve X25519:prime256v1;` `+ ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (branch aegisq/app-modern/29ff227d7e)
- `2026-10-04 02:13:10` (agent) Approval approved by soorya
- `2026-10-04 02:13:35` (agent) Applied; config test passed; reloaded
- `2026-10-04 02:14:14` (agent) Verified: negotiated X25519MLKEM768 (1120-byte server share); health HTTP 200

### app-tls12
- `2026-10-04 01:28:12` (agent) Proposed: `- ssl_protocols TLSv1.2;` `- ssl_ecdh_curve X25519:prime256v1;` `+ ssl_protocols TLSv1.2 TLSv1.3;` `+ ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (branch aegisq/app-tls12/69eeed2d27)
- `2026-10-04 01:43:41` (agent) Proposed: `- ssl_protocols TLSv1.2;` `- ssl_ecdh_curve X25519:prime256v1;` `+ ssl_protocols TLSv1.2 TLSv1.3;` `+ ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (branch aegisq/app-tls12/e0407e51a8)
- `2026-10-04 02:17:13` (agent) Proposed: `- ssl_protocols TLSv1.2;` `- ssl_ecdh_curve X25519:prime256v1;` `+ ssl_protocols TLSv1.2 TLSv1.3;` `+ ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (branch aegisq/app-tls12/42a4a6596e)
- `2026-10-04 02:17:57` (agent) Approval approved by soorya
- `2026-10-04 02:18:34` (agent) Applied; config test passed; reloaded

### app-legacy — failed (rolled back)
- `2026-10-04 01:45:25` (agent) Proposed: `- ssl_ecdh_curve X25519:prime256v1;` `+ ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (branch aegisq/app-legacy/494fdad3b8)
- `2026-10-04 01:49:08` (agent) Approval approved by soorya
- `2026-10-04 01:49:44` (agent) Config test FAILED, previous config restored. Root cause: nginx is linked against OpenSSL 3.0.11, which has no ML-KEM. X25519MLKEM768 was added in OpenSSL 3.5, so the TLS library rejected the group list. Recommendation: Upgrade this server to an nginx build linked against OpenSSL 3.5 or later (for example nginx 1.29 on Alpine 3.22+, Ubuntu 26.04 or Debian 13), then re-run AegisQ. No config change can fix this on the current library.
- `2026-10-04 02:56:46` (agent) Proposed: `- ssl_ecdh_curve X25519:prime256v1;` `+ ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (branch aegisq/app-legacy/0e6b1ba0a7)
- `2026-10-04 02:58:01` (agent) Approval approved by soorya
- `2026-10-04 02:58:29` (agent) Config test FAILED, previous config restored. Root cause: nginx is linked against OpenSSL 3.0.11, which has no ML-KEM. X25519MLKEM768 was added in OpenSSL 3.5, so the TLS library rejected the group list. Recommendation: Upgrade this server to an nginx build linked against OpenSSL 3.5 or later (for example nginx 1.29 on Alpine 3.22+, Ubuntu 26.04 or Debian 13), then re-run AegisQ. No config change can fix this on the current library.



## Handshake cost (measured)

| Setting | n | p50 (ms) | p99 (ms) | Failures |
|---|---|---|---|---|
| X25519MLKEM768 (to ServerHello, native) | 200 | 26.773 | 48.412 | 0 |
| x25519 (to ServerHello, native) | 200 | 25.879 | 74.338 | 0 |

Measured against the target as configured; on localhost there is no network delay, so these numbers are computation cost only. Real-world latency also depends on round trips and packet loss.

## Where the Z assumption comes from

| Estimate | Target | Logical qubits | Physical qubits | Runtime |
|---|---|---|---|---|
| Google Quantum AI, March 2026 | 256-bit elliptic curve | ≤ 1,200 (≤ 90M Toffoli) or ≤ 1,450 (≤ 70M Toffoli) | Under 500,000 superconducting | Minutes |
| IonQ, 2026 | 256-bit elliptic curve | 1,457 (39M Toffoli) | About 20,000 trapped-ion | About 26 days per attempt |
| Gidney, May 2025 | RSA-2048 | n/a | Under 1,000,000 superconducting | Under a week |

These estimates target secp256k1; X25519 uses Curve25519, a different curve of the same size, so they are a close proxy rather than an exact figure. Current IBM processors have ~156 physical qubits and no error-corrected logical qubits at this scale: the threat is future, but traffic recorded today is already exposed.