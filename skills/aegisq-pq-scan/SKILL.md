---
name: aegisq-pq-scan
description: Checks whether TLS, SSH and mail (STARTTLS) servers use post-quantum key exchange (ML-KEM hybrids such as X25519MLKEM768 and mlkem768x25519-sha256) with real handshakes, ranks which ones to fix first, writes a CycloneDX 1.6 cryptographic bill of materials (CBOM), and gives the vendor-documented fix for each server. Use when someone asks if their servers, website, mail or SSH are quantum-safe or post-quantum ready, wants a crypto inventory or CBOM, or shares a config or console screenshot claiming post-quantum is enabled.
license: Apache-2.0
compatibility: Requires Python 3.10+ and the aegisq package (pip install "git+https://github.com/SooryaBalaji/AegisQ"), plus network access to the servers being checked. Claim checks need Gemma 4 through GEMINI_API_KEY or a local Ollama gemma4 model.
metadata:
  author: SooryaBalaji
  version: "1.0"
  homepage: https://github.com/SooryaBalaji/AegisQ
---

# Post-quantum readiness scan with AegisQ

AegisQ sends real handshakes that offer only post-quantum key exchange and reports what each server does. Scanning
changes nothing on the servers. This skill never changes server configuration.

## Before you start

1. Check that AegisQ is installed: `python -c "import aegisq"`. If not, install it with
   `pip install "git+https://github.com/SooryaBalaji/AegisQ"`.
2. Only scan servers the user owns or is allowed to test. If the user names a server they do not control, say so
   and ask before scanning.

## Scan servers

Run the bundled script with one target per argument. A target is `host`, `host:port`, `host:port ssh`, or a mail
server as `host:25 smtp`, `host:143 imap` or `host:110 pop3`:

```bash
python scripts/pq_check.py example.com mail.example.com:25 smtp git.example.com:22 ssh
```

It prints one JSON object. For each server:

- `status`: `pq_ready` (completes a hybrid post-quantum exchange), `classical`, `tls12_only`, `legacy_tls`,
  `plaintext`, `unreachable` or `error`
- `key_exchange`: what was negotiated
- `fix`: the vendor-documented change, when the server is not ready
- `risk_rank`: fix order; lower is more urgent

Add `--cbom cbom.json` to also write a CycloneDX 1.6 CBOM that is validated against the official schema.

## Explain the result

- Lead with how many servers are post-quantum ready out of how many were reached.
- For each server that is not ready, give the `fix` text as written. Do not invent version numbers or settings.
- `tls12_only` and `legacy_tls` servers need TLS 1.3 before any post-quantum change.
- If a fix says the TLS library must be OpenSSL 3.5 or later, the server needs a library or OS upgrade, not only a
  config change.
- `unreachable` means the scan could not connect. It does not mean the server is safe.

## Check a claim (config or screenshot)

When the user shares a config file, command output, or a screenshot that says post-quantum is enabled, check it
instead of trusting it:

```bash
aegisq claims check --text shared.conf --yes      # or: --image console.png
```

Gemma 4 lists the endpoints and claims it reads, and AegisQ scans each one. Every claim comes back as
`CONFIRMED`, `CONTRADICTED` or `UNVERIFIABLE`. Report contradicted claims plainly. Without `--yes`, AegisQ asks
before scanning each endpoint. See [the reference](references/REFERENCE.md) for statuses and exit codes.

## Write the ticket for the owning team

After a scan, AegisQ can write a short brief for the team that owns one server:

```bash
aegisq brief SERVICE_NAME            # Gemma 4 writes it; add --template to skip the model
```

Every sentence cites numbered facts from the scan and the audit log, and a sentence is removed if it mentions a
version, number, name or command that is not in the facts it cites. The fix at the end is vendor documentation,
copied word for word. Pass the brief on as written; do not add steps of your own.
