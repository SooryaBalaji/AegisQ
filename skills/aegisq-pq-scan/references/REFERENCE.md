# AegisQ reference for agents

## Statuses

| Status | Meaning | What to tell the user |
|---|---|---|
| `pq_ready` | The server completed a hybrid post-quantum key exchange when it was the only option offered | Protected against harvest-now-decrypt-later for key exchange |
| `classical` | TLS 1.3 or modern SSH, but only classical key exchange | Needs the `fix` text; often a library upgrade plus one config line |
| `tls12_only` | No TLS 1.3 | Enable TLS 1.3 first; post-quantum groups need it |
| `legacy_tls` | Only TLS 1.0 or 1.1 | Urgent upgrade, independent of quantum risk |
| `plaintext` | Answers unencrypted HTTP | Readable today, not only after a quantum computer |
| `unreachable` | No connection | Not a result: check the host, port and firewall |
| `error` | Connected, but the answer was not understood, or the target was refused by scope | Report the error text |

## Commands

| Command | Does |
|---|---|
| `aegisq scan FILE --json` | Handshake scan of an inventory (YAML, JSON or one target per line) |
| `aegisq scan FILE --fail-on classical` | Exit code 2 if any reached server is not post-quantum ready (for CI) |
| `aegisq risk --json` | Fix order by Mosca margin (data lifetime + migration time - years to a quantum computer) |
| `aegisq cbom --out cbom.json` | CycloneDX 1.6 CBOM, validated against the official schema |
| `aegisq claims check --text FILE` or `--image FILE` | Gemma 4 reads the claims; every claim is checked with a handshake |
| `aegisq gemma-check` | Three live requests to the configured Gemma 4 model |

## Claim verdicts

- `confirmed`: the handshake matches what the source says.
- `contradicted`: the handshake disagrees. The output shows both sides and the vendor-documented fix.
- `unverifiable`: the server could not be reached, or the source made no post-quantum claim. Library versions
  are always unverifiable from outside.

Evidence marked "NOT found in your text" was not quoted from the input. Treat that endpoint with suspicion.
