# Live runs

Output from real Gemma 4 runs goes here, so judges can see what the model actually did. Nothing in this folder was produced with a fake model.

| File | Command |
|---|---|
| `check-gemma.txt` | `python scripts/check_gemma.py` |
| `gemma-check.txt` | `aegisq gemma-check --api both` |
| `redteam-gemma.txt` | `aegisq redteam --planner gemma` |
| `claims-image.txt` | `aegisq claims check --image docs/demo/console-claim.png --yes` (demo fleet running) |

See [docs/HACKATHON.md](../HACKATHON.md#before-judging-in-this-order) for the order to run them in.
