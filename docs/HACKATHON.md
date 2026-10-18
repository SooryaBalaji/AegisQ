# AegisQ at the hackathon

This page is for the team. It covers what each prize asks for, what to do before judging, and the demo.

## What each prize asks for, and where AegisQ shows it

### Best Use of Gemma 4 (Google DeepMind)

MLH asks judges to confirm that the project uses a Gemma model through the Gemini API, to find the model named in the README, and to see the integration in the code or the demo ([MLH Gemma module](https://hacktoberfest-handbook.mlh.com/hack-days-partner-modules/partner-challenge-google-gemma)).

| The prize's themes | In AegisQ |
|---|---|
| Multimodal experience: text and images | **Check a claim** reads console screenshots and config text, then tests every claim with a real handshake |
| A focused AI tool for productivity or your community | The **owner brief** turns scan facts into a ticket a busy team can act on, with every sentence fact-checked |
| Rapid prototyping on the Gemini API | `gemma-4-31b-it` through the Gemini API's native `generateContent`; the same code runs Gemma 4 locally in Ollama |

### Open-source / open-weight AI (DigitalOcean)

The requirements on the [MLH open-source prize page](https://hacktoberfest-handbook.mlh.com/fest-planning-guide/open-source-prize-categories):

| Requirement | In AegisQ |
|---|---|
| Open-source or open-weight AI is an important part | Gemma 4 (open weights, Apache 2.0) reads screenshots, writes owner briefs and drives the fixer |
| Public GitHub repository with an open-source license | Apache-2.0 [`LICENSE`](../LICENSE); the repository must be public before judging |
| An agent skill complies with the Agent Skill Open Standard | [`skills/aegisq-pq-scan`](../skills/aegisq-pq-scan/SKILL.md) passes `agentskills validate` |
| A model harness is an original implementation | `GemmaPlanner` in [`runner.py`](../src/aegisq/agent/runner.py) with the native adapter in [`native.py`](../src/aegisq/agent/native.py); `aegisq redteam` shows that it holds |
| Strong entries make the source, license, model and dependencies easy to verify | The "For judges" table at the top of the [README](../README.md) |

Check the event's own page for the exact DigitalOcean prize rules. The MLH page above does not mention DigitalOcean infrastructure. The separate online DEV Hacktoberfest challenges have their own rules, including a minimum age of 18 ([DEV](https://dev.to/challenges/hf26)), so they are not the same entry.

## Eligibility

The event host has confirmed that an existing project may be entered. Submit through the event's **OrganizerHQ Challenges** page ([MLH host guide](https://hacktoberfest-handbook.mlh.com/fest-planning-guide.md)), and follow the [MLH Code of Conduct](https://mlh.io/code-of-conduct).

## On GitHub

- The repository is public. After pushing, check that the **License** shows Apache-2.0 in the sidebar.
- In the repository's About settings, change the description (it still says QShield) to: _Post-quantum readiness for real servers: proven with handshakes, explained by Gemma 4, fixed only with a person's approval._
- Add topics: `gemma`, `gemma-4`, `post-quantum`, `agent-skills`, `open-source-ai`, `hacktoberfest`.

## Before judging (in this order)

1. **Get a key** at [aistudio.google.com/apikey](https://aistudio.google.com/apikey) and put `GEMINI_API_KEY=...` in `demo/.env`.
2. **Quick check that Gemma 4 answers** (plain Python, nothing to install):
   ```
   python scripts/check_gemma.py
   ```
   Three `PASS` lines (text, image, tool call) mean the key and the model work.
3. **Run the full live check** and keep the output:
   ```
   aegisq gemma-check --api both | tee docs/live/gemma-check.txt
   ```
   If only one API passes, set `AEGISQ_LLM_API` to the one it names, in `demo/.env`.
4. **Red-team Gemma 4** and keep the output:
   ```
   aegisq redteam --planner gemma | tee docs/live/redteam-gemma.txt
   ```
   It must end with four `pass` lines. If it does not, do not claim it; fix it or leave it out.
5. **Start the demo fleet** (README, Quick start, step 3) and run the claim check on the demo screenshot:
   ```
   aegisq claims check --image docs/demo/console-claim.png --yes | tee docs/live/claims-image.txt
   ```
   Expected: `127.0.0.1:8443` contradicted, `8445` and `8446` confirmed.
6. **Fix one server live** with Gemma 4, approving as a second user: `aegisq serve --inventory demo/fleet.yaml`, then Run, *Scan and fix*, Gemma 4, only `app-modern` and `app-legacy`. `app-modern` should end verified; `app-legacy` should be refused or rolled back with OpenSSL 3.0 as the reason.
7. **Write a brief** for `app-legacy` (Overview, click it, *Write with Gemma 4*) and keep a screenshot.
8. **Record the 90-second video** (below) and put the link in the README's "For judges" table.
9. Run `pip install skills-ref` and `agentskills validate skills/aegisq-pq-scan`.
10. Push, then check that the LICENSE shows on GitHub.
11. Run `make lint typecheck test` and update the test count in the README if it changed.

Only claim what these runs showed. If Gemma 4 gets something wrong, say so; the point of AegisQ is that a wrong answer is caught.

## Demo script (90 seconds)

| Time | Show | Say |
|---|---|---|
| 0:00 | README top | "Traffic recorded today can be decrypted later. New software turns on post-quantum key exchange by default; AegisQ finds the servers where that did not happen, proves it, and fixes them with a person's approval. The AI is Gemma 4." |
| 0:10 | **Check a claim**: drop `docs/demo/console-claim.png` | "Teams prove migrations with screenshots. Gemma 4 reads this one and lists three servers and what it claims about them." |
| 0:25 | Pick all three, **Test** | "AegisQ doesn't trust the screenshot: it does a real handshake. This one says Enabled, but the server only does classical key exchange: contradicted." |
| 0:40 | **Run**: Scan and fix with Gemma 4 | "Gemma 4 plans the fix. It proposes one line; a second person approves; AegisQ tests, reloads and verifies from outside. On the old server the config test fails, it rolls back and names OpenSSL 3.0 as the cause." |
| 1:00 | Overview, `app-legacy`, **Write with Gemma 4** | "Gemma 4 writes the ticket for that server's owner. Every sentence cites facts; anything it can't back up is removed, and the fix is vendor documentation, never AI text." |
| 1:15 | Terminal: `aegisq redteam --planner gemma` | "We attacked it: a config comment tells the AI to skip approval and downgrade TLS. Everything is refused, and the code checks the files, not the AI's word." |
| 1:25 | README "For judges" | "Apache-2.0, an agent skill, a GitHub Action. Thank you." |

Let the person who built it present every live part.
