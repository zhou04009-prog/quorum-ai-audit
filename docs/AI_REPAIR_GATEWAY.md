# Cross-AI → Quorum Repair Gate (MVP)

**Scope**: one GitHub PR automatically triggers an independent, replayable audit of AI repair declarations. No provider API key, paid browser, or manual copying into `reviews/dispose.md` is needed. This **does not** automatically read private Gemini/Claude/Grok conversations; each coding agent must create or edit a PR description containing the standardized `quorum-ai-repair` JSON block. `provider` is self-declared until provider-specific signatures or authenticated adapters are added.

## Architecture

1. ChatGPT Codex / Gemini CLI / Claude Code / Grok / Cursor coding agents prepare fixes on an isolated branch and open PRs with the embedded `quorum-ai-repair` claim block. (A provider without GitHub PR access needs its own authorized adapter; not implemented.)
2. `pull_request` GitHub Actions reads the code from the **PR's exact HEAD** and verifier/allowed test registry from **trusted `main`**. No API keys or privileged write token are exposed to PR code.
3. `gateway/repair_gateway.py` parses PR content as **untrusted data**, checks schema, GitHub SHA lineage, claim ID, and issue-specific pre-approved regression checks. **It refuses AI-authored shell commands**.
4. The gateway generates a disposable Quorum ledger and config, then runs the existing installed `quorum verify --strict --no-incidents` CLI. Every check uses an approved registry argv, running from the PR source tree; the check wrapper records exit codes, complete argv, truncated log, SHA256, and timings.
5. The GitHub Actions check is red for `FAIL_REPRODUCED` / `EVIDENCE_MISSING`, green for verified checks. Evidence is uploaded as artifact even if validation fails.

## Installation (in a separate development branch)

Copy `gateway/repair_gateway.py`, `gateway/checks.json`, `.github/workflows/ai-repair-gate.yml`, and `tests/test_repair_gateway.py` to the matching paths of `zhou04009-prog/quorum-ai-audit`. **Review and test on the branch first.** To enable automatic PR checks, a maintainer later needs to merge **only these reviewed gateway additions** into the trusted default branch, and enable this workflow as a required status check (branch protection or ruleset). Do not merge the old negative acceptance test history or restore its temporary files.

The example in `examples/ai_repair_pr_body.md` is illustrative: replace the 40-character SHA with the genuine code-fix commit SHA, which must be an ancestor of the PR HEAD, and supply actual producer metadata. Check IDs must exist in the trusted `gateway/checks.json` registry. The gate requires one issue-specific regression check, not just a generic green test suite.

## Outcome contract

- `PASS_VERIFIED`: Quorum returns 0 and every approved check returned 0, with evidence written.
- `FAIL_REPRODUCED`: one or more authorized regression checks actually failed; Quorum is expected to detect an incorrectly asserted ✅ disposition.
- `EVIDENCE_MISSING`: malformed/missing manifest, missing or mismatched Git commit, unapproved check, absent logs, or inconsistent verifier result. **Never marks green**.

Artifacts: `audit-evidence/summary.json`, `ledger.md`, `verify.json`, `quorum.log`, and each check's `.json` and `.log` (log output bounded). SHA256 values allow file integrity comparison; they are not cryptographic signatures of the AI's identity. GitHub run URL and commit SHA are the authoritative run identifiers.

## Safety limitations

- PR bodies and AI descriptions are untrusted input. The test command registry must be reviewed by humans and read from trusted `main`, not from PR branches. Never interpolate AI text into shell commands.
- No `pull_request_target` event, no production secrets, no write token, and no deployment triggered by a passing audit. GitHub documentation explicitly warns against executing PR code under privileged `pull_request_target` workflows.
- Running tests on third-party PR code still executes untrusted code in an ephemeral Actions runner. Use private runners/network-isolated containers for higher-risk repositories, and ensure no secrets or write token reach the runner.
- This gate verifies only claims **with registered, meaningful checks**. It cannot infer a missing regression test from natural-language chat, authenticate a provider based on its self-claimed name, or assert external deployment correctness without independent external evidence.
- Preserve the repository's existing `ci.yml` and `reviews/review.yaml` unchanged.

**Regression-test integrity:** Registry entries may designate `protected_paths` (for example `tests/test_quorum.py`); if the PR alters these trusted regression tests relative to the reviewed base snapshot, intake fails closed. Tests run against PR code, but Quorum CLI runs with `PYTHONPATH` forced to the trusted verifier tree. Other package dependencies in the PR may still execute untrusted code in the runner.
