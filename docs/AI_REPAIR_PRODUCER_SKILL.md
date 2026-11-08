# Repair claim producer contract / AI agent Skill

This contract applies to Gemini CLI, Claude Code, Codex, Grok, Cursor and any other coding agent. It is not an API connector or global chat interceptor.

## Agent instruction

When you say a software defect was fixed:

1. Commit the real code changes on an isolated feature branch. Never rewrite a frozen audit ledger, never alter `main` without authorized review.
2. Record the **actual 40-character Git SHA** of the fix, not a fabricated digest. Capture exact failing reproduction and the new regression test, if possible.
3. Use only `checks` IDs published in the repository maintainer-approved `gateway/checks.json`. If the bug lacks a mapped issue-specific regression check, request registration and mark `EVIDENCE_MISSING`. Do not self-register a trivial always-passing test.
4. Open or update a GitHub Pull Request whose body includes exactly one HTML comment fenced `quorum-ai-repair` JSON object (or array, max 10), as in `examples/ai_repair_pr_body.md`. Describe `producer.provider`, `model`, and `run_id` accurately. These fields are self-declared, not identity proof.
5. The PR edit triggers GitHub Actions. Only the verifier may assign `PASS_VERIFIED`. A green model response is never proof; provide GitHub Actions run URL, SHA, artifact and decision.
6. If the agent cannot open a PR or obtain the true commit SHA, say `EVIDENCE_MISSING` rather than inventing a submission or reporting success.

## Verifier invariants

- SHA must match PR HEAD (GitHub event) or be its proven ancestor; checked-out HEAD must exactly match the event.
- Every claim needs at least one approved, issue-matched regression test. The PR cannot alter registered protected tests without a trusted registry update.
- Registry commands come from **trusted default branch**. Commands, paths, and output status are never accepted from AI messages.
- No secrets, deployment keys, or write token are exposed to untrusted PR tests. Never use `pull_request_target` to run PR code.
- Keep log hash and provenance; do not suppress `FAIL_REPRODUCED` or `EVIDENCE_MISSING` as a green result.

## Limitations

No automated extraction from private cloud chats without each service's explicit connector/OAuth permissions. Provider identity stays `SELF_DECLARED` without verified signed attestations. Registered tests can be inadequate: a human still must review test relevance and side effects.
