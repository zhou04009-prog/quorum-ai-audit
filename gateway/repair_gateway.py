#!/usr/bin/env python3
"""PR-based cross-AI repair claim intake, with Quorum as independent check arbiter.

Only trusted registry commands are executed. Never execute commands from PR text.
Requires the existing quorum-review CLI in the environment.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any

SCHEMA = 1
MARKER = re.compile(r"<!--\s*quorum-ai-repair\s*\n(.*?)\n\s*-->", re.DOTALL | re.IGNORECASE)
SLUG = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
ISSUE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_BODY = 32_000
# A deliberately narrow, code-reviewed list. Workflow/config/code/test changes NEVER skip.
DOC_PATH = re.compile(r"(?:README\.md|(?:docs|examples)/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.md)\Z")


class IntakeError(ValueError):
    pass


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def git(subject: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(subject), *args], text=True, capture_output=True, check=False, timeout=15)


def require(cond: bool, message: str) -> None:
    if not cond:
        raise IntakeError(message)


def load_registry(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict) and data.get("schema_version") == SCHEMA, "Invalid trusted registry schema")
    checks = data.get("checks")
    require(isinstance(checks, dict) and bool(checks), "Trusted registry has no checks")
    for check_id, spec in checks.items():
        require(bool(SLUG.fullmatch(check_id)), "Invalid registry check ID")
        require(isinstance(spec, dict), f"Invalid check specification: {check_id}")
        argv = spec.get("argv")
        require(isinstance(argv, list) and bool(argv) and all(isinstance(a, str) and a for a in argv),
                f"Invalid trusted argv: {check_id}")
        require(1 <= int(spec.get("timeout_seconds", 120)) <= 600, "Invalid check timeout")
        protected = spec.get("protected_paths", [])
        require(isinstance(protected, list) and all(
            isinstance(x, str) and x and not x.startswith("/") and ".." not in Path(x).parts
            for x in protected), f"Invalid protected_paths: {check_id}")
        issues = spec.get("regression_for", [])
        require(isinstance(issues, list) and all(isinstance(k, str) and ISSUE.fullmatch(k) for k in issues),
                f"Invalid regression mapping: {check_id}")
    return checks


def validate_claim(claim: Any, checks: dict[str, dict[str, Any]], subject: Path, head_sha: str, trusted_root: Path) -> dict[str, Any]:
    require(isinstance(claim, dict) and claim.get("schema_version") == SCHEMA, "Invalid claim schema_version")
    claim_id, problem_id = claim.get("claim_id"), claim.get("problem_id")
    require(isinstance(claim_id, str) and SLUG.fullmatch(claim_id), "Invalid claim_id")
    require(isinstance(problem_id, str) and ISSUE.fullmatch(problem_id), "Invalid problem_id")
    producer = claim.get("producer")
    require(isinstance(producer, dict), f"{claim_id}: producer must be an object")
    for key in ("provider", "model", "run_id"):
        v = producer.get(key)
        require(isinstance(v, str) and 1 <= len(v) <= 128 and "\n" not in v, f"{claim_id}: missing/invalid producer.{key}")
    assertion = claim.get("claim")
    require(isinstance(assertion, str) and 8 <= len(assertion) <= 1000, f"{claim_id}: claim required")
    source = claim.get("source_commit")
    require(isinstance(source, str) and SHA.fullmatch(source), f"{claim_id}: source_commit must be a 40-character SHA")
    # Source must be a real ancestor of the checked-out pull-request HEAD.
    ancestor = git(subject, "merge-base", "--is-ancestor", source, head_sha)
    require(ancestor.returncode == 0, f"{claim_id}: source_commit is not an ancestor of checked-out HEAD")
    selected = claim.get("checks")
    require(isinstance(selected, list) and 1 <= len(selected) <= 10 and
            len(selected) == len(set(str(x) for x in selected)), f"{claim_id}: checks must be a nonempty unique list")
    require(all(isinstance(x, str) and x in checks for x in selected), f"{claim_id}: unknown/unapproved check ID")
    require(any(problem_id in checks[x].get("regression_for", []) for x in selected),
            f"{claim_id}: no independent, approved regression check matches problem_id")
    for check_id in selected:
        for relative in checks[check_id].get("protected_paths", []):
            trusted_file = trusted_root / relative
            subject_file = subject / relative
            require(trusted_file.is_file() and subject_file.is_file() and
                    digest(trusted_file.read_bytes()) == digest(subject_file.read_bytes()),
                    f"{claim_id}: approved regression test modified/missing: {relative}")
    # Provider/model/run IDs remain SELF-DECLARED; authoritative source is GitHub PR event.
    return {"schema_version": SCHEMA, "claim_id": claim_id, "problem_id": problem_id,
            "producer": producer, "producer_identity": "SELF_DECLARED", "claim": assertion,
            "source_commit": source, "checks": selected}


def parse_event(event_file: Path) -> tuple[dict[str, Any], list[Any]]:
    event = json.loads(event_file.read_text(encoding="utf-8"))
    require(isinstance(event, dict) and isinstance(event.get("pull_request"), dict), "Only pull_request events are supported")
    body = event["pull_request"].get("body") or ""
    require(isinstance(body, str) and len(body) <= MAX_BODY, "PR body is missing or too large")
    matches = MARKER.findall(body)
    # A malformed or multiply-declared claim must never fall into the docs-only path.
    require(len(matches) == 1 or (not matches and "quorum-ai-repair" not in body.lower()),
            "PR body must contain exactly one valid <!-- quorum-ai-repair ... --> block")
    claims = []
    if matches:
        parsed = json.loads(matches[0]); claims = parsed if isinstance(parsed, list) else [parsed]
        require(1 <= len(claims) <= 10, "Accept 1 to 10 claims per PR")
    head_sha = event["pull_request"].get("head", {}).get("sha", "")
    require(isinstance(head_sha, str) and SHA.fullmatch(head_sha), "PR head SHA missing")
    repo = event.get("repository", {}).get("full_name", "")
    require(isinstance(repo, str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo), "GitHub repository missing")
    base_sha = event["pull_request"].get("base", {}).get("sha", "")
    metadata = {"github_repository": repo, "github_pr_number": event["pull_request"].get("number"),
                "github_pr_url": event["pull_request"].get("html_url"), "github_head_sha": head_sha,
                "github_base_sha": base_sha, "github_event_sha256": digest(event_file.read_bytes())}
    return metadata, claims



def tracked_tree(root: Path) -> dict[str, tuple[str, str]]:
    """Read *committed* Git tree data without executing anything from PR content."""
    proc = subprocess.run(["git", "-C", str(root), "ls-tree", "-r", "-z", "HEAD"],
                          capture_output=True, timeout=15, check=False)
    require(proc.returncode == 0, "Unable to inspect committed Git tree")
    result = {}
    for entry in proc.stdout.split(b"\0"):
        if not entry:
            continue
        try:
            metadata, name = entry.split(b"\t", 1)
            mode, obj_type, oid = metadata.split(b" ")
            path = name.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise IntakeError("Unrecognized committed Git tree entry") from exc
        require(obj_type == b"blob", "Unexpected Git tree object type")
        result[path] = mode.decode("ascii"), oid.decode("ascii")
    return result


def docs_only_changes(subject: Path, base: Path, github_base_sha: str) -> list[str]:
    """Compare exact base and PR-HEAD trees; no untrusted labels or self-declarations."""
    require(bool(SHA.fullmatch(github_base_sha)), "GitHub base SHA missing")
    base_head = git(base, "rev-parse", "HEAD")
    require(base_head.returncode == 0 and base_head.stdout.strip() == github_base_sha,
            "Checked-out base SHA does not match GitHub PR event")
    before, after = tracked_tree(base), tracked_tree(subject)
    changed = sorted(path for path in before.keys() | after.keys()
                     if before.get(path) != after.get(path))
    require(bool(changed), "No committed file changes in PR")
    for path in changed:
        require(bool(DOC_PATH.fullmatch(path)),
                f"Repair claim required for non-documentation file: {path[:150]}")
        for meta in (before.get(path), after.get(path)):
            require(meta is None or meta[0] == "100644",
                    f"Non-regular documentation file forbidden: {path[:150]}")
    return changed


def cmd_check(a: argparse.Namespace) -> int:
    """Trusted wrapper invoked by quorum verify via a generated ledger check."""
    subject = Path(a.subject).resolve()
    result_path = Path(a.result).resolve()
    registry = load_registry(Path(a.registry).resolve())
    check_id = a.check_id
    require(check_id in registry, "Unknown check")
    spec = registry[check_id]
    out = ""; err = ""; code = 1; timed_out = False
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL") if k in os.environ}
    env.update({"CI": "true", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(subject)})
    t0 = dt.datetime.now(dt.timezone.utc)
    try:
        proc = subprocess.run(spec["argv"], cwd=subject, env=env, text=True,
                              capture_output=True, timeout=int(spec.get("timeout_seconds", 120)), check=False,
                              errors="replace")
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True; code = 124
        out = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = "TIMEOUT: approved check exceeded timeout"
    except (OSError, ValueError) as exc:
        err = f"CHECK_EXEC_ERROR: {type(exc).__name__}: {exc}"
        code = 127
    # Evidence-of-execution (P0, 2026-11-08): an exit code of 0 is only
    # trustworthy if a test actually ran. A conftest.py — or import-time code
    # in the subject tree — that calls os._exit(0) produces an empty log with
    # exit 0; without this check the gate would record a PASS for a repair
    # that was never tested. This applies to pytest checks only: a non-pytest
    # approved command has no test-run concept, and its exit code is its own
    # evidence. Node-targeted checks must show the node id (-v) or a passing
    # summary (-q); the full-suite check must show a passing-test summary.
    evidence_verified = True
    if code == 0 and "pytest" in spec["argv"]:
        combined = out + "\n" + err
        node = next((a for a in spec["argv"] if "::" in a), None)
        if node is not None:
            if node not in combined and " passed" not in combined:
                evidence_verified = False
                err = f"CHECK_EVIDENCE_MISSING: targeted test node did not run: {node}"
        elif " passed" not in combined:
            evidence_verified = False
            err = "CHECK_EVIDENCE_MISSING: no passing-test summary in log"
        if not evidence_verified:
            code = 1
    # Bound collected bytes; no credential environment variables passed to the check.
    log = ("STDOUT:\n" + out + "\nSTDERR:\n" + err)[-65_536:]
    log_path = result_path.with_suffix(".log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(log, encoding="utf-8")
    write_json(result_path, {"check_id": check_id, "approved_argv": spec["argv"],
                             "exit_code": code, "timed_out": timed_out,
                             "evidence_verified": evidence_verified,
                             "duration_seconds": round((dt.datetime.now(dt.timezone.utc)-t0).total_seconds(), 3),
                             "log_sha256": digest(log.encode("utf-8")), "log_file": log_path.name})
    print(f"APPROVED_CHECK id={check_id} exit={code} evidence={result_path} log_sha256={digest(log.encode('utf-8'))}")
    if code != 0:
        print(log[-1200:], file=sys.stderr)
    return 0 if code == 0 else 1


def cmd_audit(a: argparse.Namespace) -> int:
    outdir = Path(a.out).resolve(); outdir.mkdir(parents=True, exist_ok=True)
    subject = Path(a.subject).resolve(); registry_file = Path(a.registry).resolve()
    trusted_root = registry_file.parent.parent
    summary: dict[str, Any] = {"schema_version": SCHEMA,
        "audit_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "decision": "EVIDENCE_MISSING", "claims": [], "verifier": "quorum verify",
        "integration_stage": "PR_MANIFEST_GATE", "quorum_exit_code": None}
    try:
        checks = load_registry(registry_file)
        metadata, raw_claims = parse_event(Path(a.event))
        summary.update(metadata)
        repo_head = git(subject, "rev-parse", "HEAD")
        require(repo_head.returncode == 0 and repo_head.stdout.strip() == metadata["github_head_sha"],
                "Checked-out code SHA does not match GitHub PR event")
        if not raw_claims:
            require(bool(a.base), "Missing exact base checkout for non-repair classification")
            summary["changed_files"] = docs_only_changes(subject, Path(a.base).resolve(),
                                                          metadata["github_base_sha"])
            summary["decision"] = "SKIP_NON_REPAIR"
            summary["audit_scope"] = "STRICT_DOCS_ONLY"
            # This is a successful *scope exclusion*, never an accepted repair claim.
            return 0
        require(len(raw_claims) <= 10, "Too many claims")
        accepted = [validate_claim(c, checks, subject, metadata["github_head_sha"], trusted_root) for c in raw_claims]
        ids = [x["claim_id"] for x in accepted]
        require(len(ids) == len(set(ids)), "Duplicate claim IDs")
        summary["claims"] = accepted
        summary["trusted_registry_sha256"] = digest(registry_file.read_bytes())
        trusted_commit = git(trusted_root, "rev-parse", "HEAD")
        summary["trusted_verifier_commit"] = (trusted_commit.stdout.strip()
            if trusted_commit.returncode == 0 else None)
        summary["trusted_verifier_sha256"] = digest(Path(__file__).read_bytes())
        # Command fields contain ONLY the trusted wrapper, registry IDs and sanitized claim IDs.
        # PR prose and model-supplied shell commands NEVER enter the generated ledger.
        ledger = ["# Auto-generated, not authoritative input from model", "",
            "| # | 问题 | 处置 | check | status |", "|---|---|---|---|---|"]
        for c in accepted:
            for check_id in c["checks"]:
                result_file = outdir / "checks" / c["claim_id"] / f"{check_id}.json"
                cmd = [sys.executable, str(Path(__file__).resolve()), "check", "--subject", str(subject),
                       "--registry", str(registry_file), "--check-id", check_id, "--result", str(result_file)]
                command = " ".join(shlex.quote(x) for x in cmd)
                require("|" not in command and "`" not in command, "Unsafe path in trusted check invocation")
                ledger.append(f"| {c['claim_id']}.{check_id} | Independent regression check | AI claims fixed | `{command}` | ✅ |")
        ledger_file = outdir / "ledger.md"; ledger_file.write_text("\n".join(ledger)+"\n", encoding="utf-8")
        # Minimum isolated Quorum config. verify only uses repo/ledger; no live model or API key.
        cfg = {"project":"ai-repair-gateway", "repo":str(subject), "brief":str(ledger_file),
               "out_dir":str(outdir), "ledger":str(ledger_file),
               "channels":{"local":{"kind":"fake"}},
               "reviewers":[{"name":"local-checks", "channel":"local", "vendor":"independent-runner", "role":"primary"}]}
        config_file=outdir / "verify.json"; write_json(config_file,cfg)
        # Timeout layering (P1-2, 2026-11-08): quorum verify's per-command
        # timeout must exceed the registry's longest check timeout, so a hung
        # check is killed by its own timeout (result JSON with timed_out=true
        # -> FAIL_REPRODUCED) instead of quorum killing the ledger command
        # first (no result JSON -> EVIDENCE_MISSING). Layering: check (<=400)
        # < quorum per-command (600) < quorum overall (900) < job (1200).
        q_cmd_timeout = max(int(s.get("timeout_seconds", 120)) for s in checks.values()) + 200
        qcmd = [a.quorum_bin, "verify", "--config", str(config_file), "--ledger", str(ledger_file), "--no-incidents", "--strict", "--timeout", str(q_cmd_timeout)]
        # Trusted Quorum implementation must never be resolved from the AI's PR tree.
        trusted_env = dict(os.environ)
        trusted_env["PYTHONPATH"] = str(trusted_root)
        p = subprocess.run(qcmd, cwd=subject, env=trusted_env, text=True,
                           capture_output=True, timeout=a.quorum_timeout,
                           check=False, errors="replace")
        qlog=(p.stdout+"\n"+p.stderr)[-65_536:]
        (outdir/"quorum.log").write_text(qlog,encoding="utf-8")
        summary["quorum_exit_code"] = p.returncode
        summary["quorum_log_sha256"] = digest(qlog.encode("utf-8"))
        results=[]
        for c in accepted:
            for check_id in c["checks"]:
                fp=outdir/"checks"/c["claim_id"]/f"{check_id}.json"
                if fp.is_file():
                    res=json.loads(fp.read_text(encoding="utf-8"));res["claim_id"]=c["claim_id"]
                    results.append(res)
        summary["check_results"] = results
        expected_count=sum(len(c["checks"]) for c in accepted)
        if len(results) != expected_count:
            summary["decision"]="EVIDENCE_MISSING"
            summary["error"]="At least one approved check did not produce evidence"
        elif any(r["exit_code"] != 0 for r in results):
            summary["decision"]="FAIL_REPRODUCED"
        elif p.returncode == 0:
            summary["decision"]="PASS_VERIFIED"
        else:
            summary["decision"]="EVIDENCE_MISSING"
            summary["error"]="Quorum rejected or failed despite green individual checks"
        print(qlog[-6000:])
    except (IntakeError, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        summary["error"] = f"{type(exc).__name__}: {exc}"
        print("GATEWAY_INPUT_ERROR", summary["error"], file=sys.stderr)
    finally:
        write_json(outdir/"summary.json",summary)
        print("FINAL_DECISION",summary["decision"], "evidence=",outdir/"summary.json")
    return 0 if summary["decision"] == "PASS_VERIFIED" else 1


def main(argv: list[str] | None=None) -> int:
    p=argparse.ArgumentParser(description="Cross-AI repair claim to Quorum independent verification")
    sub=p.add_subparsers(dest="command",required=True)
    audit=sub.add_parser("audit")
    for key in ("event","subject","registry","out"):
        audit.add_argument("--"+key,required=True)
    audit.add_argument("--base", default=None, help="Exact checkout of GitHub PR base SHA")
    audit.add_argument("--quorum-bin",default="quorum")
    audit.add_argument("--quorum-timeout",type=int,default=900)
    audit.set_defaults(func=cmd_audit)
    check=sub.add_parser("check")
    for key in ("subject","registry","check-id","result"):
        check.add_argument("--"+key,required=True)
    check.set_defaults(func=cmd_check)
    try:
        args = p.parse_args(argv)
        return args.func(args)
    except (IntakeError, OSError, ValueError) as exc:
        print(f"GATEWAY_ERROR: {exc}",file=sys.stderr);return 2


if __name__=="__main__":
    sys.exit(main())
