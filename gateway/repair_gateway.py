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
import xml.etree.ElementTree as ET
from typing import Any

SCHEMA = 1
MARKER = re.compile(r"<!--\s*quorum-ai-repair\s*\n(.*?)\n\s*-->", re.DOTALL | re.IGNORECASE)
SLUG = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
ISSUE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_BODY = 32_000
# A deliberately narrow, code-reviewed list. Workflow/config/code/test changes NEVER skip.
DOC_PATH = re.compile(r"(?:README\.md|(?:docs|examples)/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.md)\Z")
# A pytest test target: a relative .py path (no traversal, no leading dash)
# plus optional :: segments (class / test / parametrize id).
NODE_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]*\.py(::[A-Za-z0-9_.\[\]-]+)*$")


def _node_parts(node: str) -> tuple[str, str]:
    """Map a node id to the (classname, test name) pair junitxml uses."""
    parts = node.split("::")
    classname = parts[0][:-3].replace("/", ".")
    if len(parts) > 2:
        classname += "." + ".".join(parts[1:-1])
    return classname, parts[-1].split("[", 1)[0]


def _abs_node(subject: Path, node: str) -> str:
    """Resolve a registry node id to an absolute path (file part only)."""
    parts = node.split("::")
    return str(subject / parts[0]) + ("::" + "::".join(parts[1:]) if len(parts) > 1 else "")


def _parse_pytest_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """Extract only test targets from a trusted-registry pytest argv.

    The executor rebuilds the command from a fixed trusted template, so a
    registry entry can never smuggle in a plugin (`-p`), a config override
    (`-c`, `-o`, `--override-ini`, `--rootdir`), a different import mode, or
    any other pytest flag. Only verbosity, --noconftest, --deselect and
    test node ids survive; anything else fails closed."""
    require(argv[:3] == ["python3", "-m", "pytest"],
            "Pytest check must use the approved python3 -m pytest form")
    nodes, deselects = [], []
    i = 3
    while i < len(argv):
        a = argv[i]
        if a in ("-q", "-v", "--noconftest"):
            i += 1
        elif a == "--deselect":
            require(i + 1 < len(argv) and NODE_RE.fullmatch(argv[i + 1])
                    and ".." not in Path(argv[i + 1]).parts,
                    "Invalid --deselect target in trusted registry")
            deselects.append(argv[i + 1])
            i += 2
        elif NODE_RE.fullmatch(a) and ".." not in Path(a).parts:
            nodes.append(a)
            i += 1
        else:
            raise IntakeError(f"Unapproved pytest argument in trusted registry: {a[:80]}")
    return nodes, deselects


def _verify_junitxml(xml_path: Path, nodes: list[str]) -> tuple[bool, dict[str, Any], str]:
    """Verify structured pytest evidence.

    The XML must exist, parse, and show every expected node actually ran
    and passed (no failure/error/skipped child), with zero failures/errors
    in the whole run. Returns (ok, summary, error). Output text is never
    consulted: a PR-controlled plugin can print any string it likes."""
    summary: dict[str, Any] = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    if not xml_path.is_file():
        return False, summary, "junitxml evidence file missing"
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as exc:
        return False, summary, f"junitxml evidence unparsable: {exc}"
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    cases = []
    for suite in suites:
        for attr in ("tests", "failures", "errors", "skipped"):
            try:
                summary[attr] += int(suite.get(attr, "0"))
            except ValueError:
                return False, summary, f"junitxml testsuite has non-numeric {attr}"
        cases.extend(suite.findall("testcase"))
    if summary["failures"] or summary["errors"]:
        return False, summary, "junitxml reports failures or errors"
    if nodes:
        found = []
        for node in nodes:
            classname, name = _node_parts(node)
            hit = None
            for case in cases:
                if case.get("classname") != classname:
                    continue
                cname = case.get("name", "")
                if cname == name or cname.startswith(name + "["):
                    hit = case
                    break
            if hit is None:
                return False, summary, f"junitxml has no testcase for node: {classname}::{name}"
            if (hit.find("failure") is not None or hit.find("error") is not None
                    or hit.find("skipped") is not None):
                return False, summary, f"junitxml shows node did not pass: {classname}::{name}"
            found.append(f"{classname}::{name}")
        summary["nodes_verified"] = found
        if summary["tests"] < len(nodes):
            return False, summary, "junitxml reports fewer tests than expected nodes"
    elif summary["tests"] < 1:
        return False, summary, "junitxml reports no tests ran"
    return True, summary, ""


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


def _run_pytest_check(subject: Path, spec: dict[str, Any], result_path: Path) -> dict[str, Any]:
    """Run a trusted-registry pytest check through the hardened executor.

    Trust boundary (v2, 2026-11-08 — replaces the F1 output-string check,
    which a PR-controlled pytest config could forge via a plugin):
    - The subject's pytest config is never read: `-c /dev/null` plus
      `-o addopts=` means no pyproject.toml / pytest.ini / setup.cfg /
      tox.ini in the PR tree can add options or load plugins.
    - No conftest.py (`--noconftest`) and no plugin other than the cache
      provider disable (`-p no:cacheprovider`); the registry argv is parsed
      through a strict allowlist and the command is rebuilt from a fixed
      template, so a registry entry can never smuggle in another flag.
    - Python startup hooks in the subject tree cannot run: pytest is
      launched with a trusted temp dir as cwd and PYTHONPATH, so the
      subject root is never on sys.path at interpreter startup (site would
      otherwise execute its sitecustomize.py / .pth files). The package
      under test is exposed only through a symlink in that trusted dir,
      and --rootdir pins pytest's own root to the subject.
    - Evidence is structured, not a string: pytest writes a junitxml
      report, which this trusted code parses and verifies (the expected
      node actually ran and passed). A forged pass string in the log is
      worthless on its own.
    Returns the check outcome fields for the result JSON."""
    nodes, deselects = _parse_pytest_argv(spec["argv"])
    xml_path = result_path.with_suffix(".xml")
    shim_dir = Path(tempfile.mkdtemp(prefix="trusted-pytest-shim-"))
    outcome: dict[str, Any] = {"exit_code": 1, "timed_out": False, "out": "", "err": "",
                               "evidence_verified": False, "evidence_summary": {},
                               "evidence_error": "", "executed_argv": []}
    try:
        pkg = subject / "quorum"
        if pkg.is_dir():
            (shim_dir / "quorum").symlink_to(pkg, target_is_directory=True)
        cmd = ["python3", "-m", "pytest", "-c", "/dev/null", "-o", "addopts=",
               "--noconftest", "-p", "no:cacheprovider",
               "--junitxml", str(xml_path), "--rootdir", str(subject)]
        cmd.append("-v" if nodes else "-q")
        # --deselect takes a node id, matched against the collected tests'
        # rootdir-relative ids: it must stay in the registry's relative
        # form. (An absolute path here does not match, so the deselected
        # test would run — in the read-only container it would then fail
        # for writing inside the repo, breaking the all-unit check.)
        for d in deselects:
            cmd += ["--deselect", d]
        # With no node target (full-suite check) pytest must be told where
        # to collect: it defaults to the cwd, which here is the trusted
        # shim dir, not the subject. Passing the subject as the collection
        # root replicates the old cwd=subject behaviour.
        cmd += [_abs_node(subject, n) for n in nodes] if nodes else [str(subject)]
        outcome["executed_argv"] = cmd
        env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL") if k in os.environ}
        env.update({"CI": "true", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                    "PYTHONPATH": str(shim_dir)})
        try:
            proc = subprocess.run(cmd, cwd=shim_dir, env=env, text=True,
                                  capture_output=True,
                                  timeout=int(spec.get("timeout_seconds", 120)),
                                  check=False, errors="replace")
            outcome["exit_code"], outcome["out"], outcome["err"] = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            outcome["timed_out"] = True
            outcome["exit_code"] = 124
            outcome["out"] = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            outcome["err"] = "TIMEOUT: approved check exceeded timeout"
        except (OSError, ValueError) as exc:
            outcome["err"] = f"CHECK_EXEC_ERROR: {type(exc).__name__}: {exc}"
            outcome["exit_code"] = 127
        ok, summary, error = _verify_junitxml(xml_path, nodes)
        outcome["evidence_summary"] = summary
        outcome["evidence_error"] = error
        # Evidence is only meaningful when the command itself exited 0; a
        # non-zero exit is already a failed check (FAIL_REPRODUCED).
        outcome["evidence_verified"] = bool(outcome["exit_code"] == 0 and ok)
        if xml_path.is_file():
            outcome["junitxml_sha256"] = digest(xml_path.read_bytes())
            outcome["junitxml_file"] = xml_path.name
    finally:
        shutil.rmtree(shim_dir, ignore_errors=True)
    return outcome


def cmd_check(a: argparse.Namespace) -> int:
    """Trusted wrapper invoked by quorum verify via a generated ledger check.

    Pytest checks run through the hardened trusted executor
    (_run_pytest_check): the subject's pytest config, conftest and Python
    startup hooks are all neutralised, and the pass verdict rests on a
    parsed junitxml report, never on output strings (v2, 2026-11-08).
    Non-pytest approved commands run verbatim as before: they come from
    the trusted registry, have no test-run concept, and their exit code
    is their own evidence. The production registry is pytest-only."""
    subject = Path(a.subject).resolve()
    result_path = Path(a.result).resolve()
    registry = load_registry(Path(a.registry).resolve())
    check_id = a.check_id
    require(check_id in registry, "Unknown check")
    spec = registry[check_id]
    out = ""; err = ""; code = 1; timed_out = False
    evidence_verified = True
    evidence_summary: dict[str, Any] = {}
    evidence_error = ""
    executed_argv: list[str] = list(spec["argv"])
    junitxml_sha256 = None
    junitxml_file = None
    t0 = dt.datetime.now(dt.timezone.utc)
    if "pytest" in spec["argv"]:
        try:
            outcome = _run_pytest_check(subject, spec, result_path)
        except IntakeError as exc:
            # Unapproved registry content fails closed, with a result JSON.
            outcome = {"exit_code": 127, "timed_out": False, "out": "",
                       "err": f"CHECK_CONFIG_ERROR: {exc}", "evidence_verified": False,
                       "evidence_summary": {}, "evidence_error": str(exc),
                       "executed_argv": []}
        code, out, err = outcome["exit_code"], outcome["out"], outcome["err"]
        timed_out = outcome["timed_out"]
        evidence_verified = outcome["evidence_verified"]
        evidence_summary = outcome["evidence_summary"]
        evidence_error = outcome["evidence_error"]
        executed_argv = outcome["executed_argv"]
        junitxml_sha256 = outcome.get("junitxml_sha256")
        junitxml_file = outcome.get("junitxml_file")
        if not evidence_verified and code == 0:
            # The command exited 0 but produced no trustworthy evidence
            # that a test ran. Do not override the exit code: the audit
            # distinguishes this (EVIDENCE_MISSING) from a reproduced
            # regression (FAIL_REPRODUCED) via evidence_verified.
            err = f"CHECK_EVIDENCE_MISSING: {evidence_error}" if evidence_error else "CHECK_EVIDENCE_MISSING"
    else:
        env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL") if k in os.environ}
        env.update({"CI": "true", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(subject)})
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
    # Bound collected bytes; no credential environment variables passed to the check.
    log = ("STDOUT:\n" + out + "\nSTDERR:\n" + err)[-65_536:]
    log_path = result_path.with_suffix(".log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(log, encoding="utf-8")
    result: dict[str, Any] = {"check_id": check_id, "approved_argv": executed_argv,
                              "registry_argv": spec["argv"],
                              "exit_code": code, "timed_out": timed_out,
                              "evidence_verified": evidence_verified,
                              "evidence_summary": evidence_summary,
                              "evidence_error": evidence_error,
                              "duration_seconds": round((dt.datetime.now(dt.timezone.utc)-t0).total_seconds(), 3),
                              "log_sha256": digest(log.encode("utf-8")), "log_file": log_path.name}
    if junitxml_sha256 is not None:
        result["junitxml_sha256"] = junitxml_sha256
        result["junitxml_file"] = junitxml_file
    write_json(result_path, result)
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
        elif any(r.get("evidence_verified") is not True for r in results):
            # A check exited 0 but produced no verifiable structured
            # evidence that its test ran and passed (v2, 2026-11-08).
            # This is a missing-evidence outcome, not a reproduced
            # regression: the repair is unverified, and the merge is blocked.
            summary["decision"]="EVIDENCE_MISSING"
            summary["error"]="At least one approved check produced no verifiable test evidence"
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
