import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"gateway"/"repair_gateway.py"


def _load_gateway():
    spec = importlib.util.spec_from_file_location("repair_gateway_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RG = _load_gateway()


def git(repo,*args):
    p=subprocess.run(["git","-C",str(repo),*args],text=True,capture_output=True,check=True)
    return p.stdout.strip()


@pytest.fixture
def fixture(tmp_path):
    subject=tmp_path/"subject";subject.mkdir()
    git(subject,"init","-q")
    git(subject,"config","user.name","Fixture")
    git(subject,"config","user.email","fixture" + chr(64) + "example.invalid")
    (subject/"hello.txt").write_text("sample\n")
    (subject/"tests").mkdir()
    (subject/"tests"/"test_approved.py").write_text("def test_kept():\n    assert True\n")
    git(subject,"add",".");git(subject,"commit","-qm","fixture commit")
    sha=git(subject,"rev-parse","HEAD")
    trusted=tmp_path/"trusted"
    (trusted/"gateway").mkdir(parents=True)
    (trusted/"tests").mkdir()
    (trusted/"tests"/"test_approved.py").write_bytes((subject/"tests"/"test_approved.py").read_bytes())
    registry=trusted/"gateway"/"checks.json"
    registry.write_text(json.dumps({"schema_version":1,"checks": {
        "safe-regression": {"argv":[sys.executable,"-c","print('OK_CHECK')"],
                             "timeout_seconds":20,"regression_for":["bug.fault"], "protected_paths":["tests/test_approved.py"]},
        "failing-regression": {"argv":[sys.executable,"-c","raise SystemExit(1)"],
                                "timeout_seconds":20,"regression_for":["bug.fault"], "protected_paths":["tests/test_approved.py"]},
    }}))
    claim={"schema_version":1,"claim_id":"gemini-1","problem_id":"bug.fault",
           "producer":{"provider":"Gemini","model":"model-x","run_id":"run-001"},
           "source_commit":sha,"claim":"The bug.fault regression is fixed","checks":["safe-regression"]}
    event=tmp_path/"event.json"
    def make_event(c):
        body="AI reported completion\n<!-- quorum-ai-repair\n"+json.dumps(c)+"\n-->"
        event.write_text(json.dumps({"repository":{"full_name":"org/project"},
            "pull_request":{"number":1,"body":body,"head":{"sha":sha},
                            "html_url":"https://github.com/org/project/pull/1"}}))
    make_event(claim)
    # Substitute only the Quorum *executable* to test orchestration locally.
    # This is explicitly NOT a real integration test of the external Quorum package.
    fake=tmp_path/"fake-quorum"
    fake.write_text("""#!/usr/bin/env python3
import sys,subprocess
from pathlib import Path
args=sys.argv
ledger=Path(args[args.index('--ledger')+1])
failed=0
for line in ledger.read_text().splitlines():
    if not line.startswith('| ') or '`' not in line: continue
    bits=line.split('|')
    cmd=bits[-3].strip().strip('`')
    p=subprocess.run(['bash','-lc',cmd],capture_output=True,text=True)
    if p.returncode: failed+=1
print(f'台账说谎 {failed}')
sys.exit(1 if failed else 0)
""")
    fake.chmod(0o755)
    return subject,registry,event,claim,make_event,fake,sha,tmp_path


def audit(t):
    subject,registry,event,claim,make_event,fake,sha,tmp=t
    out=tmp/"audit-out"
    cmd=[sys.executable,str(SCRIPT),"audit","--event",str(event),
         "--subject",str(subject),"--registry",str(registry),"--out",str(out),
         "--quorum-bin",str(fake)]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=25)
    return p,json.loads((out/"summary.json").read_text()),out


def test_passing_registered_check(fixture):
    p,report,out=audit(fixture)
    assert p.returncode==0,(p.stdout,p.stderr)
    assert report["decision"]=="PASS_VERIFIED"
    assert report["quorum_exit_code"]==0
    assert report["check_results"][0]["exit_code"]==0
    assert report["claims"][0]["producer_identity"]=="SELF_DECLARED"
    assert (out/"checks"/"gemini-1"/"safe-regression.log").exists()


def test_false_repair_fails_with_independent_evidence(fixture):
    subject,registry,event,claim,make_event,fake,sha,tmp=fixture
    claim["checks"]=["failing-regression"]
    make_event(claim)
    p,report,out=audit(fixture)
    assert p.returncode==1
    assert report["decision"]=="FAIL_REPRODUCED"
    assert report["quorum_exit_code"]==1
    assert report["check_results"][0]["exit_code"]==1
    assert "台账说谎" in (out/"quorum.log").read_text()


def test_missing_evidence_fails_closed(fixture):
    subject,registry,event,claim,make_event,fake,sha,tmp=fixture
    event.write_text(json.dumps({"repository":{"full_name":"org/project"},
        "pull_request":{"number":1,"body":"AI says fixed", "head":{"sha":sha}}}))
    p,report,out=audit(fixture)
    assert p.returncode==1
    assert report["decision"]=="EVIDENCE_MISSING"


def test_ai_supplied_shell_command_not_executed(fixture):
    subject,registry,event,claim,make_event,fake,sha,tmp=fixture
    claim["checks"]=["safe-regression"]
    claim["command"]="touch "+str(tmp/"SHOULD_NOT_EXIST")
    make_event(claim)
    p,report,out=audit(fixture)
    assert p.returncode==0
    assert not (tmp/"SHOULD_NOT_EXIST").exists()
    assert "SHOULD_NOT_EXIST" not in (out/"ledger.md").read_text()


def test_unapproved_check_and_missing_issue_regression_rejected(fixture):
    subject,registry,event,claim,make_event,fake,sha,tmp=fixture
    claim["checks"]=["unknown-check"]
    make_event(claim)
    p,report,out=audit(fixture)
    assert p.returncode==1 and report["decision"]=="EVIDENCE_MISSING"
    claim["checks"]=["safe-regression"];claim["problem_id"]="other.issue"
    make_event(claim)
    p,report,out=audit(fixture)
    assert p.returncode==1 and report["decision"]=="EVIDENCE_MISSING"


def test_sha_mismatch_rejected(fixture):
    subject,registry,event,claim,make_event,fake,sha,tmp=fixture
    claim["source_commit"]="1"*40
    make_event(claim)
    p,report,out=audit(fixture)
    assert p.returncode==1 and report["decision"]=="EVIDENCE_MISSING"


def test_duplicate_claim_id_rejected(fixture):
    subject,registry,event,claim,make_event,fake,sha,tmp=fixture
    make_event([claim,claim])
    p,report,out=audit(fixture)
    assert p.returncode==1 and report["decision"]=="EVIDENCE_MISSING"


def test_changed_regression_test_not_accepted(fixture):
    subject,registry,event,claim,make_event,fake,sha,tmp=fixture
    (subject/"tests"/"test_approved.py").write_text("def test_kept():\n    assert True # weakened\n")
    p,report,out=audit(fixture)
    assert p.returncode==1
    assert report["decision"]=="EVIDENCE_MISSING"
    assert "approved regression test modified" in report["error"]


@pytest.fixture
def nonrepair_fixture(tmp_path):
    """Independent exact-base and exact-head Git histories, like two Actions checkouts."""
    base = tmp_path / "base"
    base.mkdir()
    git(base, "init", "-q")
    git(base, "config", "user.name", "Fixture")
    git(base, "config", "user.email", "fixture" + chr(64) + "example.invalid")
    (base / "README.md").write_text("Base docs\n")
    (base / "src").mkdir()
    (base / "src" / "service.py").write_text("value = 1\n")
    (base / ".github" / "workflows").mkdir(parents=True)
    (base / ".github" / "workflows" / "ci.yml").write_text("name: ci\n")
    git(base, "add", ".")
    git(base, "commit", "-qm", "base")
    before = git(base, "rev-parse", "HEAD")
    subject = tmp_path / "subject"
    subprocess.run(["git", "clone", "-q", str(base), str(subject)], check=True)
    git(subject, "config", "user.name", "Fixture")
    git(subject, "config", "user.email", "fixture" + chr(64) + "example.invalid")
    registry = tmp_path / "trusted" / "gateway" / "checks.json"
    registry.parent.mkdir(parents=True)
    registry.write_text(json.dumps({"schema_version": 1, "checks": {
        "safe-regression": {"argv": [sys.executable, "-c", "print('ok')"],
                            "regression_for": ["bug.fault"]}
    }}))
    event = tmp_path / "event.json"

    def invoke(changes, *, body="Regular maintenance", base_sha=None, include_base=True):
        for path, value in changes.items():
            target = subject / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if value is None:
                target.unlink()
            elif isinstance(value, tuple) and value[0] == "symlink":
                target.symlink_to(value[1])
            else:
                target.write_text(value)
        git(subject, "add", "-A")
        if changes:
            git(subject, "commit", "-qm", "fixture change")
        sha = git(subject, "rev-parse", "HEAD")
        event.write_text(json.dumps({
            "repository": {"full_name": "org/project"},
            "pull_request": {"number": 123, "body": body, "head": {"sha": sha},
                             "base": {"sha": base_sha or before},
                             "html_url": "https://github.com/org/project/pull/123"}
        }))
        out = tmp_path / ("out" + str(len(list(tmp_path.glob("out*")))))
        command = [sys.executable, str(SCRIPT), "audit", "--event", str(event),
                   "--subject", str(subject), "--registry", str(registry),
                   "--out", str(out)]
        if include_base:
            command += ["--base", str(base)]
        p = subprocess.run(command, capture_output=True, text=True, timeout=15)
        return p, json.loads((out / "summary.json").read_text())
    return invoke


def test_docs_only_has_successful_nonrepair_status_not_false_pass(nonrepair_fixture):
    p, report = nonrepair_fixture({"docs/overview.md": "docs edit\n"})
    assert p.returncode == 0, (p.stdout, p.stderr)
    assert report["decision"] == "SKIP_NON_REPAIR"
    assert report["audit_scope"] == "STRICT_DOCS_ONLY"
    assert report["claims"] == []
    assert report["quorum_exit_code"] is None
    assert report["changed_files"] == ["docs/overview.md"]


def test_readme_and_examples_docs_only_are_safe(nonrepair_fixture):
    p, r = nonrepair_fixture({"README.md": "updated\n",
                             "examples/guide.md": "another doc\n"})
    assert p.returncode == 0 and r["decision"] == "SKIP_NON_REPAIR"


@pytest.mark.parametrize("path", [
    "src/service.py", "tests/test_hidden.py", ".github/workflows/ci.yml",
    "gateway/repair_gateway.py", "docs/setup.py", "docs/.hidden.md",
])
def test_missing_claim_on_non_documentation_changes_fails_closed(nonrepair_fixture, path):
    p, r = nonrepair_fixture({path: "changed\n"})
    assert p.returncode == 1
    assert r["decision"] == "EVIDENCE_MISSING"
    assert "Repair claim required" in r["error"]


def test_mixed_docs_and_code_cannot_bypass(nonrepair_fixture):
    p, r = nonrepair_fixture({"README.md": "doc\n", "src/service.py": "value = 2\n"})
    assert p.returncode == 1 and r["decision"] == "EVIDENCE_MISSING"


def test_symlink_disguised_as_docs_rejected(nonrepair_fixture):
    p, r = nonrepair_fixture({"docs/doc.md": ("symlink", "../src/service.py")})
    assert p.returncode == 1 and r["decision"] == "EVIDENCE_MISSING"
    assert "Non-regular documentation" in r["error"]


def test_no_base_checkout_fails_closed(nonrepair_fixture):
    p, r = nonrepair_fixture({"README.md": "docs\n"}, include_base=False)
    assert p.returncode == 1 and r["decision"] == "EVIDENCE_MISSING"


def test_wrong_github_base_sha_fails_closed(nonrepair_fixture):
    p, r = nonrepair_fixture({"README.md": "docs\n"}, base_sha="a" * 40)
    assert p.returncode == 1 and r["decision"] == "EVIDENCE_MISSING"
    assert "base SHA" in r["error"]


def test_malformed_claim_never_skips_even_with_docs_only(nonrepair_fixture):
    p, r = nonrepair_fixture({"docs/overview.md": "docs\n"},
                             body="<!-- quorum-ai-repair\n{invalid malformed}")
    assert p.returncode == 1 and r["decision"] == "EVIDENCE_MISSING"


def test_valid_repair_claim_on_docs_only_does_not_skip(nonrepair_fixture):
    claim = {"schema_version": 1, "claim_id": "qa-docs", "problem_id": "bug.fault",
             "producer": {"provider": "simulated", "model": "control", "run_id": "r1"},
             "claim": "The issue is resolved by approved regression checks",
             "source_commit": "b" * 40, "checks": ["safe-regression"]}
    body = "<!-- quorum-ai-repair\n" + json.dumps(claim) + "\n-->"
    p, r = nonrepair_fixture({"docs/overview.md": "docs\n"}, body=body)
    assert p.returncode == 1 and r["decision"] == "EVIDENCE_MISSING"
    assert r["decision"] != "SKIP_NON_REPAIR"


def test_no_tree_difference_not_treated_as_docs_only(nonrepair_fixture):
    p, r = nonrepair_fixture({})
    assert p.returncode == 1 and r["decision"] == "EVIDENCE_MISSING"


def test_removed_regular_documentation_file_is_docs_only(nonrepair_fixture):
    # README exists in both trees and can be deleted without executing code.
    p, r = nonrepair_fixture({"README.md": None})
    assert p.returncode == 0 and r["decision"] == "SKIP_NON_REPAIR"
    assert r["changed_files"] == ["README.md"]


def test_docs_with_non_ascii_path_fails_conservatively(nonrepair_fixture):
    p, r = nonrepair_fixture({"docs/说明.md": "updated\n"})
    assert p.returncode == 1 and r["decision"] == "EVIDENCE_MISSING"


def test_claim_marker_duplicated_does_not_skip(nonrepair_fixture):
    body = "<!-- quorum-ai-repair\n{}\n-->\n<!-- quorum-ai-repair\n{}\n-->"
    p, r = nonrepair_fixture({"README.md": "change\n"}, body=body)
    assert p.returncode == 1 and r["decision"] == "EVIDENCE_MISSING"


# ---------------------------------------------------------------------------
# Trusted test executor v3 (2026-11-09): the pass verdict must rest on the
# supervisor's authenticated event log from a hardened pytest invocation,
# never on output strings and never on a file the test process produced
# (v2's junitxml was forgeable by import-time code). These tests use only
# harmless probes (a standard --collect-only config flag, a marker-writing
# sitecustomize, and a forged XML that is never trusted) — no forged-pass
# plugin is created anywhere.
# ---------------------------------------------------------------------------

def _pytest_registry(tmp_path, check_id="pytest-regression"):
    trusted = tmp_path / "trusted2"
    registry = trusted / "gateway" / "checks.json"
    registry.parent.mkdir(parents=True)
    registry.write_text(json.dumps({"schema_version": 1, "checks": {
        check_id: {"argv": ["python3", "-m", "pytest", "-v", "--noconftest",
                            "tests/test_approved.py::test_kept"],
                   "timeout_seconds": 60, "regression_for": ["bug.fault"],
                   "protected_paths": ["tests/test_approved.py"]}}}))
    return registry


def test_subject_pytest_config_is_ignored(fixture):
    """A PR-controlled pytest config cannot change the check: addopts
    (--collect-only) would make pytest exit 0 without running any test,
    yet the hardened executor ignores the subject config entirely, so the
    approved test actually runs and the supervisor evidence verifies it."""
    subject, registry, event, claim, make_event, fake, sha, tmp = fixture
    (subject / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\naddopts = \"--collect-only\"\n")
    registry.write_text(json.dumps({"schema_version": 1, "checks": {
        "pytest-regression": {"argv": ["python3", "-m", "pytest", "-v", "--noconftest",
                                       "tests/test_approved.py::test_kept"],
                              "timeout_seconds": 60, "regression_for": ["bug.fault"],
                              "protected_paths": ["tests/test_approved.py"]}}}))
    claim["checks"] = ["pytest-regression"]
    make_event(claim)
    p, report, out = audit(fixture)
    assert p.returncode == 0, (p.stdout, p.stderr)
    assert report["decision"] == "PASS_VERIFIED"
    res = report["check_results"][0]
    assert res["evidence_verified"] is True
    assert res["evidence_summary"]["tests"] == 1
    assert res["evidence_summary"]["nodes_verified"] == ["tests.test_approved::test_kept"]
    assert res["evidence_summary"]["session_started"] is True
    assert res["supervisor_evidence_sha256"]
    assert res["supervisor_events"] >= 3
    assert "-c" in res["approved_argv"] and "/dev/null" in res["approved_argv"]
    assert "--junitxml" not in res["approved_argv"]
    assert "-p" in res["approved_argv"] and "quorum_supervisor_plugin" in res["approved_argv"]


def test_subject_startup_hook_is_not_executed(tmp_path):
    """A sitecustomize.py in the subject root must not run during the
    check: the executor launches pytest from a trusted temp dir, so the
    subject root is never on sys.path at interpreter startup."""
    subject = tmp_path / "subject"
    (subject / "tests").mkdir(parents=True)
    (subject / "tests" / "test_approved.py").write_text("def test_kept():\n    assert True\n")
    (subject / "sitecustomize.py").write_text(
        "from pathlib import Path\nPath(\"STARTUP_HOOK_RAN\").write_text(\"ran\\n\")\n")
    registry = _pytest_registry(tmp_path)
    result = tmp_path / "out" / "pytest-regression.json"
    cmd = [sys.executable, str(SCRIPT), "check", "--subject", str(subject),
           "--registry", str(registry), "--check-id", "pytest-regression",
           "--result", str(result)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, (p.stdout, p.stderr)
    res = json.loads(result.read_text())
    assert res["evidence_verified"] is True
    assert res["exit_code"] == 0
    assert not (subject / "STARTUP_HOOK_RAN").exists()
    # Control: the probe is live — a plain interpreter started in the
    # subject with the subject on sys.path DOES execute the hook.
    env = dict(__import__("os").environ)
    env["PYTHONPATH"] = str(subject)
    subprocess.run([sys.executable, "-c", "pass"], cwd=subject, env=env,
                   capture_output=True, timeout=30, check=True)
    assert (subject / "STARTUP_HOOK_RAN").exists()


def test_unapproved_pytest_argument_fails_closed(tmp_path):
    """A registry argv that tries to add a plugin or config override is
    rejected by the executor's allowlist instead of being executed."""
    subject = tmp_path / "subject"
    (subject / "tests").mkdir(parents=True)
    (subject / "tests" / "test_approved.py").write_text("def test_kept():\n    assert True\n")
    registry = tmp_path / "trusted" / "gateway" / "checks.json"
    registry.parent.mkdir(parents=True)
    registry.write_text(json.dumps({"schema_version": 1, "checks": {
        "bad-plugin": {"argv": ["python3", "-m", "pytest", "-p", "some_plugin",
                                "tests/test_approved.py::test_kept"],
                       "timeout_seconds": 60, "regression_for": ["bug.fault"]}}}))
    result = tmp_path / "out" / "bad-plugin.json"
    cmd = [sys.executable, str(SCRIPT), "check", "--subject", str(subject),
           "--registry", str(registry), "--check-id", "bad-plugin",
           "--result", str(result)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert p.returncode != 0
    res = json.loads(result.read_text())
    assert res["evidence_verified"] is False
    assert res["exit_code"] == 127
    assert "Unapproved pytest argument" in res["evidence_error"]


def _sup_events(*evs):
    """Build a supervisor event list: session_start + the given test events.

    For each call event, auto-add a preceding setup (passed) and, for a
    passed call, a following teardown (passed) unless already given for
    that node, so the list is a well-formed session under the v4 strict
    state machine. Tests that need a deliberately malformed sequence
    build their event lists by hand instead."""
    out = [{"type": "session_start"}]
    by_node: dict[str, dict[str, str]] = {}
    order: list[str] = []
    for node, phase, outcome in evs:
        if node not in by_node:
            by_node[node] = {}
            order.append(node)
        by_node[node][phase] = outcome
    for node in order:
        phases = by_node[node]
        if "setup" not in phases and "call" in phases:
            out.append({"type": "test", "node": node, "phase": "setup", "outcome": "passed"})
        for phase in ("setup", "call", "teardown"):
            if phase in phases:
                out.append({"type": "test", "node": node, "phase": phase, "outcome": phases[phase]})
        if phases.get("call") == "passed" and "teardown" not in phases:
            out.append({"type": "test", "node": node, "phase": "teardown", "outcome": "passed"})
    out.append({"type": "session_finish", "exitstatus": 0})
    return out


def test_verify_supervisor_accepts_real_pass(tmp_path):
    events = _sup_events(("tests/test_approved.py::test_kept", "setup", "passed"),
                         ("tests/test_approved.py::test_kept", "call", "passed"),
                         ("tests/test_approved.py::test_kept", "teardown", "passed"))
    ok, summary, error = RG._verify_supervisor_events(events, ["tests/test_approved.py::test_kept"])
    assert ok is True and error == ""
    assert summary["tests"] == 1 and summary["failures"] == 0
    assert summary["session_started"] is True
    assert summary["nodes_verified"] == ["tests.test_approved::test_kept"]


def test_verify_supervisor_rejects_failure_missing_and_malformed(tmp_path):
    failing = _sup_events(("tests/test_approved.py::test_kept", "setup", "passed"),
                          ("tests/test_approved.py::test_kept", "call", "failed"))
    ok, _, error = RG._verify_supervisor_events(failing, ["tests/test_approved.py::test_kept"])
    assert ok is False and "did not pass" in error
    missing = _sup_events(("tests/test_approved.py::test_other", "setup", "passed"),
                          ("tests/test_approved.py::test_other", "call", "passed"))
    ok, _, error = RG._verify_supervisor_events(missing, ["tests/test_approved.py::test_kept"])
    assert ok is False and "no test event" in error
    # No session_start at all (e.g. pytest died before the plugin connected).
    ok, _, error = RG._verify_supervisor_events([], ["tests/test_approved.py::test_kept"])
    assert ok is False and "session_start" in error
    # A test that only ever started (setup) but never ran its call phase.
    # v4: the strict state machine rejects it for the missing
    # session_finish (the session did not end normally), not for the
    # missing call -- either way it is rejected fail-closed.
    started_only = [{"type": "session_start"},
                    {"type": "test", "node": "tests/test_approved.py::test_kept",
                     "phase": "setup", "outcome": "passed"}]
    ok, _, error = RG._verify_supervisor_events(started_only, ["tests/test_approved.py::test_kept"])
    assert ok is False and ("did not pass" in error or "session_finish" in error)
    # Full suite: zero passed (all skipped) is rejected.
    all_skipped = _sup_events(("tests/test_a.py::test_one", "call", "skipped"),
                              ("tests/test_a.py::test_two", "call", "skipped"))
    ok, _, error = RG._verify_supervisor_events(all_skipped, [])
    assert ok is False and "no passed test" in error


def test_verify_supervisor_accepts_full_suite(tmp_path):
    events = _sup_events(("tests/test_a.py::test_one", "call", "passed"),
                         ("tests/test_a.py::test_two", "call", "passed"),
                         ("tests/test_a.py::test_three", "call", "skipped"))
    ok, summary, error = RG._verify_supervisor_events(events, [])
    assert ok is True and error == ""
    assert summary["tests"] == 3 and summary["skipped"] == 1


def test_forged_junitxml_and_early_exit_are_rejected(tmp_path):
    """v3 regression: import-time code that writes a forged junitxml and
    exits 0 (the R1 attack) must NOT produce a pass. The supervisor sees
    no test event for the node, so the check fails closed even though the
    process exited 0 and a well-formed forged XML exists on disk."""
    subject = tmp_path / "subject"
    (subject / "tests").mkdir(parents=True)
    (subject / "tests" / "test_approved.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "xml = '<?xml version=\"1.0\" encoding=\"utf-8\"?>'\n"
        "'<testsuites><testsuite name=\"pytest\" errors=\"0\" failures=\"0\" skipped=\"0\" tests=\"1\">'\n"
        "'<testcase classname=\"tests.test_approved\" name=\"test_kept\" />'\n"
        "'</testsuite></testsuites>'\n"
        "Path(\"/tmp/forged-evidence.xml\").write_text(xml)\n"
        "os._exit(0)\n")
    registry = _pytest_registry(tmp_path)
    result = tmp_path / "out" / "pytest-regression.json"
    cmd = [sys.executable, str(SCRIPT), "check", "--subject", str(subject),
           "--registry", str(registry), "--check-id", "pytest-regression",
           "--result", str(result)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    res = json.loads(result.read_text())
    # v4 (xdist): the import-time os._exit(0) kills the WORKER during
    # collection, so the controller's pytest exits non-zero (internal
    # error) and cmd_check returns 1. Either way the forged XML must
    # NOT produce a pass: no supervised test ran and evidence is false.
    assert p.returncode == 1, (p.stdout, p.stderr)
    assert res["exit_code"] != 0
    assert res["evidence_verified"] is False
    assert res["evidence_summary"]["tests"] == 0




# ---------------------------------------------------------------------------
# v4: strict supervisor state machine + trust-domain split (R7 fix)
# ---------------------------------------------------------------------------

def test_verify_supervisor_rejects_missing_session_finish(tmp_path):
    """v4: a session that never finished normally is rejected, even if the
    test events look like a pass (the audit finding: session_finished was
    recorded but never required)."""
    events = [{"type": "session_start"},
              {"type": "test", "node": "tests/test_a.py::test_one",
               "phase": "setup", "outcome": "passed"},
              {"type": "test", "node": "tests/test_a.py::test_one",
               "phase": "call", "outcome": "passed"},
              {"type": "test", "node": "tests/test_a.py::test_one",
               "phase": "teardown", "outcome": "passed"}]
    ok, _, error = RG._verify_supervisor_events(events, ["tests/test_a.py::test_one"])
    assert ok is False and "session_finish" in error


def test_verify_supervisor_rejects_duplicate_and_out_of_order_events(tmp_path):
    """v4: duplicate (node, phase) pairs and out-of-order phases are
    rejected -- real pytest can never produce them."""
    node = "tests/test_a.py::test_one"
    base = [{"type": "session_start"},
            {"type": "test", "node": node, "phase": "setup", "outcome": "passed"},
            {"type": "test", "node": node, "phase": "call", "outcome": "passed"},
            {"type": "test", "node": node, "phase": "teardown", "outcome": "passed"},
            {"type": "session_finish", "exitstatus": 0}]
    # Duplicate call event.
    dup = base[:-1] + [{"type": "test", "node": node, "phase": "call", "outcome": "passed"}] + base[-1:]
    ok, _, error = RG._verify_supervisor_events(dup, [node])
    assert ok is False and "duplicate" in error
    # Out of order: call before setup.
    ooo = [{"type": "session_start"},
           {"type": "test", "node": node, "phase": "call", "outcome": "passed"},
           {"type": "test", "node": node, "phase": "setup", "outcome": "passed"},
           {"type": "session_finish", "exitstatus": 0}]
    ok, _, error = RG._verify_supervisor_events(ooo, [node])
    assert ok is False and ("out-of-order" in error or "missing setup" in error)
    # Teardown before call.
    ooo2 = [{"type": "session_start"},
            {"type": "test", "node": node, "phase": "setup", "outcome": "passed"},
            {"type": "test", "node": node, "phase": "teardown", "outcome": "passed"},
            {"type": "test", "node": node, "phase": "call", "outcome": "passed"},
            {"type": "session_finish", "exitstatus": 0}]
    ok, _, error = RG._verify_supervisor_events(ooo2, [node])
    assert ok is False and ("out-of-order" in error or "missing call" in error)


def test_verify_supervisor_rejects_events_after_finish_and_bad_exitstatus(tmp_path):
    """v4: no event may follow session_finish; the finish exitstatus must
    be 0 and must match pytest's own exit code."""
    node = "tests/test_a.py::test_one"
    good = [{"type": "session_start"},
            {"type": "test", "node": node, "phase": "setup", "outcome": "passed"},
            {"type": "test", "node": node, "phase": "call", "outcome": "passed"},
            {"type": "test", "node": node, "phase": "teardown", "outcome": "passed"},
            {"type": "session_finish", "exitstatus": 0}]
    # Event after finish.
    late = good + [{"type": "test", "node": node, "phase": "call", "outcome": "passed"}]
    ok, _, error = RG._verify_supervisor_events(late, [node])
    assert ok is False and "after session_finish" in error
    # Non-zero finish exitstatus.
    bad_status = good[:-1] + [{"type": "session_finish", "exitstatus": 1}]
    ok, _, error = RG._verify_supervisor_events(bad_status, [node], exit_code=1)
    assert ok is False and "exitstatus" in error
    # Finish exitstatus disagrees with pytest's exit code.
    mismatch = good[:-1] + [{"type": "session_finish", "exitstatus": 0}]
    ok, _, error = RG._verify_supervisor_events(mismatch, [node], exit_code=1)
    assert ok is False and "does not match" in error
    # Session_start not first.
    not_first = [{"type": "test", "node": node, "phase": "setup", "outcome": "passed"},
                 {"type": "session_start"},
                 {"type": "session_finish", "exitstatus": 0}]
    ok, _, error = RG._verify_supervisor_events(not_first, [node])
    assert ok is False and "session_start" in error


def test_plugin_is_noop_in_xdist_worker(tmp_path):
    """v4 (R7 fix): in an xdist worker the plugin must NOT read the FD or
    hold a token -- it returns from pytest_configure immediately. A worker
    test that imports the plugin finds _TOKEN is None."""
    # Load the plugin from its file path (gateway/ is not on sys.path).
    import importlib.util
    plug_spec = importlib.util.spec_from_file_location(
        "quorum_supervisor_plugin_under_test",
        ROOT / "gateway" / "quorum_supervisor_plugin.py")
    plug = importlib.util.module_from_spec(plug_spec)
    plug_spec.loader.exec_module(plug)
    # Simulate the worker environment: xdist sets PYTEST_XDIST_WORKER.
    os.environ["PYTEST_XDIST_WORKER"] = "gw0"
    os.environ["QUORUM_SUPERVISOR_FD"] = "999"
    try:
        plug._TOKEN = "should-not-be-read"
        plug._SOCK = "should-not-be-set"
        plug.pytest_configure(None)
        # In a worker the plugin must not have touched the FD or the token:
        # it returns early, leaving _TOKEN/_SOCK as they were (the test
        # sets them to sentinels above; a real worker has them None).
        assert plug._IS_WORKER is True
    finally:
        os.environ.pop("PYTEST_XDIST_WORKER", None)
        os.environ.pop("QUORUM_SUPERVISOR_FD", None)
        plug._TOKEN = None
        plug._SOCK = None
        plug._IS_WORKER = False


def test_worker_cannot_read_supervisor_token(tmp_path):
    """v4 end-to-end (R7 fix): a test running in the xdist worker that
    imports the trusted plugin and inspects it finds NO token and NO
    socket -- the token lives only in the controller process. The test
    itself still passes (it is a legitimate passing test), and the
    supervisor evidence verifies it."""
    subject = tmp_path / "subject"
    (subject / "tests").mkdir(parents=True)
    (subject / "tests" / "test_approved.py").write_text(
        "import quorum_supervisor_plugin as plug\n"
        "def test_kept():\n"
        "    assert plug._TOKEN is None, 'token leaked into worker'\n"
        "    assert plug._SOCK is None, 'socket leaked into worker'\n"
        "    assert plug._IS_WORKER is True, 'plugin did not detect worker'\n")
    registry = _pytest_registry(tmp_path)
    result = tmp_path / "out" / "pytest-regression.json"
    cmd = [sys.executable, str(SCRIPT), "check", "--subject", str(subject),
           "--registry", str(registry), "--check-id", "pytest-regression",
           "--result", str(result)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, (p.stdout, p.stderr)
    res = json.loads(result.read_text())
    assert res["exit_code"] == 0, res
    assert res["evidence_verified"] is True, res
    assert res["evidence_summary"]["tests"] == 1
    assert res["evidence_summary"]["session_finished"] is True
    assert res["evidence_summary"]["nodes_verified"] == ["tests.test_approved::test_kept"]


def test_verify_supervisor_rejects_missing_setup_and_missing_teardown(tmp_path):
    """v4 (supplement): a call without a setup, or a passed call without a
    teardown, is rejected -- real pytest always reports setup before call
    and teardown after a completed call."""
    node = "tests/test_a.py::test_one"
    # Call with no setup.
    no_setup = [{"type": "session_start"},
                {"type": "test", "node": node, "phase": "call", "outcome": "passed"},
                {"type": "test", "node": node, "phase": "teardown", "outcome": "passed"},
                {"type": "session_finish", "exitstatus": 0}]
    ok, _, error = RG._verify_supervisor_events(no_setup, [node])
    assert ok is False and "missing setup" in error
    # Teardown with no call.
    no_call = [{"type": "session_start"},
               {"type": "test", "node": node, "phase": "setup", "outcome": "passed"},
               {"type": "test", "node": node, "phase": "teardown", "outcome": "passed"},
               {"type": "session_finish", "exitstatus": 0}]
    ok, _, error = RG._verify_supervisor_events(no_call, [node])
    assert ok is False and "missing call" in error
    # Passed call with no teardown.
    no_teardown = [{"type": "session_start"},
                   {"type": "test", "node": node, "phase": "setup", "outcome": "passed"},
                   {"type": "test", "node": node, "phase": "call", "outcome": "passed"},
                   {"type": "session_finish", "exitstatus": 0}]
    ok, _, error = RG._verify_supervisor_events(no_teardown, [node])
    assert ok is False and "missing teardown" in error
    # A setup-only failure (fixture error, no call, no teardown) is still
    # rejected by the node check (call != passed), not by the phase rules.
    setup_failed = [{"type": "session_start"},
                    {"type": "test", "node": node, "phase": "setup", "outcome": "failed"},
                    {"type": "session_finish", "exitstatus": 1}]
    ok, _, error = RG._verify_supervisor_events(setup_failed, [node], exit_code=1)
    assert ok is False
