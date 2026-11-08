import importlib.util
import json
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
# Trusted test executor v2 (2026-11-08): the pass verdict must rest on
# structured junitxml evidence from a hardened pytest invocation, never on
# output strings. These tests use only harmless probes (a standard
# --collect-only config flag, a marker-writing sitecustomize, and direct
# XML parsing) — no forged-pass plugin is created anywhere.
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
    approved test actually runs and the junitxml evidence verifies it."""
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
    assert res["junitxml_file"].endswith(".xml")
    assert "-c" in res["approved_argv"] and "/dev/null" in res["approved_argv"]
    assert "--junitxml" in res["approved_argv"]


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


def _junitxml(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return path


def test_verify_junitxml_accepts_real_pass(tmp_path):
    xml = _junitxml(tmp_path, "ok.xml", """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="0" failures="0" skipped="0" tests="1" time="0.1">
<testcase classname="tests.test_approved" name="test_kept" time="0.01" />
</testsuite></testsuites>""")
    ok, summary, error = RG._verify_junitxml(xml, ["tests/test_approved.py::test_kept"])
    assert ok is True and error == ""
    assert summary["tests"] == 1 and summary["failures"] == 0
    assert summary["nodes_verified"] == ["tests.test_approved::test_kept"]


def test_verify_junitxml_rejects_failure_missing_and_malformed(tmp_path):
    failing = _junitxml(tmp_path, "fail.xml", """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="0" failures="1" skipped="0" tests="1" time="0.1">
<testcase classname="tests.test_approved" name="test_kept" time="0.01"><failure message="assert">x</failure></testcase>
</testsuite></testsuites>""")
    ok, _, error = RG._verify_junitxml(failing, ["tests/test_approved.py::test_kept"])
    assert ok is False and "failures" in error
    missing = _junitxml(tmp_path, "missing.xml", """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="0" failures="0" skipped="0" tests="1" time="0.1">
<testcase classname="tests.test_approved" name="test_other" time="0.01" />
</testsuite></testsuites>""")
    ok, _, error = RG._verify_junitxml(missing, ["tests/test_approved.py::test_kept"])
    assert ok is False and "no testcase" in error
    empty = _junitxml(tmp_path, "empty.xml", """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="0" failures="0" skipped="0" tests="0" time="0.0">
</testsuite></testsuites>""")
    ok, _, error = RG._verify_junitxml(empty, [])
    assert ok is False and "no tests ran" in error
    bad = _junitxml(tmp_path, "bad.xml", "not xml at all")
    ok, _, error = RG._verify_junitxml(bad, ["tests/test_approved.py::test_kept"])
    assert ok is False and "unparsable" in error
    ok, _, error = RG._verify_junitxml(tmp_path / "does-not-exist.xml",
                                        ["tests/test_approved.py::test_kept"])
    assert ok is False and "missing" in error


def test_verify_junitxml_accepts_full_suite(tmp_path):
    xml = _junitxml(tmp_path, "suite.xml", """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="0" failures="0" skipped="1" tests="3" time="0.2">
<testcase classname="tests.test_a" name="test_one" time="0.01" />
<testcase classname="tests.test_a" name="test_two" time="0.01" />
<testcase classname="tests.test_a" name="test_three" time="0.01"><skipped /></testcase>
</testsuite></testsuites>""")
    ok, summary, error = RG._verify_junitxml(xml, [])
    assert ok is True and error == ""
    assert summary["tests"] == 3 and summary["skipped"] == 1
