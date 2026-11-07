import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"gateway"/"repair_gateway.py"


def git(repo,*args):
    p=subprocess.run(["git","-C",str(repo),*args],text=True,capture_output=True,check=True)
    return p.stdout.strip()


@pytest.fixture
def fixture(tmp_path):
    subject=tmp_path/"subject";subject.mkdir()
    git(subject,"init","-q")
    git(subject,"config","user.name","Fixture")
    git(subject,"config","user.email","fixture@example.invalid")
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
