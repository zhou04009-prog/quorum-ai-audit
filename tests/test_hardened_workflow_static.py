"""Candidate workflow's static security assertions (not a GitHub execution test)."""
from pathlib import Path
import re
import yaml

SOURCE=Path(__file__).resolve().parents[1]/'.github/workflows/ai-repair-gate.yml'
s=SOURCE.read_text()
y=yaml.load(s,Loader=yaml.BaseLoader)
steps=y['jobs']['independently-verify-ai-repairs']['steps']

def test_only_base_workflow_runs():
    assert 'pull_request_target' in y['on']
    assert 'pull_request' not in y['on']
    assert y['on']['pull_request_target']['branches']==['main']

def test_read_only_git_permissions():
    assert y['permissions']=={'contents':'read'}
    assert not re.search(r'\bsecrets\.',s)
    assert not re.search(r'\bpull_request_target:\s*\n\s*types:\s*\[?closed',s)

def test_all_external_actions_sha_pinned():
    refs=re.findall(r'\buses:\s*([^\s#]+)',s)
    assert len(refs)==4
    for a in refs:
        assert re.fullmatch(r'actions/[\w-]+@[0-9a-f]{40}',a),a

def test_untrusted_checkout_cannot_run_on_host():
    checkouts=[step for step in steps if 'actions/checkout@' in step.get('uses','')]
    assert len(checkouts)==3
    assert all(k['with']['persist-credentials']=='false' for k in checkouts)
    assert all(k['with'].get('path') in {'verifier','subject','base'} for k in checkouts)
    commands='\n'.join(str(step.get('run','')) for step in steps)
    assert 'pip install -e ./subject' not in commands
    assert 'docker build' in commands and '"$GITHUB_WORKSPACE/verifier"' in commands

def test_sandbox_is_offline_and_credentials_not_forwarded():
    run=next(step['run'] for step in steps if step['name'].startswith('Independent audit'))
    for required in ['--network none','--read-only','--cap-drop ALL','--security-opt no-new-privileges',
                     '--memory 2g','--memory-swap=2g','--pids-limit 256','exec,size=256m',
                     'dst=/subject,readonly','dst=/base,readonly','--env HOME=/tmp',
                     '--base /base','--registry /trusted/gateway/checks.json']:
        assert required in run,required
    assert '--env GITHUB_TOKEN' not in run
    assert '--env GH_TOKEN' not in run

def test_trusted_verifier_pinned():
    first=steps[0]
    assert first['with']['ref']=='b700f5f00222867379146398062edf15d58ad538'
    assert first['with']['path']=='verifier'

def test_artifact_preserved_on_fail():
    last=steps[-1]
    assert last['if']=='always()'
    assert last['with']['if-no-files-found']=='error'
