#!/usr/bin/env python3
"""Check the explicit public file inventory and every reachable Git tree."""
import json,re,subprocess,sys
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN={'AGENTS.md','CODEX_MASTER_PROMPT.md','PROJECT_STATUS.md','project_status.yaml',
           'execution_manifest.yaml','task_graph.yaml','locks.json','model_router.yaml',
           'HUMAN_ACTION_REQUIRED.md','PROJECT_DOSSIER.md','PORTFOLIO_POSITIONING.md'}
FORBIDDEN_DIRS={'.codex','verification','private_research','public'}
PATTERNS=[re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE'+rb' KEY-----'),
          re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})'),
          re.compile(rb'sk-(?:proj-)?[A-Za-z0-9_-]{32,}'),
          re.compile(rb'AKIA[0-9A-Z]{16}'),
          re.compile(rb'[A-Za-z0-9._%+-]+@(?:gmail|hotmail|outlook)\.com')]
def git(*args):
    return subprocess.check_output(['git','--no-replace-objects',*args],cwd=ROOT)
def main():
    expected=json.loads((ROOT/'public-files.json').read_text())['files']
    if len(expected)!=len(set(expected)):raise ValueError('Duplicate inventory path')
    for name in expected:
        path=PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or path.name in FORBIDDEN or set(path.parts)&FORBIDDEN_DIRS:
            raise ValueError('Internal or unsafe inventory path: '+name)
    allowed=set(expected)
    tracked={x.decode() for x in git('ls-files','-z').split(b'\0') if x}
    if tracked!=allowed:raise ValueError('Tracked inventory mismatch: '+str(sorted(tracked^allowed)))
    unknown=git('ls-files','--others','--exclude-standard','-z')
    if unknown:raise ValueError('Unreviewed untracked files are present')
    commits=git('rev-list','--all').splitlines()
    if not commits:raise ValueError('No committed public source')
    blobs=set();entries=0
    for commit in commits:
        for row in git('ls-tree','-rz',commit.decode()).split(b'\0'):
            if not row:continue
            meta,raw_name=row.split(b'\t',1);mode,kind,sha=meta.split();name=raw_name.decode()
            if name not in allowed:raise ValueError('Non-public historical path: '+name)
            if mode not in (b'100644',b'100755') or kind!=b'blob':raise ValueError('Nonregular public entry: '+name)
            blobs.add(sha.decode());entries+=1
    for name in allowed:
        path=ROOT/name
        if path.is_symlink() or not path.is_file():raise ValueError('Missing or nonregular file: '+name)
        data=path.read_bytes()
        if len(data)>1<<20 or any(pattern.search(data) for pattern in PATTERNS):raise ValueError('Content requires review: '+name)
    for sha in blobs:
        data=git('cat-file','blob',sha)
        if len(data)>1<<20 or any(pattern.search(data) for pattern in PATTERNS):raise ValueError('Historical content requires review')
    print(json.dumps({'status':'PASS','public_files':len(allowed),'commits':len(commits),
                      'history_entries':entries,'history_blobs':len(blobs),
                      'scope':'Explicit inventory, regular files, reachable history and heuristic credential/contact scan'}))
    return 0
if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,KeyError,subprocess.CalledProcessError) as exc:
        print('FAIL:',str(exc),file=sys.stderr);sys.exit(1)
