#!/usr/bin/env python3
"""Require current official Go release metadata and a installed govulncheck.
No privileged installation, shell download execution or paid services.
"""
import datetime as dt,hashlib,json,re,shutil,subprocess,sys,urllib.error,urllib.request,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
folder=ROOT/'verification/security/online'/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:6])
folder.mkdir(parents=True)
def capture(label,argv):
    result=subprocess.run(argv,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    (folder/(label+'.stdout')).write_bytes(result.stdout)
    (folder/(label+'.stderr')).write_bytes(result.stderr)
    (folder/(label+'.json')).write_text(json.dumps({'command':argv,'exit_code':result.returncode,'stdout_sha256':hashlib.sha256(result.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(result.stderr).hexdigest()},indent=2)+'\n')
    if result.stdout:print(result.stdout.decode(errors='replace'),end='')
    if result.stderr:print(result.stderr.decode(errors='replace'),end='',file=sys.stderr)
    return result
def blocked(message):print('BLOCKED HA-003:',message);sys.exit(77)
try:
    with urllib.request.urlopen('https://go.dev/dl/?mode=json',timeout=15) as response:releases=json.load(response)
except (OSError,ValueError) as e:blocked('cannot verify official current Go release metadata: '+type(e).__name__)
(folder/'official_go_releases.json').write_text(json.dumps(releases,indent=2)+'\n')
local=subprocess.check_output(['go','env','GOVERSION'],text=True).strip()
stable=[r['version'] for r in releases if r.get('stable')]
if local not in stable:blocked(f'installed {local} is not one of the supported current patches returned by go.dev: {stable}')
scanner=shutil.which('govulncheck')
if not scanner:blocked('install a reviewed pinned golang.org/x/vuln/cmd/govulncheck version, record its version, then rerun; do not invent a scan')
print('Official current patch match:',local)
scanner_metadata=capture('scanner-build',['go','version','-m',scanner])
if scanner_metadata.returncode:sys.exit(scanner_metadata.returncode)
if not re.search(r'\bmod\s+golang.org/x/vuln\s+v1\.8\.0\b',scanner_metadata.stdout.decode(errors='replace')):
    raise SystemExit('FAIL: scanner is not the reviewed pinned golang.org/x/vuln v1.8.0 build')
versions=capture('scanner-version',[scanner,'-version'])
if versions.returncode:sys.exit(versions.returncode)
# Verify the reviewed action commits against their official release refs.
references={'actions/checkout':'refs/tags/v6','actions/setup-go':'refs/tags/v6','actions/upload-artifact':'refs/tags/v6','github/codeql-action':'refs/tags/v4^{}'}
workflow=(ROOT/'.github/workflows/ci.yml').read_text()
for repository,reference in references.items():
    pins=set(re.findall(r'uses:\s*'+re.escape(repository)+r'(?:/[\w-]+)?@([0-9a-f]{40})\b',workflow))
    if len(pins)!=1:raise SystemExit('FAIL: missing or inconsistent reviewed action pin for '+repository)
    result=capture('action-'+repository.replace('/','-'),['git','ls-remote','https://github.com/'+repository+'.git',reference])
    if result.returncode:sys.exit(result.returncode)
    revisions=[line.split()[0] for line in result.stdout.decode().splitlines() if line.split()]
    if revisions!=list(pins):raise SystemExit('FAIL: action pin differs from the official reviewed release ref: '+repository)
    print('Official action ref match:',repository,next(iter(pins)))
modules=capture('module-inventory',['go','list','-m','-json','all'])
if modules.returncode:sys.exit(modules.returncode)
decoder=json.JSONDecoder();rest=modules.stdout.decode();inventory=[]
while rest.strip():
    item,offset=decoder.raw_decode(rest.lstrip());inventory.append(item);rest=rest.lstrip()[offset:]
if len(inventory)!=1 or not inventory[0].get('Main'):
    raise SystemExit('FAIL: new third-party modules require explicit license review')
goroot=Path(subprocess.check_output(['go','env','GOROOT'],text=True).strip())
project_license=(ROOT/'LICENSE').read_bytes();go_license=(goroot/'LICENSE').read_bytes()
if b'Permission is hereby granted, free of charge' not in project_license or b'Neither the name of Google LLC' not in go_license:
    raise SystemExit('FAIL: source/compiler license text requires review')
(folder/'license_inventory.json').write_text(json.dumps({'source_license':'MIT','source_license_sha256':hashlib.sha256(project_license).hexdigest(),'go_standard_library_license':'BSD-3-Clause','go_license_sha256':hashlib.sha256(go_license).hexdigest(),'third_party_go_modules':[],'modules':inventory,'scope':'Declared source and actual module/toolchain inventory; future dependencies require review'},indent=2)+'\n')
(folder/'GO_LICENSE.txt').write_bytes(go_license)
result=capture('govulncheck',[scanner,'-json','./...'])
print('Online security evidence:',folder.relative_to(ROOT).as_posix())
sys.exit(result.returncode)
