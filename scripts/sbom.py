#!/usr/bin/env python3
"""Record the actual binary, compiler and standard-library dependency inventory."""
import datetime as dt,hashlib,json,subprocess,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
binary=ROOT/'bin/relayfence'
if not binary.exists():raise SystemExit('Run make build first')
version=subprocess.check_output(['go','env','GOVERSION'],text=True).strip()
raw=subprocess.check_output(['go','version','-m',str(binary)],text=True)
packages=subprocess.check_output(['go','list','-deps','-f','{{if .Standard}}{{.ImportPath}}{{end}}','./cmd/relayfence'],cwd=ROOT,text=True).splitlines()
report={'schema':'RelayFence binary inventory v1','generated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'go_version':version,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'build_metadata':raw,'standard_library_packages':sorted(x for x in packages if x),'third_party_go_modules':[],'source_license':'MIT','go_standard_library_license':'BSD-3-Clause','scope':'Inventory of this build; not an independently attested SBOM or vulnerability scan'}
out=ROOT/'verification/artifacts';out.mkdir(parents=True,exist_ok=True)
(out/'binary_inventory.json').write_text(json.dumps(report,indent=2)+'\n')
gOROOT=Path(subprocess.check_output(['go','env','GOROOT'],text=True).strip())
(out/'GO_LICENSE.txt').write_text((gOROOT/'LICENSE').read_text())
print(json.dumps({'binary_sha256':report['binary_sha256'],'go_version':version,'stdlib_packages':len(report['standard_library_packages'])}))
