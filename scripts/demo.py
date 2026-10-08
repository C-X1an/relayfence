#!/usr/bin/env python3
import argparse,datetime as dt,json,shutil,subprocess,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--latest',action='store_true');args=p.parse_args()
if args.latest:
    paths=sorted((ROOT/'verification/demo').glob('*/inspection.html'))
    if not paths:raise SystemExit('Run make demo first')
    print(paths[-1]);raise SystemExit(0)
run=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:6]
out=ROOT/'.state'/('demo-'+run)
subprocess.run([str(ROOT/'bin/relayfence'),'demo','--out',str(out)],check=True)
public=ROOT/'verification/demo'/run;public.mkdir(parents=True)
for name in ['report.json','audit.jsonl','inspection.html']:shutil.copy2(out/name,public/name)
print((public/'report.json').read_text());print('Inspection:',public/'inspection.html')
