#!/usr/bin/env python3
"""Run real synthetic socket experiments and retain every sample/repetition."""
import argparse,datetime as dt,json,math,shutil,statistics,subprocess,sys,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--smoke',action='store_true');args=p.parse_args()
run=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:6]
work=ROOT/'.state'/('bench-'+run);out=ROOT/'verification/benchmarks'/run;out.mkdir(parents=True)
command=['go','run','./cmd/relaybench','--out',str(work),'--operations','16' if args.smoke else '100','--repeats','1' if args.smoke else '5']
print('Command:',json.dumps(command),flush=True)
result=subprocess.run(command,cwd=ROOT)
if (work/'results.json').exists():shutil.copy2(work/'results.json',out/'results.json')
if (work/'audit.jsonl').exists():shutil.copy2(work/'audit.jsonl',out/'audit.jsonl')
if result.returncode:sys.exit(result.returncode)
data=json.loads((out/'results.json').read_text());rows=[]
if data.get('schema_version')!=4:raise SystemExit('Expected prepared-TLS and bounded-release observation schema4')
repetitions=1 if args.smoke else 5;operations=16 if args.smoke else 100
def check_grid(key,levels):
    groups=data[key]
    wanted={(mode,level,repeat) for mode in ['direct_mtls','proxy_mtls'] for level in levels for repeat in range(1,repetitions+1)}
    actual={(g['mode'],g['concurrency'],g['repetition']) for g in groups}
    if actual!=wanted or len(groups)!=len(wanted) or any(len(g['samples'])!=operations or g['successful']!=operations or g['failures']!=0 or any(s.get('error') for s in g['samples']) or {s['index'] for s in g['samples']}!=set(range(operations)) for g in groups):
        raise SystemExit('Incomplete, duplicated or failed '+key+' observations retained')
check_grid('groups',[1,4,8,16,64]);check_grid('setup_groups',[1,8])
if data['status']!='PASS' or data['warmup_attempted']!=20*repetitions or data['revocation_attempted']!=100 or len(data['revocation_ns'])!=100 or any(a.get('error') or a.get('latency_ns') is None for a in data['warmup_attempts']+data['revocation_attempts']):
    raise SystemExit('Incomplete or failed warmup/revocation observations retained')
stalls=data['stall_groups']
if len(stalls)!=4*repetitions or {(g['concurrency'],g['repetition']) for g in stalls}!={(level,repeat) for level in [1,4,16,64] for repeat in range(1,repetitions+1)} or any(g['failures'] or g['final_active'] or not 1<=g['peak_observed_active']<=4 or g['observation_window_ns']<500_000_000 or g['admitted']+g['denied']!=g['concurrency'] or len(g['attempts'])!=g['concurrency'] or any(a.get('error') for a in g['attempts']) for g in stalls):
    raise SystemExit('Incomplete or failed fixed-window stall observations retained')
for group in stalls:
    last_admitted=max(a.get('connect_observed_ns',0) for a in group['attempts'] if a['connect_status']==200)
    released=group.get('release_observed_ns',0)
    samples=group.get('active_samples',[])
    if group.get('preparation_ns',0)<=0 or any(a.get('tls_setup_ns',0)<=0 or a.get('connect_observed_ns',0)<=0 for a in group['attempts']) or not last_admitted<=released<=last_admitted+700_000_000 or not any(s['active']==0 and s['elapsed_ns']==released for s in samples) or any(not 0<=s['active']<=4 for s in samples):
        raise SystemExit('Missing preparation or timely server-release observation retained')
for mode in ['direct_mtls','proxy_mtls']:
    for conc in [1,4,8,16,64]:
        groups=[g for g in data['groups'] if g['mode']==mode and g['concurrency']==conc]
        if not groups or any(g['failures'] for g in groups):raise SystemExit('Missing groups or failed observations')
        med=lambda key:statistics.median(g[key] for g in groups)
        p95=f"{med('p95_ns')/1e6:.3f}" if operations>=100 else 'insufficient n'
        p99=f"{med('p99_ns')/1e6:.3f}" if operations>=100 else 'insufficient n'
        spread=f"{min(g['p95_ns'] for g in groups)/1e6:.3f}-{max(g['p95_ns'] for g in groups)/1e6:.3f}" if operations>=100 else 'insufficient n'
        rows.append(f"| {mode} | {conc} | {len(groups)} | {med('p50_ns')/1e6:.3f} | {p95} | {p99} | {statistics.median(g['successful']/(g['wall_ns']/1e9) for g in groups):.1f} | {spread} |")
revoke=sorted(data['revocation_ns']);q=lambda fraction:revoke[max(0,math.ceil(fraction*len(revoke))-1)]/1e6
text='# Measured synthetic benchmark\n\nNot production capacity. All clients/servers share one process. Raw observations: results.json. Quantiles below are median per-repetition quantiles, not pooled tail estimates.\n\n| Mode | Concurrency | Repeats | p50 ms | p95 ms | p99 ms | Successful ops/s | p95 range ms |\n|---|---:|---:|---:|---:|---:|---:|---:|\n'+'\n'.join(rows)+f'\n\nRevocation: n={len(revoke)}, p50={q(.5):.3f}ms, p95={q(.95):.3f}ms, p99={q(.99):.3f}ms, max={max(revoke)/1e6:.3f}ms. This is observed under the recorded synthetic environment, not a hard real-time guarantee.\n\n'+'\n\n'.join(data['notes'])+'\n'
(out/'summary.md').write_text(text)
setup_rows=[]
for mode in ['direct_mtls','proxy_mtls']:
    for conc in [1,8]:
        groups=[g for g in data['setup_groups'] if g['mode']==mode and g['concurrency']==conc]
        p95=f"{statistics.median(g['p95_ns'] for g in groups)/1e6:.3f}" if operations>=100 else 'insufficient n'
        spread=f"{min(g['p95_ns'] for g in groups)/1e6:.3f}-{max(g['p95_ns'] for g in groups)/1e6:.3f}" if operations>=100 else 'insufficient n'
        setup_rows.append(f"| {mode} | {conc} | {len(groups)} | {statistics.median(g['p50_ns'] for g in groups)/1e6:.3f} | {p95} | {spread} |")
stall_rows=[]
for conc in [1,4,16,64]:
    groups=[g for g in stalls if g['concurrency']==conc]
    stall_rows.append(f"| {conc} | {len(groups)} | {max(g['peak_observed_active'] for g in groups)} | {sum(g['admitted'] for g in groups)} | {sum(g['denied'] for g in groups)} | {sum(g['failures'] for g in groups)} |")
text=text.replace('| Mode | Concurrency | Repeats | p50 ms | p95 ms | p99 ms | Successful ops/s | p95 range ms |','## Full 1KiB exchange, including half-close/EOF\n\n| Mode | Concurrency | Repeats | p50 ms | p95 ms | p99 ms | Successful ops/s | p95 range ms |',1)
text+='\n## mTLS handshake / CONNECT setup\n\n| Mode | Concurrency | Repeats | p50 ms | p95 ms | p95 range ms |\n|---|---:|---:|---:|---:|---:|\n'+'\n'.join(setup_rows)+'\n\n## Fixed500ms idle-stall observation windows\n\nSingle identity ceiling4, global ceiling8; peak is sampled. No payload is sent by these clients. Every group ends with active0.\n\n| Concurrency | Repeats | Peak observed active | Admitted | Capacity denied | Failures |\n|---|---:|---:|---:|---:|---:|\n'+'\n'.join(stall_rows)+'\n'
if args.smoke:text+='\nSmoke run:16samples/group and1repetition. Tail estimates require at least100samples; their raw nearest-rank statistics are retained only as diagnostic observations.\n'
(out/'summary.md').write_text(text)
print(text);print('Evidence:',out.relative_to(ROOT))
