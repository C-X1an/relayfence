#!/usr/bin/env python3
"""Record actual command output under ignored verification/, never in source."""
import argparse,datetime as dt,hashlib,json,os,platform,signal,subprocess,sys,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--category',required=True)
    parser.add_argument('--timeout',type=float,default=180)
    parser.add_argument('command',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    command=args.command[1:] if args.command[:1]==['--'] else args.command
    if not command:parser.error('A real command is required')
    ident=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')+'-'+uuid.uuid4().hex[:8]
    raw=ROOT/'verification/raw';runs=ROOT/'verification/runs'
    raw.mkdir(parents=True,exist_ok=True);runs.mkdir(parents=True,exist_ok=True)
    stdout=raw/(ident+'.stdout');stderr=raw/(ident+'.stderr')
    start=dt.datetime.now(dt.timezone.utc).isoformat();tick=time.monotonic();timed_out=False
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    with stdout.open('wb') as out,stderr.open('wb') as err:
        try:
            process=subprocess.Popen(command,cwd=ROOT,stdout=out,stderr=err,start_new_session=True)
            try:code=process.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                timed_out=True
                if os.name=='nt':
                    cleanup=subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True)
                    if cleanup.returncode and process.poll() is None:
                        err.write(b'Process-tree cleanup failed:\n'+cleanup.stdout);process.kill()
                else:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                process.wait();code=124
        except OSError as exc:err.write((str(exc)+'\n').encode());code=127
    record={'schema_version':1,'run_id':ident,'git_commit':head,'category':args.category,
            'command':command,'cwd':str(ROOT),'platform':platform.platform(),
            'start':start,'end':dt.datetime.now(dt.timezone.utc).isoformat(),
            'duration_seconds':time.monotonic()-tick,'exit_code':code,'timed_out':timed_out,
            'status':'PASS' if code==0 else ('BLOCKED' if code==77 else 'FAIL')}
    for kind,path in [('stdout',stdout),('stderr',stderr)]:
        record[kind]=path.relative_to(ROOT).as_posix()
        record[kind+'_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    (runs/(ident+'.json')).write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(record),flush=True)
    print(stdout.read_text(errors='replace'),end='')
    print(stderr.read_text(errors='replace'),end='',file=sys.stderr)
    return code
if __name__=='__main__':sys.exit(main())
