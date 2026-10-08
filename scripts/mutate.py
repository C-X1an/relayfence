#!/usr/bin/env python3
"""Run baseline -> targeted defect -> restoration in disposable copies.
A compiler failure is NOT a killed mutant. Require the named Go test to fail.
"""
import datetime as dt,hashlib,json,shutil,subprocess,sys,tempfile,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(data):return hashlib.sha256(data).hexdigest()
def capture(folder,name,command,cwd):
    start=dt.datetime.now(dt.timezone.utc).isoformat();tick=time.monotonic()
    try:
        p=subprocess.run(command,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        code,out,err=p.returncode,p.stdout,p.stderr
    except subprocess.TimeoutExpired as e:code,out,err=124,e.stdout or b'',e.stderr or b''
    (folder/(name+'.stdout')).write_bytes(out);(folder/(name+'.stderr')).write_bytes(err)
    record={'command':command,'cwd':str(cwd),'start':start,'end':dt.datetime.now(dt.timezone.utc).isoformat(),'duration_seconds':time.monotonic()-tick,'exit_code':code,'stdout_sha256':sha(out),'stderr_sha256':sha(err)}
    (folder/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n');return code,out
MUTATIONS=[
 ('M-IP','internal/relayfence/address.go','if !allowed {','if !allowed && false {','TestMixedDNS'),
 ('M-AUTH','internal/relayfence/store.go','if !allowed {','if !allowed && false {','TestAuthorizeBeforeDNS'),
 ('M-REV','internal/relayfence/store.go','session.Revision != s.policy.Revision','false','TestRevisionFence'),
 ('M-BUDGET','internal/relayfence/budget.go','if n > old {','if n > old && false {','TestBudgetConcurrent'),
 ('M-HALFCLOSE','internal/relayfence/gateway.go','reader := bufio.NewReader(io.MultiReader(io.LimitReader(buffer.Reader, int64(buffer.Reader.Buffered())), client))','reader := buffer.Reader','TestHalfClose'),
 ('M-UNICODE','internal/relayfence/address.go','if raw[i] >= 0x80 {','if raw[i] >= 0x80 && false {','TestAuthorityRejectsUnicode'),
 ('M-POLICYFILE','internal/relayfence/store.go','bytes, err := json.Marshal(validated)','bytes, err := json.MarshalIndent(validated, "", "  ")','TestPolicyPersistenceSizeBound'),
 ('M-POLICYSIZE','internal/relayfence/policy.go','if err != nil || len(encoded)+1 > MaxPolicyBytes {','if err != nil || (len(encoded)+1 > MaxPolicyBytes && false) {','TestOversizedPolicyRejectedBeforePersistence'),
 ('M-BENCHFAIL','internal/relayfence/benchmark.go','data, writeErr := json.MarshalIndent(report, "", "  ")','if report.Status == "FAIL" { return }; data, writeErr := json.MarshalIndent(report, "", "  ")','TestReviewBenchmarkRevocationFailureRetained'),
 ('M-STALLTIME','internal/relayfence/benchmark_stalls.go','limited.Rules[0].IdleTimeoutMS = 200','limited.Rules[0].IdleTimeoutMS = 800','TestReviewBenchmarkSuccessReport'),
 ('M-TLSCLOSE','internal/relayfence/store.go','if secured, ok := c.(*tls.Conn); ok {','if secured, ok := c.(*tls.Conn); ok && false {','TestGatewayTLSCloseBlockedApplicationWrite'),
]
def main():
    out=ROOT/'verification/mutation'/ (dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:6]);out.mkdir(parents=True)
    records=[]
    for ident,file,original,broken,test in MUTATIONS:
        folder=out/ident;folder.mkdir()
        with tempfile.TemporaryDirectory(prefix='relayfence-mutant-') as tmp:
            copy=Path(tmp)/'repo';shutil.copytree(ROOT,copy,ignore=shutil.ignore_patterns('.git','verification','.state','.tools','bin','__pycache__'))
            target=copy/file;original_bytes=target.read_bytes();data=original_bytes.decode('utf-8')
            if data.count(original)!=1:raise RuntimeError(f'{ident}: mutation anchor not unique')
            command=['go','test','-json','-count=1','-timeout=10s','-run','^'+test+'$','./internal/relayfence']
            before,_=capture(folder,'baseline',command,copy)
            altered=data.replace(original,broken,1);target.write_bytes(altered.encode('utf-8'))
            mutant,output=capture(folder,'mutant',command,copy)
            target.write_bytes(original_bytes)
            restored,_=capture(folder,'restored',command,copy)
            named_failure=False
            for line in output.decode(errors='replace').splitlines():
                try:row=json.loads(line)
                except json.JSONDecodeError:continue
                if row.get('Action')=='fail' and row.get('Test')==test:named_failure=True
            record={'id':ident,'file':file,'test':test,'original_sha256':sha(original_bytes),'mutant_sha256':sha(altered.encode('utf-8')),'restored_sha256':sha(target.read_bytes()),'baseline_exit':before,'mutant_exit':mutant,'restored_exit':restored,'named_test_failed':named_failure}
            record['status']='PASS' if before==restored==0 and mutant!=0 and named_failure and record['original_sha256']==record['restored_sha256'] else 'FAIL'
            records.append(record);print(ident,record['status'],flush=True)
    (out/'summary.json').write_text(json.dumps({'scope':f'{len(MUTATIONS)} selected critical mutations; not a comprehensive mutation score','mutations':records},indent=2)+'\n')
    return 0 if all(r['status']=='PASS' for r in records) else 1
if __name__=='__main__':sys.exit(main())
