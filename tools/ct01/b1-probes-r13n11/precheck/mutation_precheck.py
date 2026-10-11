#!/usr/bin/env python3
"""Offline targeted mutations. Count only named behavioral target failing without target exception, with complete JSON.
No guest/harness suites. Copies precheck sources into temporary trees. INVALID/ERROR controls aren't logical catches.
"""
import argparse,hashlib,json,pathlib,shutil,subprocess,sys,tempfile
HERE=pathlib.Path(__file__).resolve().parent
M=[
 ('M01','evaluate_precheck.py',"verdict='UNUSABLE' if issues else", "verdict='PASS' if issues else",'F1-missing-docker-info'),
 ('M02','evaluate_precheck.py',"if name in reads:bad('duplicate read name: '+name);continue", "if name in reads:continue",'F1-duplicate'),
 ('M03','evaluate_precheck.py',"if type(rc) is not int or rc not in C.accepted_rcs(name) or error is not None:rb('OK contradicts rc/error')", "if False:rb('OK contradicts rc/error')",'F1-rc-status'),
 ('M04','evaluate_precheck.py',"elif r.get('status')=='SKIPPED' or r.get('argv')!=concrete[n]:bad(n+': argv/branch contradicts collector command')", "elif r.get('status')=='SKIPPED':bad(n+': argv/branch contradicts collector command')",'F1-argv'),
 ('M05','evaluate_precheck.py',"if p and (p['id']!=ident or p['name']!=name):bad(ins+': inspect identity differs from resolved list')", "if False:bad(ins+': inspect identity differs from resolved list')",'F1-network-identity'),
 ('M06','evaluate_precheck.py',"elif ch!=(expected_hash or digest_file(C.__file__)):bad('collector hash does not match pinned contract source')", "elif False:bad('collector hash does not match pinned contract source')",'F1-source-hash'),
 ('M07','collector.py',"if k in d:\n                raise ValueError('duplicate JSON key: ' + k)", "if False:\n                raise ValueError('duplicate JSON key: ' + k)",'F1-duplicate-json-key'),
 ('M08','evaluate_precheck.py',"os.unlink(dst) # no stale PASS", "pass # no stale PASS",'F3-write-failure-removes-stale'),
 ('M09','evaluate_precheck.py',"if now-meta['t_start']>context['max_age_s']:return 'snapshot exceeds coordinator-approved age window'", "if False:return 'snapshot exceeds coordinator-approved age window'",'F4-current-stale'),
 ('M10','evaluate_precheck.py',"if not input_sha256 or context.get('reads_sha256')!=input_sha256:return 'context reads.json digest mismatch/missing'", "if False:return 'context reads.json digest mismatch/missing'",'F4-context-sha'),
 ('M11','export_precheck.py',"if res['producer_rc']!=0:raise ValueError('producer failed; evaluator not called')", "if False:raise ValueError('producer failed; evaluator not called')",'F4-export-producer-error'),
 ('M12','export_precheck.py',"if res['extractor_rc']!=0:raise ValueError('extractor failed; evaluator not called')", "if False:raise ValueError('extractor failed; evaluator not called')",'F4-export-extractor-error'),
 ('M13','RUN-PROCEDURE.md', 'if ! echo "$HASH  $T/collector.py" | /usr/bin/sha256sum -c --quiet - ; then', 'if false; then','PC4-copy-hash-bad'),
 ('M14','evaluate_precheck.py',"if problems:evaluated['issues']+=problems;evaluated['verdict']='UNUSABLE';evaluated['current_ready']=False", "if False:evaluated['issues']+=problems;evaluated['verdict']='UNUSABLE';evaluated['current_ready']=False",'F1-raw-file-mismatch'),
 ('M15','collector.py',"try:ipam,ctrs = strict_json(ipam_s),strict_json(ctrs_s)","try:ipam,ctrs = strict_json(ipam_s),strict_json(ctrs_s) or {}",'F2-network-null-sandbox'),
 ('M16','collector.py',"rs = rows(text, 4, 'ps', allow_empty=True); names=set(); ids=set()","rs = [l.split('\\t')[:4] for l in text.splitlines() if l.strip()]; names=set(); ids=set()",'F2-ps-extra-column'),
 ('M17','collector.py',"nets=strict_json(nets_s)","nets=strict_json(nets_s) or {}",'F2-manager-null-networks'),
 ('X1','collector.py','TEXT NOT IN SOURCE','x',None),
 ('X2','selftest_precheck.py','import argparse,','import argparse(,',None),
]
def suite(d):
 jf=d/'test-results.json'
 try:p=subprocess.run([sys.executable,'-I','-B',str(d/'selftest_precheck.py'),'--json',str(jf)],capture_output=True,text=True,timeout=90)
 except subprocess.TimeoutExpired:return None,{'error':'TIMEOUT'}
 detail={'rc':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
 if not jf.exists() or 'SELFTEST-PRECHECK:' not in p.stdout:return None,detail
 try:r=json.loads(jf.read_text())
 except Exception:return None,detail
 return r,detail

def main(argv):
 ap=argparse.ArgumentParser();ap.add_argument('--json');ap.add_argument('--logs');ap.add_argument('--only');a=ap.parse_args(argv)
 files=[p for p in HERE.iterdir() if p.is_file()];initial={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in files};results={}
 with tempfile.TemporaryDirectory(prefix='ir3r-mutation.') as root:
  def cp(label):
   d=pathlib.Path(root)/label;d.mkdir()
   for p in files:shutil.copyfile(p,d/p.name)
   shutil.copytree(HERE/'references',d/'references')
   return d
  base,detail=suite(cp('baseline'))
  if base is None or not all(base['tests'].values()):print('BASELINE FAILED');return 2
  print('baseline',len(base['tests']))
  for mid,file,old,new,target in M:
   if a.only and mid not in a.only.split(','):continue
   d=cp(mid);s=(d/file).read_text();r=None;detail={}
   if s.count(old)!=1:klass='INVALID'
   else:
    (d/file).write_text(s.replace(old,new));r,detail=suite(d)
    if r is None or set(r['tests'])!=set(base['tests']):klass='ERROR'
    elif target is None:klass='MISSED'
    elif r['details'].get(target,'').startswith('EXCEPTION'):klass='TARGET-EXCEPTION'
    elif r['tests'].get(target) is False:klass='DETECTED'
    elif not all(r['tests'].values()):klass='DETECTED-ELSEWHERE'
    else:klass='MISSED'
   expected={'X1':'INVALID','X2':'ERROR'}.get(mid,'DETECTED');ok=klass==expected
   results[mid]={'classification':klass,'target':target,'expected':expected,'ok':ok,'failed':[] if r is None else [k for k,v in r['tests'].items() if not v],
                 'target_detail':None if r is None or target is None else r['details'].get(target)}
   print(('OK ' if ok else 'BAD ')+mid+' '+klass+' target='+str(target))
   if a.logs:
    out=pathlib.Path(a.logs);out.mkdir(parents=True,exist_ok=True);(out/(mid+'.log')).write_text(detail.get('stdout','')+'\nSTDERR\n'+detail.get('stderr',''))
    if r:(out/(mid+'.json')).write_text(json.dumps(r,indent=2))
 final={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in files};same=initial==final
 result={'baseline_tests':len(base['tests']),'mutants':results,'sources_unchanged':same,'note':'X controls excluded from logical catch total; no crash/timeout/elsewhere counted as target catch'}
 if a.json:pathlib.Path(a.json).write_text(json.dumps(result,indent=2))
 return 0 if same and all(v['ok'] for v in results.values()) else 1
if __name__=='__main__':sys.exit(main(sys.argv[1:]))
