#!/usr/bin/env python3
"""F1-F4 offline behavioral regression tests. Only fake runners and user-owned toy archives. No root or probes."""
import argparse,copy,hashlib,importlib.util,json,os,pathlib,shutil,subprocess,sys,tarfile,tempfile,time,traceback
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import collector as C,evaluate_precheck as E,export_precheck as X,fixtures_precheck as F
RESULTS={};DETAILS={}
def t(name,fn):
 try:
  value=fn();ok=value is True;detail='' if ok else repr(value)
 except Exception as e:ok=False;detail='EXCEPTION '+type(e).__name__+': '+str(e)
 RESULTS[name]=ok;DETAILS[name]=detail;print(('PASS ' if ok else 'FAIL ')+name+(' '+detail if detail else ''))
def raises(fn):
 try:fn()
 except Exception:return True
 return False
def collect(tmp,name,spec=None):
 p=pathlib.Path(tmp)/name;p.mkdir(mode=0o700);fd=C.prepare_outdir(str(p),os.geteuid());r=F.fake_runner(spec)
 try:rc=C.collect(fd,r)
 finally:os.close(fd)
 return p,C.strict_json((p/'reads.json').read_text()),rc,r.calls
def ev(d,**kw):return E.evaluate(d,F.REF,**kw)
def mutate(d,fn):
 x=copy.deepcopy(d);fn(x);before=copy.deepcopy(x);r=ev(x);return r,x==before
def read(d,n):return next(r for r in d['reads'] if r['name']==n)
def sync_files(p,d):
 for r in d['reads']:
  if isinstance(r,dict):
   for f in ('stdout','stderr'):
    if isinstance(r.get(f),str) and isinstance(r.get(f+'_file'),str) and '/' not in r[f+'_file']:(p/r[f+'_file']).write_text(r[f])
 (p/'reads.json').write_text(json.dumps(d,indent=1))
def cli(p,dst,ref,*extra):
 q=subprocess.run([sys.executable,'-I','-B',str(HERE/'evaluate_precheck.py'),str(p),str(dst),'--ruleset-ref',str(ref),*extra],capture_output=True,text=True)
 try:result=C.strict_json(dst.read_text()) if dst.exists() and dst.is_file() else None
 except ValueError:result=None # preserved raw evidence is not a result JSON
 return q.returncode,result,q.stdout,q.stderr
def context(d,sha,age=60):
 return {'schema':'ct01-precheck-context/1','approved_by':'SYNTHETIC TEST COORDINATOR','approval_ref':'FIXTURE ONLY; not real approval',
         'max_age_s':age,'not_before':d['meta']['t_start']-1,'reads_sha256':sha,**{k:d['meta'][k] for k in ('run_id','root_source','collector_sha256','host','t_start','t_end')}}
def main(argv):
 ap=argparse.ArgumentParser();ap.add_argument('--json');ap.add_argument('--only');args=ap.parse_args(argv)
 with tempfile.TemporaryDirectory(prefix='ir3r-selftest.') as tmp:
  tmp=pathlib.Path(tmp);p,d,rc,calls=collect(tmp,'clean');ref=tmp/'ref';ref.write_text(F.REF)
  t('C-clean',lambda:rc==0 and ev(d)['verdict']=='PASS' and ev(d)['current_ready'] is False)
  shared={'valid':[1,2]};shared_doc=copy.deepcopy(d);shared_doc['extra']=[shared,shared]
  t('C-shared-json-values',lambda:ev(shared_doc)['verdict']=='PASS')
  # N1/N2 behavioral regression gates: real evaluator/CLI, no repair of evidence.
  for label,value in [('infinite',float('inf')),('nan',float('nan')),('surrogate','\ud800')]:
   def invalid(value=value):
    x=copy.deepcopy(d);x['extra']={'deep':[{'value':value}]};frozen=json.dumps(x,ensure_ascii=True)
    res=ev(x)
    return res['verdict']=='UNUSABLE' and not res['current_ready'] and json.dumps(x,ensure_ascii=True)==frozen
   t('N1-deep-'+label,invalid)
   t('N1-decode-'+label,lambda value=value:raises(lambda:C.strict_json(json.dumps({'x':[value]}))))
  src=tmp/'n1-invalid';shutil.copytree(p,src);x=copy.deepcopy(d);x['meta']['host']='\ud800';(src/'reads.json').write_text(json.dumps(x,ensure_ascii=True))
  code,r,out,err=cli(src,tmp/'n1-result.json',ref)
  t('N1-schema-new-result',lambda:code==3 and r['verdict']=='UNUSABLE' and not r['current_ready'] and 'Traceback' not in err)
  code,r,out,err=cli(src,tmp/'not-created/n1-result.json',ref)
  t('N1-output-error-safe',lambda:code==5 and json.loads(out)['verdict']=='OUTPUT_ERROR' and 'Traceback' not in err)
  for field in ('stdout','stderr'):
   raw=p/('03-image-id.'+field);before=raw.read_bytes();code,r,out,err=cli(p,raw,ref)
   t('N2-raw-'+field,lambda code=code,out=out,raw=raw,before=before:code==5 and json.loads(out)['verdict']=='OUTPUT_ERROR' and raw.read_bytes()==before)
   dst=tmp/('n2-'+field+'-hardlink.json');os.link(raw,dst);code,r,out,err=cli(p,dst,ref)
   t('N2-hardlink-'+field,lambda code=code,out=out,raw=raw,dst=dst,before=before:code==5 and json.loads(out)['verdict']=='OUTPUT_ERROR' and raw.read_bytes()==before and dst.read_bytes()==before)
  t('C-allowed-argv',lambda:all(a[0] in C.BINS.values() and (a[0]!=C.BINS['docker'] or a[1] in ('version','info','image','ps','network','inspect','exec')) for a in calls) and not any('Env' in str(a) for a in calls))
  for name in C.read_contract():
   t('F1-missing-'+name,lambda name=name:mutate(d,lambda x:x.__setitem__('reads',[r for r in x['reads'] if r['name']!=name]))[0]['verdict']=='UNUSABLE')
  variants={
   'F1-duplicate':lambda x:x['reads'].append(copy.deepcopy(read(x,'image-id'))),
   'F1-rc-status':lambda x:read(x,'image-id').__setitem__('rc',1),
   'F1-argv':lambda x:read(x,'image-id').__setitem__('argv',['/toy/wrong']),
   'F1-meta-false':lambda x:x['meta'].__setitem__('data_complete',False),
   'F1-skipped-missing-argv':lambda x:read(x,'manager-ip-version').pop('argv'),
   'F1-required-type':lambda x:read(x,'docker-info').__setitem__('required',1),
   'F1-network-identity':lambda x:read(x,'network-inspect-sandboxnet').__setitem__('stdout',F.SB_INSPECT.replace(F.SB,F.DB)),
   'F1-resolution-meta':lambda x:x['meta']['networks_resolved'].__setitem__('sandboxnet','other_sandboxnet'),
   'F1-source-image':lambda x:x['meta'].__setitem__('image','unreviewed:latest'),
   'F1-source-bin':lambda x:x['meta']['bins'].__setitem__('docker','/toy/untrusted'),
   'F1-source-hash':lambda x:x['meta'].__setitem__('collector_sha256','0'*64),
   'F2-ps':lambda x:read(x,'ps-all').__setitem__('stdout','broken response\n'),
   'F2-ps-extra-column':lambda x:read(x,'ps-all').__setitem__('stdout','\n'.join(l+'\tunrequested' for l in read(x,'ps-all')['stdout'].splitlines())+'\n'),
   'F2-network-null-sandbox':lambda x:read(x,'network-inspect-sandboxnet').__setitem__('stdout','\t'.join(F.SB_INSPECT.rstrip('\n').split('\t')[:-1])+'\tnull\n'),
   'F2-manager-null-networks':lambda x:read(x,'inspect-manager').__setitem__('stdout','\t'.join(F.MANAGER.rstrip('\n').split('\t')[:-1])+'\tnull\n'),
   'F2-manager':lambda x:read(x,'inspect-manager').__setitem__('stdout','exited\n'),
   'F2-network-list':lambda x:read(x,'network-ls-dbnet').__setitem__('stdout',F.DB+'\n'),
   'F2-network-array':lambda x:read(x,'network-inspect-dbnet').__setitem__('stdout','\t'.join(F.DB_INSPECT.rstrip('\n').split('\t')[:-1])+ '\t[1]\n'),
   'F2-manager-array':lambda x:read(x,'inspect-manager').__setitem__('stdout','exited\t'+F.MAN+'\t0\t2026-10-08T08:42:17Z\t[1]\n'),
   'F2-version':lambda x:read(x,'docker-version').__setitem__('stdout','server=garbage\n'),
   'F2-info':lambda x:read(x,'docker-info').__setitem__('stdout','garbage\n'),
   'F2-image':lambda x:read(x,'image-id').__setitem__('stdout','sha256:x\n'),
   'F2-pgrep':lambda x:read(x,'pgrep-qemu').__setitem__('stdout','123 qemu\n'),
   'F3-read-object':lambda x:x['reads'].append({'status':'OK'}),
   'F3-read-list':lambda x:x.__setitem__('reads',[None]),
   'F3-rc-bool':lambda x:read(x,'docker-info').__setitem__('rc',False),
   'F3-okrc-null':lambda x:read(x,'docker-info').__setitem__('ok_rcs',None),
   'F3-stdout-list':lambda x:read(x,'docker-info').__setitem__('stdout',[]),
   'F4-reversed':lambda x:x['meta'].update(t_start=20,t_end=10),
   'F4-nan':lambda x:x['meta'].__setitem__('t_start',float('nan')),
  }
  for name,change in variants.items():
   def check(change=change):
    r,same=mutate(d,change);return same and r['verdict']=='UNUSABLE'
   t(name,check)
  # Real collector + faulty fake reads; status/payload error must survive evaluator without repaired input.
  for name,spec in {
    'F2-collector-ps':{'ps':(0,b'broken response\n',b'',None)},'F2-collector-manager':{'manager':(0,b'exited\n',b'',None)},
    'F2-collector-list':{'ls-dbnet':(0,(F.DB+'\n').encode(),b'',None)},
    'C-permission':{'docker_all':(1,b'',b'permission denied',None)},'C-daemon':{'docker_all':(1,b'',b'daemon unavailable',None)},
    'C-info-read-error':{'info':(1,b'',b'permission denied',None)},'C-network-missing':{'ls-sandboxnet':(0,b'',b'',None)},
    'C-network-ambiguous':{'ls-sandboxnet':(0,(F.SB+'\t'+F.SN+'\n'+F.DB+'\tother_sandboxnet\n').encode(),b'',None)},
    'C-timeout':{'version':(None,b'',b'partial stderr','TIMEOUT')},'C-pgrep-error':{'pgrep':(2,b'',b'bad option',None)},
  }.items():
   q,x,c_rc,c_calls=collect(tmp,name,spec);r=ev(x)
   t(name,lambda r=r,c_rc=c_rc:c_rc==3 and r['verdict']=='UNKNOWN')
   if 'manager' in name or name in ('C-permission','C-daemon'):t(name+'-no-exec',lambda cc=c_calls:not any(a[0]==C.BINS['docker'] and a[1]=='exec' for a in cc))
  q,x,_,_=collect(tmp,'image-mismatch',{'image':(0,('sha256:'+'0'*64+'\n').encode(),b'',None)})
  t('C-image-fail',lambda:ev(x)['verdict']=='FAIL')
  # Independent FAIL plus missing reads is retained, not relabelled as a successful environment.
  q,x,c_rc,_=collect(tmp,'image-fail-and-read-error',{'image':(0,('sha256:'+'0'*64+'\n').encode(),b'',None),'info':(1,b'',b'denied',None)})
  t('C-fail-and-measurement',lambda:ev(x)['verdict']=='FAIL' and any(i['status']=='UNKNOWN' for i in ev(x)['items']))
  # Running manager control requires mutually consistent ps/network/container payloads, not only a state token.
  ep={'Name':C.MANAGER,'EndpointID':F.MAN,'MacAddress':'02:00:00:00:00:10','IPv4Address':'192.168.60.10/24','IPv6Address':''}
  sb='\t'.join(F.SB_INSPECT.rstrip('\n').split('\t')[:-1])+'\t'+json.dumps({F.MAN:ep})+'\n'
  manager='running\t'+F.MAN+'\t0\t2026-10-08T08:42:17Z\t'+json.dumps({F.SN:{'NetworkID':F.SB,'IPAddress':'192.168.60.10','MacAddress':ep['MacAddress']}})+'\n'
  ps=f'{C.MANAGER}\trunning\tsandbox-manager\t{F.MAN}\nmongo-db\trunning\tmongo\t{F.MONGO}\n'
  q,x,c_rc,cc=collect(tmp,'manager-running',{'manager':(0,manager.encode(),b'',None),'ps':(0,ps.encode(),b'',None),'inspect-sb':(0,sb.encode(),b'',None)})
  t('C-manager-running',lambda:c_rc==0 and ev(x)['verdict']=='PASS' and len([a for a in cc if a[0]==C.BINS['docker'] and a[1]=='exec'])==4)

  # Container absence/stopped are decided from mutually coherent valid reads, never a failed listing.
  db_empty='\t'.join(F.DB_INSPECT.rstrip('\n').split('\t')[:-1])+'\t{}\n'
  manager_ps=f'{C.MANAGER}\texited\tsandbox-manager\t{F.MAN}\n'
  mongo_ps=f'mongo-db\trunning\tmongo\t{F.MONGO}\n'
  q,x,_,_=collect(tmp,'manager-absent',{'ps':(0,mongo_ps.encode(),b'',None),'manager':(1,b'',b'No such object',None)})
  t('C-manager-absent',lambda:ev(x)['verdict']=='FAIL')
  q,x,_,_=collect(tmp,'mongo-absent',{'ps':(0,manager_ps.encode(),b'',None),'mongo':(1,b'',b'No such object',None),'inspect-db':(0,db_empty.encode(),b'',None)})
  t('C-mongo-absent',lambda:ev(x)['verdict']=='FAIL')
  stopped=f'exited\t{F.MONGO}\t0\t2026-10-08T08:42:17Z\t'+json.dumps({F.DN:{'IPAddress':'','MacAddress':'','NetworkID':F.DB}})+'\n'
  q,x,_,_=collect(tmp,'mongo-stopped',{'ps':(0,(manager_ps+f'mongo-db\texited\tmongo\t{F.MONGO}\n').encode(),b'',None),'mongo':(0,stopped.encode(),b'',None),'inspect-db':(0,db_empty.encode(),b'',None)})
  t('C-mongo-stopped',lambda:ev(x)['verdict']=='FAIL')
  # Exercise a real nonzero process return using a harmless local Python stub, not Docker.
  stub_result=C.subprocess_runner([sys.executable,'-I','-B','-c','import sys; sys.stderr.write("fixture read denied\\n");sys.exit(1)'])
  q,x,c_rc,_=collect(tmp,'actual-stub-nonzero',{'info':stub_result})
  t('C-real-subprocess-error',lambda:stub_result[0]==1 and c_rc==3 and ev(x)['verdict']=='UNKNOWN' and b'fixture read denied' in stub_result[2])
  # Selected schema crash cases must produce NEW structured CLI JSON over an old PASS sentinel.
  for n in ('F3-read-object','F2-network-array','F3-okrc-null','F4-reversed','F4-nan'):
   src=tmp/('cli-'+n);shutil.copytree(p,src);x=copy.deepcopy(d);variants[n](x);sync_files(src,x);dst=tmp/(n+'-result.json');dst.write_text('{"verdict":"PASS","evaluation_id":"OLD"}')
   code,res,_,err=cli(src,dst,ref)
   t(n+'-CLI',lambda code=code,res=res,err=err:code==3 and res['verdict']=='UNUSABLE' and res['evaluation_id']!='OLD' and 'Traceback' not in err)
  duplicate_json=tmp/'duplicate-json';shutil.copytree(p,duplicate_json)
  raw=json.dumps(d).replace('"status": "OK"','"status": "NONZERO", "status": "OK"',1);(duplicate_json/'reads.json').write_text(raw)
  code,r,_,_=cli(duplicate_json,tmp/'duplicate-json-result.json',ref)
  t('F1-duplicate-json-key',lambda:code==3 and r['verdict']=='UNUSABLE')
  dst=tmp/'unreadable-input-result.json';dst.write_text('{"verdict":"PASS"}')
  code,r,_,_=cli(tmp/'missing-input',dst,ref);t('F3-input-read-error',lambda:code==3 and r['verdict']=='UNUSABLE')
  code,r,_,_=cli(p,p/'reads.json',ref);t('F3-protected-input',lambda:code==5 and C.strict_json((p/'reads.json').read_text())==d)
  bad=tmp/'missing-parent/result.json';code,r,out,err=cli(p,bad,ref);t('F3-output-error',lambda:code==5 and 'OUTPUT_ERROR' in out and r is None)
  code,r,_,_=cli(p,tmp/'clean-result.json',ref);t('C-clean-CLI',lambda:code==0 and r['verdict']=='PASS' and not r['current_ready'])
  # Current context uses ONLY synthetic root provenance/window, not real coordinator approval.
  current=copy.deepcopy(d);current['meta'].update(root_source='/var/tmp/ct01-precheck.ABCDEFGH/out',execution_uid=0)
  sha='f'*64;ctx=context(current,sha);now=current['meta']['t_end']+1
  t('F4-current-clean',lambda:ev(current,mode='current',context=ctx,input_sha256=sha,now=now)['current_ready'] is True)
  t('F4-current-no-context',lambda:ev(current,mode='current',now=now)['verdict']=='UNKNOWN')
  for n,change in {'window':lambda x:x.__setitem__('max_age_s',None),'sha':lambda x:x.__setitem__('reads_sha256','0'*64),'run':lambda x:x.__setitem__('run_id','0'*32),'source':lambda x:x.__setitem__('root_source','/toy/out'),'approval':lambda x:x.__setitem__('approval_ref','')}.items():
   c=copy.deepcopy(ctx);change(c);t('F4-context-'+n,lambda c=c:ev(current,mode='current',context=c,input_sha256=sha,now=now)['verdict']=='UNKNOWN')
  t('F4-current-stale',lambda:ev(current,mode='current',context=ctx,input_sha256=sha,now=now+1000)['verdict']=='UNKNOWN')
  t('F4-history-stale-not-ready',lambda:ev(current,now=now+1000)['verdict']=='PASS' and ev(current,now=now+1000)['current_ready'] is False)
  # Raw file contradiction checked independently from payload/schema; no new host reads.
  (p/'01-docker-version.stdout').write_text('wrong saved output')
  code,r,_,_=cli(p,tmp/'raw-mismatch.json',ref);t('F1-raw-file-mismatch',lambda:code==3 and r['verdict']=='UNUSABLE');sync_files(p,d)
  # Fresh export. Fake producer supplies only a toy archive; extractor uses user tar, never sudo.
  archive=tmp/'toy.tar';sync_files(p,current)
  with tarfile.open(archive,'w') as tar:tar.add(p,arcname='out',recursive=False);[tar.add(f,arcname='out/'+f.name) for f in p.iterdir() if f.name.endswith(('.stdout','.stderr')) or f.name=='reads.json']
  export_ctx=tmp/'export-context.json';export_ctx.write_text(json.dumps(context(current,hashlib.sha256((p/'reads.json').read_bytes()).hexdigest())))
  stageparent=tmp/'exports';stageparent.mkdir();(stageparent/'run1').mkdir();(stageparent/'run1/old-pass.json').write_text('{"verdict":"PASS"}')
  for n,producer_rc,extractor_rc in [('clean',0,0),('current-clean',0,0),('producer-error',1,0),('extractor-error',0,2)]:
   calls_eval=[]
   def run(argv,stdout,stderr):
    pathlib.Path(stderr).write_text('')
    if argv[0]=='/usr/bin/sudo':shutil.copyfile(archive,stdout);return producer_rc
    if extractor_rc:
     X.runner(argv,stdout,stderr) # complete-looking partial output must not bypass a failing extractor rc
     return extractor_rc
    return X.runner(argv,stdout,stderr) # actual tar only on toy archive, normal user
   def evaluator(a):calls_eval.append(a);return E.main(a)
   code,r=X.export_and_evaluate(current['meta']['root_source'],current['meta']['run_id'],str(stageparent),E.digest_file(C.__file__),run=run,evaluator=evaluator,ruleset_ref=str(ref),mode='current' if n=='current-clean' else 'historical',context=str(export_ctx) if n=='current-clean' else None)
   t('F4-export-'+n,lambda n=n,code=code,r=r,calls_eval=calls_eval:code==0 and r['evaluator_called'] and len(calls_eval)==1 and r['reads_sha256']==hashlib.sha256((p/'reads.json').read_bytes()).hexdigest() and (n!='current-clean' or r['current_ready']) if n in ('clean','current-clean') else code==4 and not r['evaluator_called'] and not calls_eval)
   t('F4-export-'+n+'-fresh',lambda r=r:pathlib.Path(r['destination']).parent==stageparent and pathlib.Path(r['destination']).name.startswith('ct01-precheck-export.'))
  t('F4-stale-output-untouched',lambda:(stageparent/'run1/old-pass.json').read_text()=='{"verdict":"PASS"}')
  # Output FD / source copy-hash positive and negative path tests remain relevant.
  victim=tmp/'victim';victim.mkdir();(victim/'keep').write_text('keep');q=tmp/'fd-out';q.mkdir(mode=0o700);fd=C.prepare_outdir(str(q),os.geteuid());q.rename(tmp/'opened');q.symlink_to(victim,target_is_directory=True);C.write_new(fd,'new','new');os.close(fd)
  t('PC4-fd-race',lambda:(tmp/'opened/new').exists() and list(victim.iterdir())==[victim/'keep'])
  t('PC4-final-symlink',lambda:raises(lambda:C.prepare_outdir(str(q),os.geteuid())))
  # Exact root snippet, with only toy BASE/SRC/HASH and inert PY in this non-root process.
  snippet=(HERE/'RUN-PROCEDURE.md').read_text().split('# --- BEGIN ROOT SNIPPET ---')[1].split('# --- END ROOT SNIPPET ---')[0]
  launch=tmp/'launch';launch.mkdir();stub=launch/'py-stub';stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "'+str(launch/'ran')+'"\nexit 3\n');stub.chmod(0o755)
  def go(h):
   return subprocess.run(['/bin/sh','-c',snippet],env={'BASE':str(launch),'SRC':str(HERE/'collector.py'),'HASH':h,'PY':str(stub),'PATH':'/usr/bin:/bin'},capture_output=True,text=True)
  launched=go(E.digest_file(C.__file__));trace=(launch/'ran').read_text()
  t('PC4-copy-hash-good',lambda:launched.returncode==3 and 'ct01-precheck.' in trace and str(HERE/'collector.py') not in trace)
  before=(launch/'ran').read_text();bad=go('0'*64)
  t('PC4-copy-hash-bad',lambda:bad.returncode==1 and 'HASH MISMATCH' in bad.stdout and (launch/'ran').read_text()==before)
  # Current CLI must bind actual bytes and produce a fresh invocation identity.
  sync_files(p,current);sha_real=hashlib.sha256((p/'reads.json').read_bytes()).hexdigest();ctx_real=context(current,sha_real);ctxfile=tmp/'context.json';ctxfile.write_text(json.dumps(ctx_real))
  code,r,_,_=cli(p,tmp/'current.json',ref,'--mode','current','--context',str(ctxfile))
  t('F4-current-CLI',lambda:code==0 and r['current_ready'] and r['reads_sha256']==sha_real)
  ctx_real['reads_sha256']='0'*64;ctxfile.write_text(json.dumps(ctx_real));code,r,_,_=cli(p,tmp/'current-wrong.json',ref,'--mode','current','--context',str(ctxfile))
  t('F4-current-CLI-wrong-digest',lambda:code==2 and not r['current_ready'])
  # A failed new write cannot leave an old PASS at a writable result path.
  failed_dst=tmp/'write-fails.json';failed_dst.write_text('{"verdict":"PASS"}')
  original_write=E.atomic_json
  def fail_write(*a):raise OSError('synthetic output failure')
  E.atomic_json=fail_write
  try:failed_code=E.main([str(p),str(failed_dst),'--ruleset-ref',str(ref)])
  finally:E.atomic_json=original_write
  t('F3-write-failure-removes-stale',lambda:failed_code==5 and not failed_dst.exists())
  # Invalidating an old result can itself fail; explicitly report it, never hide it behind old PASS.
  locked=tmp/'locked';locked.mkdir();old=locked/'result.json';old.write_text('{"verdict":"PASS"}');locked.chmod(0o500)
  try:
   code,r,out,err=cli(p,old,ref);t('F3-invalidation-permission',lambda:code==5 and 'old_result_may_remain' in out and 'OUTPUT_ERROR' in out)
  finally:locked.chmod(0o700)
  t('PC4-no-root-main',lambda:subprocess.run([sys.executable,'-I','-B',str(HERE/'collector.py'),'/toy/never-open'],capture_output=True).returncode==2)
 if args.only:
  wanted=set(args.only.split(','));missing=wanted-set(RESULTS)
  if missing:raise SystemExit('missing requested targets '+repr(missing))
  RESULTS_FILTER={k:v for k,v in RESULTS.items() if k in wanted}
 else:RESULTS_FILTER=RESULTS
 if args.json:pathlib.Path(args.json).write_text(json.dumps({'tests':RESULTS_FILTER,'details':DETAILS},indent=2))
 print('SELFTEST-PRECHECK: '+str(sum(RESULTS_FILTER.values()))+'/'+str(len(RESULTS_FILTER))+' passed')
 return 0 if all(RESULTS_FILTER.values()) else 1
if __name__=='__main__':sys.exit(main(sys.argv[1:]))
