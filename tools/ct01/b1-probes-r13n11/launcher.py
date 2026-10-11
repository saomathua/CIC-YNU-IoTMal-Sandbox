#!/usr/bin/env python3
"""Pinned staged-root ARP launcher. No automatic context approval/window extension.
CLI is root-only and trusts reviewed installed binaries + no privileged concurrent writer.
Dependencies/clock injection in Session is only an offline Python fixture boundary, never CLI/env flags.
"""
import argparse,contextlib,hashlib,json,math,os,pathlib,re,signal,stat,subprocess,sys,tempfile,time,types,uuid
P=pathlib.Path
COLLECTOR_PIN='8300562e055e9f900c1cd0e3cc46ae774e914fd132529ccdf75c318a1c6ab85e'
POLICY='ct01-nft-exact-channels/1';SET='ct01-nft-historical-4G-3G-MGR-MGR2-MGR3/4';FIELDS=('run_id','root_source','collector_sha256','host','t_start','t_end')
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
class Refused(ValueError):pass
def digest(path):return hashlib.sha256(P(path).read_bytes()).hexdigest()
def require(ok,reason):
    if not ok:raise Refused(reason)
def read_json(path):
    def bad(s):raise Refused('non-finite JSON: '+s)
    def pairs(items):
        out={}
        for k,v in items:
            require(k not in out,'duplicate JSON key: '+k);out[k]=v
        return out
    d=json.loads(P(path).read_bytes(),parse_constant=bad,object_pairs_hook=pairs)
    def visit(v):
        if isinstance(v,float):require(math.isfinite(v),'non-finite JSON number')
        elif isinstance(v,str):require(not any(0xd800<=ord(c)<=0xdfff for c in v),'surrogate JSON string')
        elif isinstance(v,dict):
            for k,x in v.items():visit(k);visit(x)
        elif isinstance(v,list):
            for x in v:visit(x)
    visit(d);require(isinstance(d,dict),'JSON object required');return d
def save_json(path,doc,new=False):
    p=P(path)
    if new:require(not p.exists(),'refusing old output: '+str(p))
    else:require(not p.is_symlink(),'symlink output refused')
    data=json.dumps(doc,ensure_ascii=True,allow_nan=False,indent=2)+'\n'
    fd,tmp=tempfile.mkstemp(prefix='receipt.',dir=p.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,p)
    except BaseException:
        try:os.unlink(tmp)
        except OSError:pass
        raise

def trust_runtime(path):
    p=P(path)
    require(p.is_absolute() and str(p.resolve())==str(p),'canonical path required')
    q=p
    while True:
        s=q.lstat();require(not stat.S_ISLNK(s.st_mode),'symlink ancestry refused: '+str(q));require(s.st_uid==0,'not root-owned: '+str(q))
        if str(q)=='/var/tmp':require(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o1777,'root /var/tmp sticky1777 required')
        else:require(not stat.S_IMODE(s.st_mode)&0o022,'writable by non-root: '+str(q))
        if q.parent==q:break
        q=q.parent

def manifest_entries(stage,expected):
    stage=P(stage);require(re.fullmatch('[0-9a-f]{64}',expected or '') is not None,'externally pinned manifest hash required')
    require(digest(stage/'SHA256SUMS')==expected,'manifest digest mismatch')
    entries={}
    for line in (stage/'SHA256SUMS').read_text().splitlines():
        h,name=line.split(None,1);name=name.removeprefix('./');path=P(name)
        require(re.fullmatch('[0-9a-f]{64}',h) is not None and name and not path.is_absolute() and '..' not in path.parts and name not in entries,'invalid/duplicate manifest entry')
        require(all(re.fullmatch('[A-Za-z0-9_.-]+',c) for c in path.parts),'manifest unsafe path')
        entries[name]=h
    require({'launcher.py','bootstrap.py','harness/run-ct01-b1.sh','harness/capture_drain.py','harness/cumulative_anchor.py','harness/b1_cases.py','harness/b1_harness.py','harness/selftest_b1.py','harness/probe_matrix_launch.py','harness/worker_guard.py','harness/run-06b4i.sh','harness/harness_lib.sh','harness/arp_cases.py','harness/guest_state.py','precheck/collector.py','precheck/evaluate_precheck.py','precheck/export_precheck.py','precheck/nft_policy.py','precheck/references/provenance.json','repo/docker-compose.yml'}<=set(entries),'manifest missing mandatory runtime payload')
    return entries

def allowed_output(name,is_dir):
    """Closed output namespace: never permit unmanifested code in import/source trees.
    harness/out includes selftest-generated doubles + guest evidence; exports are R2 data only.
    These outputs are not executable runtime INPUT pins and cannot confer approval.
    """
    path=P(name);parts=path.parts
    if parts[:2]==('harness','out'):return True
    if parts[0]=='exports':
        return len(parts)==1 and is_dir or len(parts)>1 and re.fullmatch(r'ct01-precheck-export\.[A-Za-z0-9_]{8}',parts[1]) is not None
    if name=='launch-proof':return is_dir
    if name=='launch-proof/use.json':return not is_dir
    files={'collector.stdout','collector.stderr','collection-status.json','collection-receipt.json','historical-discovery.json','approved-context.json','export-evaluation.stdout','launch-receipt.json','launch-process.json'}
    if name in files:return not is_dir
    return not is_dir and re.fullmatch(r'current-(ENTRY|SETUP|ARM|MIPS)-[0-9a-f]{32}\.(json|stdout)',name) is not None

def verify_layout(stage,entries):
    directories={str(P(n).parent) for n in entries}
    for n in entries:
        directories.update(str(p) for p in P(n).parents if str(p)!='.')
    for path in P(stage).rglob('*'):
        name=str(path.relative_to(stage))
        require(not path.is_symlink(),'stage symlink not allowed: '+name)
        if name=='SHA256SUMS' or name in entries:continue
        if path.is_dir() and name in directories:continue
        require((path.is_dir() or path.is_file()) and allowed_output(name,path.is_dir()),'file/directory outside manifest/output contract: '+name)

def verify_stage(stage,expected,trust=trust_runtime):
    stage=P(stage);trust(stage);trust(stage/'SHA256SUMS');entries=manifest_entries(stage,expected)
    for name,h in entries.items():
        path=stage/name;trust(path);require(path.is_file() and not path.is_symlink(),'regular runtime file required');require(digest(path)==h,'staged pin mismatch: '+name)
    verify_layout(stage,entries)
    require(entries['precheck/collector.py']==COLLECTOR_PIN,'collector must retain reviewed bytes')
    return entries

def load_precheck(stage):
    sys.path.insert(0,str(P(stage)/'precheck'))
    import collector as C,evaluate_precheck as E,export_precheck as X
    for m in (C,E,X):require(P(m.__file__).resolve().parent==P(stage).resolve()/'precheck','precheck import not from verified root stage')
    return C,E,X

class Session:
    def __init__(self,stage,manifest_sha,*,clock=time.time,trust=trust_runtime,external_run=None,evaluator=None,modules=None):
        self.stage=P(stage);self.manifest_sha=manifest_sha;self.clock=clock;self.trust=trust;self.external_run=external_run;self.evaluator=evaluator
        verify_stage(self.stage,manifest_sha,trust)
        self.C,self.E,self.X=modules or load_precheck(self.stage);self.exporter=self.X.export_and_evaluate
        self.receipt_path=self.stage/'launch-receipt.json'
    def collection(self):
        path=self.stage/'collection-receipt.json';self.trust(path);c=read_json(path)
        require(c.get('schema')=='ct01-arp-collection/1' and c.get('stage')==str(self.stage) and c.get('manifest_sha256')==self.manifest_sha,'collection receipt stage/manifest binding invalid')
        require(c.get('collector_rc')==0 and type(c.get('collector_rc')) is int and type(c.get('historical_rc')) is int and c.get('historical_rc')==0 and c.get('historical_verdict')=='PASS','collection not eligible')
        meta=c.get('collection');require(isinstance(meta,dict),'collection identity missing');src=P(meta.get('root_source',''))
        require(re.fullmatch(r'/var/tmp/ct01-precheck\.[A-Za-z0-9]{8}/out',str(src)) is not None,'fixed root source required');self.trust(src);self.trust(src/'reads.json')
        require(digest(src/'reads.json')==c.get('reads_sha256'),'root source digest differs from collection receipt')
        d=read_json(src/'reads.json');raw_problems=self.E.verify_raw_files(str(src),d);require(not raw_problems,'root raw verification failed: '+repr(raw_problems))
        require(d.get('meta',{}).get('execution_uid')==0,'root collection uid required')
        require(all(d['meta'].get(k)==meta.get(k) for k in FIELDS),'source identity differs from receipt')
        require(meta.get('collector_sha256')==COLLECTOR_PIN,'collector binding mismatch')
        return c,d
    def validate_export(self,x,rc,c):
        require(type(rc) is int and rc==0,'export/evaluation exit not zero')
        require(x.get('schema')=='ct01-precheck-export/2' and x.get('status')=='EVALUATED','export schema/status invalid')
        require(all(type(x.get(k)) is int and x[k]==0 for k in ('producer_rc','extractor_rc','evaluator_rc')) and x.get('evaluator_called') is True,'producer/extractor/evaluator failed')
        require(x.get('verdict')=='PASS' and x.get('mode')=='current' and x.get('current_ready') is True,'export not current PASS/ready')
        require(x.get('policy_version')==POLICY and x.get('reference_set_version')==SET,'export policy mismatch')
        require(all(x.get(k)==c['collection'][k] for k in ('root_source','run_id','collector_sha256')),'export source/run binding mismatch')
        dest=P(x.get('destination',''));require(dest.is_absolute() and dest.parent==self.stage/'exports' and dest.name.startswith('ct01-precheck-export.'),'export outside fresh session destination')
        self.trust(dest);r=read_json(dest/'precheck-result.json');require(x.get('precheck_result_sha256')==digest(dest/'precheck-result.json'),'export result digest mismatch')
        d=read_json(dest/'out/reads.json');require(x.get('reads_sha256')==c['reads_sha256']==digest(dest/'out/reads.json'),'export input digest mismatch')
        raw_problems=self.E.verify_raw_files(str(dest/'out'),d);require(not raw_problems,'export raw verification failed: '+repr(raw_problems))
        args=[str(dest/'out'),str(dest/'precheck-result.json'),'--mode','current','--context',str(self.stage/'approved-context.json')]
        self.X.verify_evaluation(r,d,args,rc,c['reads_sha256'],'current')
        require(r.get('schema')=='ct01-precheck-result/3' and r.get('mode')=='current' and r.get('verdict')=='PASS' and r.get('current_ready') is True,'bound evaluator result not current PASS/ready')
        require(x.get('nft_policy')==r.get('nft_policy') and x.get('evaluator_argv')==r.get('evaluator_argv'),'export provenance/argv binding mismatch')
        return dest
    def prepare(self,context_path,context_sha):
        verify_stage(self.stage,self.manifest_sha,self.trust);require(not self.receipt_path.exists(),'launch receipt exists: session cannot be reused')
        c,d=self.collection();require(re.fullmatch('[0-9a-f]{64}',context_sha or '') is not None,'externally pinned context digest required')
        # Source is untrusted data only: copied bytes checked; no imports/eval/source of the context.
        context_copy=self.stage/'approved-context.json';require(not context_copy.exists(),'context copy already exists')
        # Freeze every source path component through descriptors, regular file only; no secret symlink/FIFO reads.
        src=P(context_path);require(src.is_absolute() and '..' not in src.parts,'absolute context path required')
        dfd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            for name in src.parts[1:-1]:
                nf=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=dfd);os.close(dfd);dfd=nf
            fd=os.open(src.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=dfd)
            with os.fdopen(fd,'rb') as f:
                require(stat.S_ISREG(os.fstat(f.fileno()).st_mode),'context not regular');require(os.fstat(f.fileno()).st_size<=1048576,'context too large');raw=f.read()
        finally:os.close(dfd)
        require(hashlib.sha256(raw).hexdigest()==context_sha,'context hash mismatch')
        with context_copy.open('xb') as f:f.write(raw)
        context_copy.chmod(0o600);self.trust(context_copy);ctx=read_json(context_copy)
        problem=self.E.current_problem(d['meta'],ctx,c['reads_sha256'],self.clock());require(problem is None,'current context rejected: '+str(problem))
        parent=self.stage/'exports';parent.mkdir(mode=0o700,exist_ok=False)
        kw={'mode':'current','context':str(context_copy)}
        if self.external_run is not None:kw['run']=self.external_run
        if self.evaluator is not None:kw['evaluator']=self.evaluator
        with (self.stage/'export-evaluation.stdout').open('x') as log,contextlib.redirect_stdout(log):
            rc,x=self.exporter(c['collection']['root_source'],c['collection']['run_id'],str(parent),COLLECTOR_PIN,**kw)
        dest=self.validate_export(x,rc,c)
        record={'schema':'ct01-arp-launch-receipt/1','launch_id':uuid.uuid4().hex,'stage':str(self.stage),'manifest_sha256':self.manifest_sha,'collection_receipt_sha256':digest(self.stage/'collection-receipt.json'),'collection':c['collection'],'reads_sha256':c['reads_sha256'],'context_path':str(context_copy),'context_sha256':context_sha,'export_destination':str(dest),'export_result_sha256':digest(dest/'export-result.json'),'initial_result_sha256':digest(dest/'precheck-result.json'),'policy_version':POLICY,'reference_set_version':SET,'status':'PREPARED','events':[],'note':'receipt binds checks to launch, never confers approval or proves host unchanged; context approval is independently managed'}
        (self.stage/'launch-proof').mkdir(mode=0o755,exist_ok=False)
        save_json(self.receipt_path,record,new=True);return record
    def checkpoint(self,phase):
        self.trust(self.receipt_path);r=read_json(self.receipt_path)
        require(r.get('schema')=='ct01-arp-launch-receipt/1' and r.get('stage')==str(self.stage) and r.get('manifest_sha256')==self.manifest_sha,'invalid launch receipt')
        try:
            require(r.get('status') in ('PREPARED','ACTIVE'),'launch stopped/completed; no retry')
            require(r.get('policy_version')==POLICY and r.get('reference_set_version')==SET and re.fullmatch('[0-9a-f]{32}',r.get('launch_id','')) is not None,'receipt identity/policy invalid')
            phases=['ENTRY','SETUP','ARM','MIPS'];events=r.get('events');require(isinstance(events,list) and len(events)<len(phases) and phase==phases[len(events)],'unexpected launch phase')
            require(all(isinstance(e,dict) and e.get('phase')==phases[i] and e.get('ok') is True and isinstance(e.get('checked_at'),(int,float)) and not isinstance(e.get('checked_at'),bool) and math.isfinite(e['checked_at']) for i,e in enumerate(events)),'receipt phase history invalid')
            verify_stage(self.stage,self.manifest_sha,self.trust)
            require(digest(self.stage/'collection-receipt.json')==r.get('collection_receipt_sha256'),'collection receipt changed')
            c,d=self.collection();require(c['collection']==r.get('collection') and c['reads_sha256']==r.get('reads_sha256'),'launch collection binding mismatch')
            ctx_path=self.stage/'approved-context.json';self.trust(ctx_path);require(str(ctx_path)==r.get('context_path') and digest(ctx_path)==r.get('context_sha256'),'approved context changed')
            ctx=read_json(ctx_path);problem=self.E.current_problem(d['meta'],ctx,c['reads_sha256'],self.clock());require(problem is None,'current expired/invalid at '+phase+': '+str(problem))
            dest=P(r.get('export_destination',''));x=read_json(dest/'export-result.json');require(digest(dest/'export-result.json')==r.get('export_result_sha256') and digest(dest/'precheck-result.json')==r.get('initial_result_sha256'),'bound export/result changed')
            require(self.validate_export(x,0,c)==dest,'export destination changed')
            target=self.stage/('current-'+phase+'-'+uuid.uuid4().hex+'.json');args=[str(dest/'out'),str(target),'--mode','current','--context',str(ctx_path)]
            with target.with_suffix('.stdout').open('x') as log,contextlib.redirect_stdout(log):
                code=(self.evaluator or self.E.main)(args)
            require(type(code) is int and code==0,'current evaluator exit at '+phase+': '+str(code));result=read_json(target)
            self.X.verify_evaluation(result,read_json(dest/'out/reads.json'),args,code,c['reads_sha256'],'current')
            require(result.get('verdict')=='PASS' and result.get('mode')=='current' and result.get('current_ready') is True,'current result not PASS/ready')
            # Check clock again after evaluator and pin checks; never auto-extend max_age_s.
            used_at=self.clock();problem=self.E.current_problem(d['meta'],ctx,c['reads_sha256'],used_at);require(problem is None,'expired during current evaluation: '+str(problem))
            r['events'].append({'phase':phase,'ok':True,'checked_at':used_at,'age_s':used_at-d['meta']['t_start'],'max_age_s':ctx['max_age_s'],'result_path':str(target),'result_sha256':digest(target),'argv':[str(self.E.__file__),*args]});r['status']='ACTIVE';save_json(self.receipt_path,r)
            if phase in ('ARM','MIPS'):
                proof={'schema':'ct01-arp-use-proof/1','launch_id':r['launch_id'],'phase':phase,'collection':c['collection'],'reads_sha256':c['reads_sha256'],'context_sha256':r['context_sha256'],'policy_version':POLICY,'reference_set_version':SET,'max_age_s':ctx['max_age_s'],'not_before':ctx['not_before'],'checked_at':used_at}
                save_json(self.stage/'launch-proof/use.json',proof);(self.stage/'launch-proof/use.json').chmod(0o644)
            return r
        except Exception as e:
            r['events'].append({'phase':phase,'ok':False,'checked_at':self.clock(),'reason':type(e).__name__+': '+str(e)});r['status']='STOPPED';save_json(self.receipt_path,r);raise

def collect(stage,manifest_sha,*,trust=trust_runtime,modules=None,run=subprocess.run):
    verify_stage(stage,manifest_sha,trust);C,E,X=modules or load_precheck(stage);stage=P(stage);require(not (stage/'collection-receipt.json').exists(),'collection already recorded')
    t=P('/var/tmp')/('ct01-precheck.'+uuid.uuid4().hex[:8]);t.mkdir(mode=0o700);out=t/'out';out.mkdir(mode=0o700)
    shutil_copy=C.__file__;data=P(shutil_copy).read_bytes();require(hashlib.sha256(data).hexdigest()==COLLECTOR_PIN,'collector source pin mismatch');(t/'collector.py').write_bytes(data);(t/'collector.py').chmod(0o400);require(digest(t/'collector.py')==COLLECTOR_PIN,'collector staged copy mismatch')
    with (stage/'collector.stdout').open('xb') as stdout,(stage/'collector.stderr').open('xb') as stderr:q=run(['/usr/bin/python3','-I','-B',str(t/'collector.py'),str(out)],env=ENV,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
    base={'schema':'ct01-arp-collection/1','stage':str(stage),'manifest_sha256':manifest_sha,'root_source':str(out),'collector_rc':q.returncode,'historical_rc':None,'historical_verdict':None}
    save_json(stage/'collection-status.json',base,new=True);require(q.returncode==0,'collector failed; NOT a precheck PASS; preserved '+str(out))
    d=read_json(out/'reads.json');raw_problems=E.verify_raw_files(str(out),d);require(not raw_problems,'collected raw verification failed: '+repr(raw_problems));require(d['meta']['root_source']==str(out) and d['meta']['execution_uid']==0 and d['meta']['collector_sha256']==COLLECTOR_PIN,'actual collection identity mismatch')
    rc=E.main([str(out),str(stage/'historical-discovery.json'),'--mode','historical']);r=read_json(stage/'historical-discovery.json');require(rc==0 and r.get('verdict')=='PASS' and r.get('current_ready') is False,'historical precheck not PASS; keep data, no launch')
    base.update(historical_rc=rc,historical_verdict=r['verdict'],collection={k:d['meta'][k] for k in FIELDS},reads_sha256=digest(out/'reads.json'))
    save_json(stage/'collection-receipt.json',base,new=True);return base

def managed_run(argv,**kw):
    """Relay the first INT/TERM/HUP to an isolated script PGID and WAIT; never kill cleanup.
    Repeated signals are recorded, not escalated to KILL. SIGKILL/daemon hangs cannot be recovered here.
    """
    state={'signals':[],'forwarded':False};child=None;previous={}
    def relay(number,frame):
        state['signals'].append({'number':number,'name':signal.Signals(number).name,'at':time.time()})
        if len(state['signals'])==1 and child is not None:
            try:os.killpg(child.pid,number);state['forwarded']=True
            except ProcessLookupError:pass
    try:
        for number in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
            previous[number]=signal.getsignal(number);signal.signal(number,relay)
        if state['signals']:
            return types.SimpleNamespace(returncode=128+state['signals'][0]['number'],signal_state=state)
        child=subprocess.Popen(argv,start_new_session=True,**kw)
        if state['signals'] and not state['forwarded']:
            try:os.killpg(child.pid,state['signals'][0]['number']);state['forwarded']=True
            except ProcessLookupError:pass
        while child.poll() is None:time.sleep(.05)
        return types.SimpleNamespace(returncode=child.wait(),signal_state=state)
    finally:
        for number,handler in previous.items():signal.signal(number,handler)

def launch(stage,manifest_sha,context,context_sha,*,session_factory=Session,run=None):
    session=session_factory(P(stage),manifest_sha);session.prepare(context,context_sha);session.checkpoint('ENTRY')
    runenv=dict(ENV);runenv['CT01_LAUNCH_RECEIPT']=str(session.receipt_path);runenv['CT01_LAUNCH_ID']=read_json(session.receipt_path)['launch_id']
    try:q=(managed_run if run is None else run)(['/bin/bash',str(session.stage/'harness/run-ct01-b1.sh')],cwd=session.stage/'repo',env=runenv,stdin=subprocess.DEVNULL)
    except Exception as e:
        out=read_json(session.receipt_path);out.update(status='FAILED',run_rc=None,reason='entry spawn failed: '+str(e));save_json(session.receipt_path,out);raise
    out=read_json(session.receipt_path);code=q.returncode
    relay=getattr(q,'signal_state',None);interruption_path=session.stage/'harness/out/interruption.json';interruption=None
    if interruption_path.exists():interruption=read_json(interruption_path)
    if relay and relay.get('signals'):
        interruption={'schema':'ct01-arp-interruption/1','number':relay['signals'][0]['number'],'signal':relay['signals'][0]['name'],'source':'launcher','received_signals':relay['signals']}
    elif interruption is None and code in (-2,-15,-1):
        interruption={'schema':'ct01-arp-interruption/1','number':-code,'signal':signal.Signals(-code).name,'source':'script exit signal'}
    if interruption is not None:
        require(interruption.get('schema')=='ct01-arp-interruption/1' and type(interruption.get('number')) is int and interruption['number'] in (1,2,15),'invalid interruption record')
        code=128+interruption['number'];out['interruption']=interruption;out['reason']='interrupted by '+interruption['signal']+'; script was awaited, no launcher SIGKILL'
    cleanup_path=session.stage/'harness/out/cleanup-status.json'
    if cleanup_path.exists():out['cleanup']=read_json(cleanup_path)
    if code==0 and (out.get('status')!='ACTIVE' or [e.get('phase') for e in out.get('events',[])]!=['ENTRY','SETUP','ARM','MIPS'] or not all(e.get('ok') is True for e in out.get('events',[]))):
        code=2;out['reason']='run exit0 without complete successful launch checkpoints'
    out.update(status='INTERRUPTED' if interruption is not None else 'FINISHED' if code==0 else 'FAILED',run_rc=q.returncode,launcher_rc=code,output_path=str(session.stage/'harness/out'));save_json(session.receipt_path,out);return code,out

def checkpoint_entry(receipt,phase,**dependencies):
    path=P(receipt);trust=dependencies.get('trust',trust_runtime);clock=dependencies.get('clock',time.time);trust(path);r=read_json(path)
    require(path==P(r.get('stage',''))/'launch-receipt.json' and r.get('schema')=='ct01-arp-launch-receipt/1','receipt path/schema mismatch')
    try:return Session(path.parent,r['manifest_sha256'],**dependencies).checkpoint(phase)
    except Exception as e:
        # Pin/import failure occurs before Session.checkpoint can record an event; preserve it using stdlib only.
        current=read_json(path)
        if not (current.get('status')=='STOPPED' and current.get('events') and current['events'][-1].get('phase')==phase and current['events'][-1].get('ok') is False):
            require(isinstance(current.get('events'),list),'invalid receipt events')
            current['events'].append({'phase':phase,'ok':False,'checked_at':clock(),'reason':type(e).__name__+': '+str(e)});current['status']='STOPPED';save_json(path,current)
        raise

def main(argv):
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='mode',required=True)
    for mode in ('collect','launch'):
        a=sub.add_parser(mode);a.add_argument('stage');a.add_argument('manifest_sha')
        if mode=='launch':a.add_argument('context');a.add_argument('context_sha')
    a=sub.add_parser('checkpoint');a.add_argument('receipt');a.add_argument('phase')
    args=parser.parse_args(argv)
    try:
        require(os.geteuid()==0,'root launcher required; offline fixtures must not invoke production CLI')
        if args.mode=='checkpoint':
            out=checkpoint_entry(args.receipt,args.phase)
        elif args.mode=='collect':out=collect(P(args.stage),args.manifest_sha)
        else:
            code,out=launch(P(args.stage),args.manifest_sha,args.context,args.context_sha);print(json.dumps(out,ensure_ascii=True,allow_nan=False));return code
        print(json.dumps(out,ensure_ascii=True,allow_nan=False));return 0
    except Exception as e:
        print(json.dumps({'schema':'ct01-arp-launch-error/1','status':'REJECTED','reason':type(e).__name__+': '+str(e),'guest_authorized':False},ensure_ascii=True,allow_nan=False));return 2
if __name__=='__main__':sys.exit(main(sys.argv[1:]))
