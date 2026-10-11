#!/usr/bin/env python3
"""Offline precheck evaluator. Historical PASS is a snapshot verdict, never current readiness.
Current mode needs an independently approved, exact collection context and approved age window.
Exit: PASS 0, FAIL 1, UNKNOWN 2, UNUSABLE 3, OUTPUT_ERROR 5. No guest authorization.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
import uuid
HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE)
import collector as C
import nft_policy as NFT
DEFAULT_RULESET_REF=os.path.join(HERE,'references','4G.source.txt')
RESULT_SCHEMA='ct01-precheck-result/3'
EXIT={'PASS':0,'FAIL':1,'UNKNOWN':2,'UNUSABLE':3,'OUTPUT_ERROR':5}

def digest_file(path):
    with open(path,'rb') as f:return hashlib.sha256(f.read()).hexdigest()

def item(items,title,status,required=True,**detail):
    items.append({'item':title,'status':status,'required':required,**detail})

def validate(doc,expected_hash=None):
    """Never repairs or mutates input. Do not collapse duplicate names before reporting them."""
    issues=[];reads={};payloads={};meta={}
    try:C.valid_json_values(doc)
    except ValueError as e:return ['invalid JSON value: '+str(e)],meta,reads,payloads
    def bad(msg):issues.append(msg)
    if not isinstance(doc,dict):return ['document must be object'],meta,reads,payloads
    if not isinstance(doc.get('meta'),dict):bad('meta must be object')
    else:meta=doc['meta']
    if meta.get('schema')!=C.SCHEMA:bad('unsupported collector schema (v2 provenance required)')
    for name in ('t_start','t_end'):
        if not C.finite_number(meta.get(name)):bad(name+' must be finite number')
    if C.finite_number(meta.get('t_start')) and C.finite_number(meta.get('t_end')) and meta['t_start']>meta['t_end']:bad('collection timestamps reversed')
    if not isinstance(meta.get('run_id'),str) or not re.fullmatch(r'[0-9a-f]{32}',meta['run_id']):bad('run_id must be uuid hex')
    if not isinstance(meta.get('root_source'),str) or not os.path.isabs(meta['root_source']) or os.path.normpath(meta['root_source'])!=meta['root_source']:bad('root_source must be canonical absolute path')
    if not isinstance(meta.get('host'),str) or not meta['host']:bad('host identity missing')
    if type(meta.get('execution_uid')) is not int or meta['execution_uid']<0:bad('execution_uid invalid')
    ch=meta.get('collector_sha256')
    if not isinstance(ch,str) or not re.fullmatch(r'[0-9a-f]{64}',ch):bad('collector hash invalid')
    elif ch!=(expected_hash or digest_file(C.__file__)):bad('collector hash does not match pinned contract source')
    expected_meta={'expected_image_id':C.EXPECTED_IMAGE_ID,'image':C.IMAGE,'manager':C.MANAGER,'mongo':C.MONGO,
                   'harness_containers':list(C.HARNESS_CONTAINERS),'bins':C.BINS,'env':C.ENV}
    for k,v in expected_meta.items():
        if meta.get(k)!=v:bad('source identity/contract mismatch: '+k)
    if type(meta.get('data_complete')) is not bool:bad('data_complete must be bool (informational)')
    if not isinstance(meta.get('networks_resolved'),dict):bad('networks_resolved must be object')
    rs=doc.get('reads')
    if not isinstance(rs,list):return issues+['reads must be list'],meta,reads,payloads
    contract=C.read_contract();expected_names=list(contract)
    for seq,r in enumerate(rs,1):
        if not isinstance(r,dict):bad(f'reads[{seq}] must be object');continue
        name=r.get('name')
        if not isinstance(name,str) or name not in contract:bad(f'reads[{seq}] name invalid/unknown');continue
        if name in reads:bad('duplicate read name: '+name);continue
        reads[name]=r
        valid=True
        def rb(msg):
            nonlocal valid
            valid=False;bad(name+': '+msg)
        expected_fields={'name','argv','required','rc','status','error','ok_rcs','stdout_file','stderr_file','stdout','stderr'}
        if set(r)!=expected_fields:rb('read field set differs from collector schema')
        for k in ('stdout','stderr','stdout_file','stderr_file','status'):
            if not isinstance(r.get(k),str):rb(k+' must be string')
        if type(r.get('required')) is not bool or r['required']!=(name not in C.OPTIONAL):rb('required inconsistent with contract')
        if not isinstance(r.get('ok_rcs'),list) or r['ok_rcs']!=C.accepted_rcs(name) or any(type(x) is not int for x in r['ok_rcs']):rb('ok_rcs inconsistent')
        for k,suffix in [('stdout_file','.stdout'),('stderr_file','.stderr')]:
            if r.get(k)!=f'{seq:02d}-{name}'+suffix:rb('raw file identity/order invalid: '+k)
        argv=r.get('argv');status=r.get('status');rc=r.get('rc');error=r.get('error')
        if argv is not None and (not isinstance(argv,list) or not argv or any(not isinstance(x,str) for x in argv)):rb('argv invalid')
        if rc is not None and type(rc) is not int:rb('rc must be integer or null')
        if error is not None and not isinstance(error,str):rb('error must be string or null')
        if status=='SKIPPED':
            if argv is not None or rc is not None or not isinstance(error,str) or not error or r.get('stdout')!='' or r.get('stderr')!='':rb('SKIPPED fields inconsistent')
        elif status=='OK':
            if type(rc) is not int or rc not in C.accepted_rcs(name) or error is not None:rb('OK contradicts rc/error')
        elif status=='NONZERO':
            if type(rc) is not int or rc in C.accepted_rcs(name) or error is not None:rb('NONZERO contradicts rc/error')
        elif status in ('TIMEOUT','EXEC_ERROR'):
            if rc is not None or not isinstance(error,str) or not error.startswith(status):rb('execution error fields inconsistent')
        elif status=='PAYLOAD_ERROR':
            if type(rc) is not int or rc not in C.accepted_rcs(name) or not isinstance(error,str) or not error:rb('PAYLOAD_ERROR fields inconsistent')
        else:rb('status unsupported')
        if valid and status in ('OK','PAYLOAD_ERROR'):
            try:p=C.parse_payload(name,r['stdout'],rc)
            except (ValueError,TypeError) as e:
                if status=='OK':bad(name+': malformed payload: '+str(e))
            else:
                if status=='PAYLOAD_ERROR':bad(name+': PAYLOAD_ERROR contradicts valid payload')
                else:payloads[name]=p
    missing=[n for n in expected_names if n not in reads]
    if missing:bad('required collection records missing: '+', '.join(missing))
    if list(reads)!=expected_names:bad('read order/name set does not match collector contract')
    ids={};resolved={};skip={}
    for net in C.NETWORK_LABELS:
        ls='network-ls-'+net;ins='network-inspect-'+net;r=reads.get(ls,{})
        if r.get('status')!='OK':skip[ins]='network list not usable: '+str(r.get('status'))
        elif ls not in payloads:continue
        elif len(payloads[ls])!=1:skip[ins]='network resolution requires exactly one row; got '+str(len(payloads[ls]))
        else:
            ident,name=payloads[ls][0];ids[net]=ident;resolved[net]=name
            p=payloads.get(ins)
            if p and (p['id']!=ident or p['name']!=name):bad(ins+': inspect identity differs from resolved list')
    if meta.get('networks_resolved')!=resolved:bad('networks_resolved contradicts valid network listings')
    manager=payloads.get('inspect-manager');running=manager and manager['state']=='running'
    for n in C.OPTIONAL:
        if not running:skip[n]='manager not running' if reads.get('inspect-manager',{}).get('status')=='OK' else 'manager state unknown: '+str(reads.get('inspect-manager',{}).get('status'))
    concrete=C.read_contract(ids)
    for n,r in reads.items():
        if n in skip:
            if r.get('status')!='SKIPPED' or r.get('error')!=skip[n]:bad(n+': skip contradicts collector branch')
        elif r.get('status')=='SKIPPED' or r.get('argv')!=concrete[n]:bad(n+': argv/branch contradicts collector command')
    # Recompute; meta never drives completeness. A lying flag is a contradiction, not a verdict source.
    complete=not missing and all(reads.get(n,{}).get('status')=='OK' and n in payloads for n in contract if n not in C.OPTIONAL)
    if type(meta.get('data_complete')) is bool and meta['data_complete']!=complete:bad('data_complete contradicts validated required reads')
    ps=payloads.get('ps-all')
    if ps is not None:
        for who,name in [('manager',C.MANAGER),('mongo',C.MONGO)]:
            p=payloads.get('inspect-'+who)
            if p and (name not in ps or ps[name]['id']!=p['id'] or ps[name]['state']!=p['state']):bad(who+': inspect identity/state contradicts ps listing')
    for who,net in [('manager','sandboxnet'),('mongo','dbnet')]:
        p=payloads.get('inspect-'+who)
        if p and net in resolved:
            n=p['networks'].get(resolved[net]);
            if n and n.get('NetworkID') and n['NetworkID']!=ids[net]:bad(who+': endpoint NetworkID contradicts network resolution')
    # Cross-read contradictions are measurement problems, never proof of a stable/absent endpoint.
    for who,net in [('manager','sandboxnet'),('mongo','dbnet')]:
        p=payloads.get('inspect-'+who);network=payloads.get('network-inspect-'+net)
        if p and network and p['state']=='running':
            ep=p['networks'].get(network['name']);seen=network['containers'].get(p['id'])
            expected_name=C.MANAGER if who=='manager' else C.MONGO
            if ep is None or seen is None or seen['Name']!=expected_name or seen['IPv4Address'].split('/')[0]!=ep['IPAddress'] or seen['MacAddress'].lower()!=ep['MacAddress'].lower():
                bad(who+': running endpoint contradicts network inspect')
    for net in C.NETWORK_LABELS:
        network=payloads.get('network-inspect-'+net)
        if network and ps is not None:
            for ident,endpoint in network['containers'].items():
                row=ps.get(endpoint['Name'])
                if row is None or row['id']!=ident:bad(net+': network container identity contradicts ps')
    return issues,meta,reads,payloads

def current_problem(meta,context,input_sha256,now):
    try:C.valid_json_values(context)
    except ValueError as e:return 'invalid context JSON value: '+str(e)
    if not isinstance(context,dict):return 'current mode requires independently approved collection context/window'
    if context.get('schema')!='ct01-precheck-context/1':return 'context schema invalid'
    for k in ('approved_by','approval_ref'):
        if not isinstance(context.get(k),str) or not context[k].strip():return 'coordinator approval missing: '+k
    for k in ('max_age_s','not_before','t_start','t_end'):
        if not C.finite_number(context.get(k)):return 'context '+k+' must be finite number'
    if context['max_age_s']<=0:return 'approved age window must be positive'
    for k in ('run_id','root_source','collector_sha256','host','t_start','t_end'):
        if context.get(k)!=meta.get(k):return 'context collection binding mismatch: '+k
    if not input_sha256 or context.get('reads_sha256')!=input_sha256:return 'context reads.json digest mismatch/missing'
    if meta.get('execution_uid')!=0 or not re.fullmatch(r'/var/tmp/ct01-precheck\.[A-Za-z0-9]{8}/out',meta.get('root_source','')):return 'current mode requires fixed root-stage source and root collector'
    if not C.finite_number(now):return 'evaluation time not finite'
    if meta['t_start']<context['not_before'] or meta['t_end']>now:return 'collection outside approved start/current time'
    if now-meta['t_start']>context['max_age_s']:return 'snapshot exceeds coordinator-approved age window'
    return None

def evaluate(reads_doc,ruleset_ref_text,endpoint_mac_problem=None,parse_neigh_full=None,*,mode='historical',context=None,input_sha256=None,now=None,expected_collector_sha256=None,legacy_reference_path=None):
    issues,meta,reads,payloads=validate(reads_doc,expected_collector_sha256);items=[]
    def get(n):return payloads.get(n) if reads.get(n,{}).get('status')=='OK' else None
    def unavailable(n):
        r=reads.get(n,{})
        return {'read':n,'status':r.get('status'),'rc':r.get('rc'),'reason':r.get('error') or ('read missing or failed/schema invalid' if get(n) is None else None),'stdout':r.get('stdout'),'stderr':r.get('stderr')}
    req=[n for n in C.read_contract() if n not in C.OPTIONAL]
    complete=all(get(n) is not None for n in req)
    item(items,'collector: validated required reads complete','PASS' if complete else 'UNKNOWN',failed=[unavailable(n) for n in req if get(n) is None])
    p=get('image-id');item(items,'image sandbox-worker:latest reviewed id','UNKNOWN' if p is None else 'PASS' if p==C.EXPECTED_IMAGE_ID else 'FAIL',raw=p,expected=C.EXPECTED_IMAGE_ID)
    ps=get('ps-all')
    for n in C.HARNESS_CONTAINERS:item(items,'harness container '+n+' absent','UNKNOWN' if ps is None else 'FAIL' if n in ps else 'PASS')
    for net in C.NETWORK_LABELS:
        ls=get('network-ls-'+net);p=get('network-inspect-'+net)
        ok=ls is not None and len(ls)==1 and p is not None
        if net=='sandboxnet' and ok:ok=any(c['Subnet']=='192.168.60.0/24' and c['Gateway']=='192.168.60.1' for c in p['ipam'])
        item(items,'network '+net+' resolved and inspected','UNKNOWN' if ls is None or len(ls)!=1 or p is None else 'PASS' if ok else 'FAIL')
    for who,net in [('manager','sandboxnet'),('mongo','dbnet')]:
        p=get('inspect-'+who);resolved=meta.get('networks_resolved',{});resolved=resolved if isinstance(resolved,dict) else {}
        if p is None:
            absent=ps is not None and (C.MANAGER if who=='manager' else C.MONGO) not in ps
            item(items,who+': readable state','FAIL' if absent else 'UNKNOWN',ps_presence='ABSENT' if absent else 'UNKNOWN or PRESENT',read_error=unavailable('inspect-'+who));continue
        if net not in resolved and (who=='mongo' or p['state']=='running'):
            item(items,who+': state/endpoint policy','UNKNOWN',reason='network resolution unavailable');continue
        if who=='manager':
            ok=p['state'] in ('running','exited')
            if p['state']=='running':
                ep=p['networks'].get(resolved.get(net,''),{});ok=ep.get('IPAddress')=='192.168.60.10' and C.endpoint_mac_problem(ep.get('MacAddress')) is None
        else:
            ep=p['networks'].get(resolved.get(net,''),{});ok=p['state']=='running' and bool(ep.get('IPAddress'))
        item(items,who+': state/endpoint policy','PASS' if ok else 'FAIL',raw=p)
    for n in ('pgrep-qemu','pgrep-capture'):
        p=get(n);item(items,n+': no process','UNKNOWN' if p is None else 'PASS' if reads[n]['rc']==1 else 'FAIL')
    nft=get('nft-ruleset');nft_record=reads.get('nft-ruleset',{})
    nft_trace,nft_issues=NFT.compare(nft,nft_record.get('stderr') if nft is not None else None,ruleset_ref_text,legacy_reference_path)
    issues.extend(nft_issues)
    item(items,'nft exact historical reference-set and diagnostic',nft_trace['verdict'] if nft_trace['verdict']!='UNUSABLE' else 'UNKNOWN',reason=nft_trace['reason'])
    item(items,'AppArmor status readable','PASS' if get('aa-status') is not None else 'UNKNOWN')
    problem=None
    if mode=='current':
        problem=current_problem(meta,context,input_sha256,time.time() if now is None else now) if not issues else 'collection validation failed'
        item(items,'current collection/context/approved freshness','UNKNOWN' if problem else 'PASS',reason=problem)
    elif mode!='historical':issues.append('mode unsupported')
    verdict='UNUSABLE' if issues else 'FAIL' if any(i['status']=='FAIL' for i in items) else 'UNKNOWN' if any(i['status']=='UNKNOWN' for i in items) else 'PASS'
    return {'schema':RESULT_SCHEMA,'verdict':verdict,'mode':mode,'current_ready':mode=='current' and verdict=='PASS','issues':issues,'items':items,
            'raw_input':json.dumps(reads_doc,ensure_ascii=True,default=repr),'collection':{k:(meta.get(k) if isinstance(meta.get(k),(str,int,float)) and (not isinstance(meta.get(k),float) or C.finite_number(meta[k])) else repr(meta.get(k))) for k in ('run_id','root_source','collector_sha256','host','t_start','t_end')},
            'nft_policy':nft_trace,'note':'snapshot only; never proof host stayed unchanged after collection; never guest authorization'}

def atomic_json(path,res):
    fd,tmp=tempfile.mkstemp(prefix='.precheck-result.',dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd,'w') as f:json.dump(res,f,indent=2,ensure_ascii=True,allow_nan=False);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def invalidate_result(dst,protected,source=None):
    """Check the whole evidence tree and inode aliases BEFORE touching an old output.
    Inputs are assumed quiescent during offline evaluation; this is not a concurrent-writer guarantee.
    """
    target=os.path.realpath(dst)
    protected=[p for p in protected if p]
    if source and os.path.isdir(source):
        root=os.path.realpath(source)
        if os.path.commonpath([root,target])==root:
            raise OSError('result must be outside the source evidence tree')
        def walk_error(error):raise error
        for directory,dirs,files in os.walk(source,followlinks=False,onerror=walk_error):
            protected.extend(os.path.join(directory,n) for n in files)
    try:target_stat=os.stat(dst)
    except FileNotFoundError:target_stat=None
    for p in protected:
        if target==os.path.realpath(p):raise OSError('result aliases a protected input')
        if target_stat is not None:
            try:input_stat=os.stat(p)
            except FileNotFoundError:continue
            if (target_stat.st_dev,target_stat.st_ino)==(input_stat.st_dev,input_stat.st_ino):
                raise OSError('result is a hardlink alias of protected evidence')
    try:st=os.lstat(dst)
    except FileNotFoundError:return
    if not stat.S_ISREG(st.st_mode):raise OSError('existing result is not a regular file; refusing symlink/directory')
    os.unlink(dst) # no stale PASS survives a later read/parse/validation failure if this directory is writable

def output_error(res,error,old_result_may_remain):
    """A fresh, safely encodable diagnostic, independent of serialization of a failed result."""
    diagnostic={k:res[k] for k in ('schema','evaluation_id','evaluated_at','mode')}
    diagnostic.update(verdict='OUTPUT_ERROR',current_ready=False,
                      error=ascii(error),old_result_may_remain=old_result_may_remain,
                      failed_result=ascii(res))
    print(json.dumps(diagnostic,ensure_ascii=True,allow_nan=False))
    print(diagnostic['error'],file=sys.stderr)
    return 5

def verify_raw_files(src,doc):
    problems=[]
    for r in doc.get('reads',[]) if isinstance(doc,dict) and isinstance(doc.get('reads'),list) else []:
        if not isinstance(r,dict):continue
        for field in ('stdout','stderr'):
            n=r.get(field+'_file')
            if not isinstance(n,str) or '/' in n or n in ('.','..'):problems.append('raw filename malformed');continue
            try:
                fd=os.open(os.path.join(src,n),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as f:
                    if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):raise OSError('raw output is not a regular file')
                    text=f.read().decode(errors='replace')
                if text!=r.get(field):problems.append(r.get('name','?')+': raw '+field+' contradicts reads.json')
            except OSError as e:problems.append('raw file unreadable '+n+': '+str(e))
    return problems

def main(argv):
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('src');ap.add_argument('dst');ap.add_argument('--ruleset-ref',default=DEFAULT_RULESET_REF)
    ap.add_argument('--mode',choices=['historical','current'],default='historical');ap.add_argument('--context');ap.add_argument('--harness',help='legacy informational argument; harness is never executed/imported')
    args=ap.parse_args(argv);eid=uuid.uuid4().hex;res={'schema':RESULT_SCHEMA,'evaluation_id':eid,'evaluated_at':time.time(),'mode':args.mode,'current_ready':False,'policy_version':NFT.POLICY_VERSION,'reference_set_version':NFT.SET_VERSION,'evaluator_argv':[os.path.abspath(__file__),*argv],'process_argv':list(getattr(sys,'orig_argv',sys.argv)),'execution_model':'cli' if __name__=='__main__' else 'in_process'}
    inputpath=os.path.join(args.src,'reads.json')
    try:invalidate_result(args.dst,[inputpath,args.context,args.ruleset_ref,*NFT.protected_paths()],args.src)
    except Exception as e:
        return output_error(res,'cannot invalidate old result: '+type(e).__name__+': '+str(e),True)
    raw=None
    try:
        res['nft_policy']=NFT.compare(None,None,legacy_path=args.ruleset_ref)[0]
        with open(inputpath,'rb') as f:raw=f.read()
        sha=hashlib.sha256(raw).hexdigest();doc=C.strict_json(raw.decode('utf-8'))
        context=C.strict_json(open(args.context).read()) if args.context else None
        evaluated=evaluate(doc,None,mode=args.mode,context=context,input_sha256=sha,legacy_reference_path=args.ruleset_ref)
        problems=verify_raw_files(args.src,doc)
        if problems:evaluated['issues']+=problems;evaluated['verdict']='UNUSABLE';evaluated['current_ready']=False
        res.update(evaluated,reads_sha256=sha,collector_output=os.path.abspath(args.src))
    except Exception as e:
        res.update(verdict='UNUSABLE',error=type(e).__name__+': '+str(e),raw_input=None if raw is None else raw.decode(errors='replace'))
    try:atomic_json(args.dst,res)
    except Exception as e:
        return output_error(res,'cannot write new result: '+type(e).__name__+': '+str(e),False)
    print('PRECHECK '+args.mode.upper()+' VERDICT: '+res['verdict']+'; current_ready='+str(res.get('current_ready',False)))
    return EXIT[res['verdict']]

if __name__=='__main__':sys.exit(main(sys.argv[1:]))
