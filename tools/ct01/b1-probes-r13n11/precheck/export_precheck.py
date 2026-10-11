#!/usr/bin/env python3
"""USER export/evaluate only. Creates a fresh destination, no pipeline. Current mode requires coordinator context.
Production producer is pinned sudo tar READ ONLY on a fixed root stage. Never run during offline tests.
Exit 0/1/2/3 mirrors evaluator, 4 export failure, 5 result-output error. Evidence is retained, never cleaned recursively.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
HERE=os.path.dirname(os.path.abspath(__file__));sys.path.insert(0,HERE)
import collector as C
import evaluate_precheck as E
import nft_policy as NFT

def runner(argv,stdout_file,stderr_file):
    with open(stdout_file,'wb') as out,open(stderr_file,'wb') as err:
        p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=dict(C.ENV),timeout=120)
    return p.returncode

def check_archive(path):
    """Refuse links/devices/absolute/traversal paths before invoking tar extractor in the fresh user tree."""
    seen=set()
    with tarfile.open(path,'r:') as arc:
        for m in arc:
            name=m.name.rstrip('/')
            if name in seen or not (name=='out' and m.isdir() or re.fullmatch(r'out/(?:reads\.json|\d{2}-[A-Za-z0-9-]+\.(?:stdout|stderr))',name) and m.isfile()):
                raise ValueError('archive member not a unique regular collector output: '+repr(m.name))
            seen.add(name)
    if 'out/reads.json' not in seen:raise ValueError('archive missing out/reads.json')

def verify_evaluation(result,doc,args,rc,reads_sha256,mode):
    """Bind verdict, invocation, policy and channel hashes to THIS exported collection.
    The evaluator remains trusted reviewed code; metadata from input cannot authorize references.
    """
    if not isinstance(result,dict) or result.get('reads_sha256')!=reads_sha256:
        raise ValueError('evaluation result does not bind new exported input')
    meta=doc.get('meta',{});collection=result.get('collection')
    if not isinstance(collection,dict) or any(collection.get(k)!=meta.get(k) for k in ('run_id','root_source','collector_sha256','host','t_start','t_end')):
        raise ValueError('result collection binding mismatch')
    if result.get('schema')!=E.RESULT_SCHEMA:raise ValueError('evaluation result schema mismatch')
    if result.get('evaluator_argv')!=[os.path.abspath(E.__file__),*args]:raise ValueError('evaluator argv binding mismatch')
    if result.get('mode')!=mode or type(result.get('current_ready')) is not bool:
        raise ValueError('evaluation mode/readiness schema mismatch')
    if result.get('verdict') not in E.EXIT or E.EXIT[result['verdict']]!=rc:
        raise ValueError('evaluator exit/verdict mismatch')
    if result['current_ready'] and (mode!='current' or result['verdict']!='PASS'):
        raise ValueError('current readiness contradicts mode/verdict')
    if result.get('policy_version')!=NFT.POLICY_VERSION or result.get('reference_set_version')!=NFT.SET_VERSION:
        raise ValueError('result policy/reference-set version mismatch')
    nt=result.get('nft_policy')
    if nt is None:
        if result['verdict']=='PASS':raise ValueError('PASS without nft policy evidence')
        return
    if not isinstance(nt,dict) or nt.get('policy_version')!=NFT.POLICY_VERSION or nt.get('reference_set_version')!=NFT.SET_VERSION:
        raise ValueError('nft policy/reference-set mismatch')
    if result['verdict']=='PASS' and nt.get('verdict')!='PASS':raise ValueError('PASS contradicts nft policy')
    if nt.get('verdict')=='PASS':
        nft=next((r for r in doc.get('reads',[]) if isinstance(r,dict) and r.get('name')=='nft-ruleset'),{})
        ident=nt.get('matched_reference')
        if ident not in NFT.REFERENCE_IDS:raise ValueError('matched reference not in pinned set')
        for channel in ('stdout','stderr'):
            text=nft.get(channel)
            if not isinstance(text,str) or nt.get(channel+'_sha256')!=hashlib.sha256(text.encode('utf-8')).hexdigest():
                raise ValueError('nft observed channel digest binding mismatch: '+channel)
            if nt[channel+'_sha256']!=NFT.PINS[ident+'.'+channel+'.txt']:
                raise ValueError('matched reference/channel digest mismatch')
        if not isinstance(nt.get('diagnostic'),dict) or nt['diagnostic'].get('verdict')!='PASS':
            raise ValueError('nft PASS without diagnostic PASS')
        if nt.get('policy_module_sha256')!=E.digest_file(NFT.__file__):raise ValueError('policy module hash mismatch')
        refs=nt.get('references')
        if not isinstance(refs,dict) or set(refs)!=set(NFT.PINS):raise ValueError('reference provenance incomplete')
        for name,pinned in NFT.PINS.items():
            entry=refs[name];path=str(NFT.HERE/'references'/name)
            if not isinstance(entry,dict) or entry.get('sha256')!=pinned or entry.get('expected_sha256')!=pinned or entry.get('path_raw')!=path or entry.get('path_resolved')!=os.path.realpath(path):
                raise ValueError('reference provenance binding mismatch: '+name)

def export_and_evaluate(root_source,run_id,parent,collector_hash,*,mode='historical',context=None,ruleset_ref=None,run=runner,evaluator=None):
    stage=tempfile.mkdtemp(prefix='ct01-precheck-export.',dir=parent)
    res={'schema':'ct01-precheck-export/2','destination':stage,'root_source':root_source,'run_id':run_id,'collector_sha256':collector_hash,
         'mode':mode,'policy_version':NFT.POLICY_VERSION,'reference_set_version':NFT.SET_VERSION,'status':'EXPORT_ERROR','producer_rc':None,'extractor_rc':None,'evaluator_called':False,'current_ready':False}
    rc=4
    try:
        if not re.fullmatch(r'/var/tmp/ct01-precheck\.[A-Za-z0-9]{8}/out',root_source):raise ValueError('root source must be fixed canonical root stage')
        if not re.fullmatch(r'[0-9a-f]{32}',run_id):raise ValueError('run identity invalid')
        if collector_hash!=E.digest_file(C.__file__):raise ValueError('collector hash must match reviewed local contract')
        if mode not in ('historical','current'):raise ValueError('mode invalid')
        if mode=='current' and not context:raise ValueError('current export requires approved collection context; no default window')
        archive=os.path.join(stage,'collection.tar');err=os.path.join(stage,'producer.stderr')
        producer=['/usr/bin/sudo','/usr/bin/tar','-C',os.path.dirname(root_source),'-cf','-','out'];res['producer_argv']=producer
        res['producer_rc']=run(producer,archive,err)
        if res['producer_rc']!=0:raise ValueError('producer failed; evaluator not called')
        check_archive(archive)
        extractor=['/usr/bin/tar','-xf',archive,'--no-same-owner','--no-same-permissions','-C',stage];res['extractor_argv']=extractor
        res['extractor_rc']=run(extractor,os.path.join(stage,'extractor.stdout'),os.path.join(stage,'extractor.stderr'))
        if res['extractor_rc']!=0:raise ValueError('extractor failed; evaluator not called')
        src=os.path.join(stage,'out');raw=open(os.path.join(src,'reads.json'),'rb').read();doc=C.strict_json(raw.decode())
        meta=doc.get('meta',{}) if isinstance(doc,dict) else {}
        for k,value in [('root_source',root_source),('run_id',run_id),('collector_sha256',collector_hash)]:
            if meta.get(k)!=value:raise ValueError('exported collection binding differs: '+k)
        res['reads_sha256']=hashlib.sha256(raw).hexdigest()
        args=[src,os.path.join(stage,'precheck-result.json'),'--mode',mode]
        if context:args+=['--context',context]
        if ruleset_ref:args+=['--ruleset-ref',ruleset_ref]
        res['evaluator_argv']=[os.path.abspath(E.__file__),*args];res['legacy_ruleset_ref_raw']=ruleset_ref or E.DEFAULT_RULESET_REF
        res['evaluator_called']=True;rc=(evaluator or E.main)(args)
        if rc not in (0,1,2,3):
            res.update(status='OUTPUT_ERROR' if rc==5 else 'EVALUATION_ERROR',evaluator_rc=rc);raise ValueError('evaluator failed to deliver usable result; do not use an old result')
        result=C.strict_json(open(os.path.join(stage,'precheck-result.json')).read())
        res['status']='EVALUATION_ERROR'
        verify_evaluation(result,doc,args,rc,res['reads_sha256'],mode)
        res.update(status='EVALUATED',evaluator_rc=rc,verdict=result.get('verdict'),current_ready=result.get('current_ready',False),
                   result_schema=result['schema'],policy_version=result['policy_version'],reference_set_version=result['reference_set_version'],nft_policy=result.get('nft_policy'),
                   precheck_result_sha256=E.digest_file(os.path.join(stage,'precheck-result.json')),evaluator_execution_model=result.get('execution_model'),evaluator_process_argv=result.get('process_argv'))
    except Exception as e:
        res.update(error=type(e).__name__+': '+str(e),current_ready=False);rc=5 if res['status']=='OUTPUT_ERROR' else 4
    try:E.atomic_json(os.path.join(stage,'export-result.json'),res)
    except Exception as e:
        res.update(status='OUTPUT_ERROR',error='export result write failed: '+str(e));rc=5
    print(json.dumps(res,ensure_ascii=True,allow_nan=False));return rc,res

def main(argv):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root-source',required=True);p.add_argument('--run-id',required=True)
    p.add_argument('--collector-sha256',required=True);p.add_argument('--dest-parent',required=True);p.add_argument('--mode',choices=['historical','current'],default='historical')
    p.add_argument('--context');p.add_argument('--ruleset-ref');a=p.parse_args(argv)
    if os.geteuid()==0:print('REFUSED: export/evaluate runs as normal user',file=sys.stderr);return 4
    try:return export_and_evaluate(a.root_source,a.run_id,a.dest_parent,a.collector_sha256,mode=a.mode,context=a.context,ruleset_ref=a.ruleset_ref)[0]
    except Exception as e:print('EXPORT_SETUP_ERROR: '+str(e),file=sys.stderr);return 4

if __name__=='__main__':sys.exit(main(sys.argv[1:]))
