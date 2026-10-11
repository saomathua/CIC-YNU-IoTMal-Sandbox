#!/usr/bin/env python3
"""Offline exact-channel policy tests: saved historical references and saved export only. No production exporter."""
import pathlib,sys,json,shutil,hashlib,copy,tempfile,subprocess,argparse
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import collector as C,evaluate_precheck as E,export_precheck as X
REAL=pathlib.Path('/home/dathq/projects/ct01-06b4ir3r1-historical-exports/ct01-precheck-export.wihhhkqd');TESTS={};DETAILS={}
def t(n,ok,detail):TESTS[n]=ok is True;DETAILS[n]=detail;print(('PASS ' if TESTS[n] else 'FAIL ')+n)
def main(argv):
 ap=argparse.ArgumentParser();ap.add_argument('--json');a=ap.parse_args(argv)
 with tempfile.TemporaryDirectory(prefix='nft-policy-offline.') as tmp:
  root=pathlib.Path(tmp);doc=json.loads((REAL/'out/reads.json').read_text());legacy=(HERE/'references/4G.source.txt').read_text();std4=(HERE/'references/4G.stdout.txt').read_text();std3=(HERE/'references/3G.stdout.txt').read_text();stdm2=(HERE/'references/MGR2.stdout.txt').read_text();stdm=(HERE/'references/MGR.stdout.txt').read_text();stdm3=(HERE/'references/MGR3.stdout.txt').read_text();diag=(HERE/'references/4G.stderr.txt').read_text()
  def run(n,stdout=std4,stderr=diag,change=None,extra=()):
   src=root/n;shutil.copytree(REAL/'out',src);d=copy.deepcopy(doc);r=next(r for r in d['reads'] if r['name']=='nft-ruleset');r.update(stdout=stdout,stderr=stderr)
   if change:change(d)
   for r in d['reads']:
    if isinstance(r,dict):
     for field in ('stdout','stderr'):
      if isinstance(r.get(field),str):(src/r[field+'_file']).write_bytes(r[field].encode('utf-8',errors='surrogatepass'))
   (src/'reads.json').write_text(json.dumps(d,ensure_ascii=True));before={str(p):p.read_bytes() for p in src.iterdir() if p.is_file()};dst=root/(n+'.result.json');dst.write_text('{"verdict":"PASS","evaluation_id":"OLD"}')
   p=subprocess.run([sys.executable,'-I','-B',str(HERE/'evaluate_precheck.py'),str(src),str(dst),*extra],capture_output=True,text=True,timeout=20)
   result=json.loads(dst.read_text()) if dst.exists() else {};same=all(pathlib.Path(n).read_bytes()==b for n,b in before.items());return p,result,same
  for name,stdout in [('4G',std4),('3G',std3),('MGR',stdm),('MGR2',stdm2),('MGR3',stdm3)]:
   p,r,same=run('clean-'+name,stdout);nt=r.get('nft_policy',{})
   t('clean-'+name,p.returncode==0 and r.get('verdict')=='PASS' and not r.get('current_ready') and nt.get('matched_reference')==name and nt.get('reference_set_version')=='ct01-nft-historical-4G-3G-MGR-MGR2-MGR3/4' and nt.get('diagnostic',{}).get('verdict')=='PASS' and same,{'rc':p.returncode,'verdict':r.get('verdict'),'policy':nt})
   t('legacy-4G-separate-'+name,nt.get('strict_4g_channels',{}).get('verdict')==('PASS' if name=='4G' else 'FAIL') and nt.get('legacy_4g_merged_text',{}).get('verdict')=='FAIL',nt)
   t('argv-provenance-'+name,r.get('evaluator_argv')==[str(HERE/'evaluate_precheck.py'),str(root/('clean-'+name)),str(root/('clean-'+name+'.result.json'))] and nt.get('stdout_sha256')==hashlib.sha256(stdout.encode()).hexdigest() and nt.get('stderr_sha256')==hashlib.sha256(diag.encode()).hexdigest(),r.get('evaluator_argv'))
  # R13N10: the new reference accepts ONLY its exact bytes. Variants are derived from MGR3 itself.
  assert stdm3.count('172.18.0.2')==3 and stdm3.count('172.18.0.3')==1 and stdm.count('172.18.0.2')==1 and stdm.count('172.18.0.3')==3
  mgr3={
   'mgr3-ip-outside-set':stdm3.replace('172.18.0.2','172.18.0.9'),
   'mgr3-ip-wildcard-like':stdm3.replace('dnat to 172.18.0.2:8011','dnat to 172.18.0.0:8011',1),
   'mgr3-mixed-old-new-ip':stdm3.replace('dnat to 172.18.0.2:8011','dnat to 172.18.0.3:8011',1),
   'mgr3-dport':stdm3.replace('tcp dport 8011 counter accept','tcp dport 8012 counter accept',1),
   'mgr3-dnat-port':stdm3.replace('dnat to 172.18.0.2:8011','dnat to 172.18.0.2:8012',1),
   'mgr3-verdict':stdm3.replace('tcp dport 8011 counter accept','tcp dport 8011 counter drop',1),
   'mgr3-interface':stdm3.replace('iifname != "br-09fed07bbb6b" oifname "br-09fed07bbb6b" tcp dport 8011','iifname != "br-1d86fe3e8bbe" oifname "br-09fed07bbb6b" tcp dport 8011',1),
   'mgr3-missing-rule':stdm3.replace('\t\tip daddr 192.168.60.10 iifname != "br-1d86fe3e8bbe" counter drop\n','',1),
   'mgr3-extra-rule':stdm3.replace('\t\tip daddr 127.0.0.1 iifname != "lo" tcp dport 8011 counter drop\n','\t\tip daddr 127.0.0.1 iifname != "lo" tcp dport 8011 counter drop\n\t\tcounter accept\n',1),
  }
  for n,text in mgr3.items():
   assert text!=stdm3,n;p,r,same=run(n,text);nt=r.get('nft_policy',{})
   t('reject-'+n,p.returncode==1 and r.get('verdict')=='FAIL' and nt.get('matched_reference') is None and not r.get('current_ready') and same and 'Traceback' not in p.stderr,{'rc':p.returncode,'verdict':r.get('verdict'),'policy':nt})
  for n,(so,se) in {'mgr3-stdout-with-changed-stderr':(stdm3,diag.replace('do not touch!','changed!')),'mgr3-stdout-without-stderr':(stdm3,''),
                    'mgr3-stdout-with-extra-warning':(stdm3,diag+'# Warning: unknown\n'),'old-mgr-stdout-with-changed-stderr':(stdm,diag.replace('do not touch!','changed!'))}.items():
   p,r,same=run(n,so,stderr=se);nt=r.get('nft_policy',{});t('reject-'+n,p.returncode==1 and r.get('verdict')=='FAIL' and nt.get('matched_reference') is None and nt.get('diagnostic',{}).get('verdict')=='FAIL' and same,{'rc':p.returncode,'policy':nt})
  # every older reference still carries its own identity (no alias to MGR3)
  for name,stdout in (('MGR',stdm),('MGR2',stdm2)):
   p,r,same=run('still-'+name,stdout);t('older-reference-not-aliased-'+name,r.get('nft_policy',{}).get('matched_reference')==name and r.get('nft_policy',{}).get('candidates',{}).get('MGR3',{}).get('stdout_exact') is False,r.get('nft_policy',{}).get('matched_reference'))
  variants={
   'add-rule':std4.replace('\tchain DOCKER {\n','\tchain DOCKER {\n\t\tcounter accept\n',1),
   'remove-rule':std4.replace('\t\tct state impossible\n',''),
   'change-rule':std4.replace('192.168.60.0/24','192.168.61.0/24',1),
   'policy':std4.replace('policy drop;','policy accept;',1),
   'hook':std4.replace('hook forward','hook input',1),
   'priority':std4.replace('priority filter','priority 1',1),
   'action':std4.replace('counter drop','counter accept',1),
   'unknown-comment':std4+'# unapproved extra\n',
   'whitespace':std4.replace('\tchain','  chain',1),
   'crlf':std4.replace('\n','\r\n'),
   'table-name':std4.replace('table ip raw','table ip unexpected'),
   'chain-name':std4.replace('chain DOCKER-USER','chain UNEXPECTED',1),
   'malformed-nft':'malformed payload\n',
  }
  # New order beyond both snapshots: move docker0 masquerade after the other two rules.
  ls=std4.splitlines(keepends=True);idx=next(i for i,l in enumerate(ls) if 'ip saddr 172.17.0.0/16' in l);ls[idx:idx+3]=ls[idx+1:idx+3]+[ls[idx]];variants['third-order']=''.join(ls)
  line=next(l for l in std4.splitlines(keepends=True) if 'counter drop' in l);variants['remove-rule']=std4.replace(line,'',1)
  # Preserve block bytes but move entire table or chain.
  marker='table ip filter {';pos=std4.index(marker);end=std4.index('table ip6 nat {');variants['table-order']=std4[pos:end]+std4[:pos]+std4[end:]
  block='\tchain DOCKER-USER {\n\t}\n';variants['chain-order']=std4.replace(block,'',1).replace('table ip filter {\n','table ip filter {\n'+block,1)
  for n,text in variants.items():
   assert text!=std4,n;p,r,same=run(n,text);t('reject-'+n,p.returncode in (1,2,3) and r.get('verdict')!='PASS' and not r.get('current_ready') and same and 'Traceback' not in p.stderr,{'rc':p.returncode,'verdict':r.get('verdict'),'policy':r.get('nft_policy')})
  for n,err in [('missing-warning',''.join(diag.splitlines(keepends=True)[1:])),('no-diagnostics',''),('extra-warning',diag+'# Warning: unknown\n'),('changed-warning',diag.replace('do not touch!','changed!')),('diagnostic-order',''.join(reversed(diag.splitlines(keepends=True))))]:
   p,r,same=run(n,stderr=err);nt=r.get('nft_policy',{});t('reject-'+n,p.returncode==1 and r.get('verdict')=='FAIL' and nt.get('diagnostic',{}).get('verdict')=='FAIL' and not r.get('current_ready') and same,{'rc':p.returncode,'policy':nt})
  for n,change in [('schema',lambda d:d['reads'][0].__setitem__('rc',True)),('surrogate',lambda d:d['meta'].__setitem__('host','\ud800')),('nonfinite',lambda d:d.__setitem__('extra',{'deep':[float('inf')]}))]:
   p,r,same=run(n,change=change);t('reject-'+n,p.returncode==3 and r.get('verdict')=='UNUSABLE' and same and 'Traceback' not in p.stderr,{'rc':p.returncode,'verdict':r.get('verdict')})
  p,r,same=run('nft-record-malformed',change=lambda d:next(r for r in d['reads'] if r['name']=='nft-ruleset').__setitem__('stderr',None))
  t('reject-nft-record-malformed',p.returncode==3 and r.get('verdict')=='UNUSABLE' and same,{'rc':p.returncode,'verdict':r.get('verdict')})
  # Supplied reference path cannot extend policy, even if payload declares it approved.
  fake=root/'unapproved-ref';fake.write_text(variants['add-rule']);p,r,same=run('self-approved',variants['add-rule'],change=lambda d:d['meta'].update(approved_reference=True,reference_set=[str(fake)],reference_sha256=hashlib.sha256(fake.read_bytes()).hexdigest()),extra=('--ruleset-ref',str(fake)))
  t('reject-self-approved-reference',p.returncode in (1,3) and r.get('verdict')!='PASS' and same,{'rc':p.returncode,'policy':r.get('nft_policy')})
  for n,content in [('ref-wrong-hash',legacy+'\n'),('ref-other-snapshot',(HERE/'references/3G.source.txt').read_text())]:
   ref=root/(n+'.reference');ref.write_text(content);p,r,same=run(n,extra=('--ruleset-ref',str(ref)));t('reject-'+n,p.returncode==3 and r.get('verdict')=='UNUSABLE' and same,{'rc':p.returncode,'policy':r.get('nft_policy')})
  p,r,same=run('meta-only-expansion',variants['third-order'],change=lambda d:d['meta'].update(approved_reference=True,reference_set_version='self-declared',reference_set=[variants['third-order']],reference_sha256=hashlib.sha256(variants['third-order'].encode()).hexdigest()))
  t('reject-meta-only-reference-expansion',p.returncode==1 and r.get('verdict')=='FAIL' and r.get('nft_policy',{}).get('reference_set_version')=='ct01-nft-historical-4G-3G-MGR-MGR2-MGR3/4' and same,{'rc':p.returncode,'policy':r.get('nft_policy')})
  original=root/'legacy-original';original.write_text(legacy);link=root/'legacy-link';link.symlink_to(original);p,r,same=run('legacy-provenance',extra=('--ruleset-ref',str(link)));entry=r.get('nft_policy',{}).get('legacy_4g_merged_text',{}).get('reference',{})
  t('legacy-path-raw-resolved-hash',p.returncode==0 and entry.get('path_raw')==str(link) and entry.get('path_resolved')==str(original.resolve()) and entry.get('sha256')==hashlib.sha256(legacy.encode()).hexdigest(),entry)
  cp=root/'protected-artifacts';shutil.copytree(HERE,cp,ignore=shutil.ignore_patterns('__pycache__'));target=cp/'references/3G.stdout.txt';before=target.read_bytes()
  proc=subprocess.run([sys.executable,'-I','-B',str(cp/'evaluate_precheck.py'),str(root/'clean-4G'),str(target)],capture_output=True,text=True,timeout=20)
  try:diag_result=json.loads(proc.stdout)
  except ValueError:diag_result={}
  t('protect-reference-output-alias',proc.returncode==5 and diag_result.get('verdict')=='OUTPUT_ERROR' and target.read_bytes()==before,{'rc':proc.returncode,'diagnostic':diag_result})
  # Exercise tampered pinned artifacts through real CLI on a copy; no original source edits.
  for n in ('4G.stdout.txt','3G.stderr.txt','MGR3.stdout.txt','MGR3.stderr.txt','provenance.json'):
   cp=root/('tamper-'+n);shutil.copytree(HERE,cp,ignore=shutil.ignore_patterns('__pycache__'));(cp/'references'/n).write_bytes((cp/'references'/n).read_bytes()+b'\n');src=root/'clean-4G';dst=root/('tampered-'+n+'.result.json')
   p=subprocess.run([sys.executable,'-I','-B',str(cp/'evaluate_precheck.py'),str(src),str(dst)],capture_output=True,text=True,timeout=20);r=json.loads(dst.read_text())
   t('reject-tampered-'+n,p.returncode==3 and r.get('verdict')=='UNUSABLE' and not r.get('current_ready') and 'Traceback' not in p.stderr,{'rc':p.returncode,'issues':r.get('issues')})
  # Integrity guard must block even when tampered reference and observed payload match each other.
  cp=root/'coupled-tamper';shutil.copytree(HERE,cp,ignore=shutil.ignore_patterns('__pycache__'));bad_stdout=std4+'\n';(cp/'references/4G.stdout.txt').write_text(bad_stdout)
  src=root/'coupled-payload';shutil.copytree(REAL/'out',src);cdoc=copy.deepcopy(doc);nr=next(r for r in cdoc['reads'] if r['name']=='nft-ruleset');nr.update(stdout=bad_stdout,stderr=diag);(src/nr['stdout_file']).write_text(bad_stdout);(src/nr['stderr_file']).write_text(diag);(src/'reads.json').write_text(json.dumps(cdoc));dst=root/'coupled-result.json'
  proc=subprocess.run([sys.executable,'-I','-B',str(cp/'evaluate_precheck.py'),str(src),str(dst)],capture_output=True,text=True,timeout=20);result=json.loads(dst.read_text())
  t('reject-coupled-tamper',proc.returncode==3 and result.get('verdict')=='UNUSABLE',{'rc':proc.returncode,'verdict':result.get('verdict'),'issues':result.get('issues')})
  # Exporter only uses fake producer on the saved archive; real user tar extracts to fresh toy destination.
  parent=root/'exports';parent.mkdir()
  def fake_run(argv,out,err):
   pathlib.Path(err).write_text('')
   if argv[0]=='/usr/bin/sudo':shutil.copyfile(REAL/'collection.tar',out);return 0
   return X.runner(argv,out,err) # user tar only; never producer
  actual_doc=json.loads((REAL/'out/reads.json').read_text())
  for n in ('clean','wrong-policy-version','wrong-reference-set','wrong-matched-reference','wrong-stream-digest','wrong-argv','wrong-schema','wrong-exit-verdict','wrong-collection','wrong-reference-provenance'):
   def evaluator(args,n=n):
    code=E.main(args)
    if n!='clean':
     dst=pathlib.Path(args[1]);r=json.loads(dst.read_text());nt=r.setdefault('nft_policy',{})
     if n=='wrong-policy-version':r['policy_version']='forged';nt['policy_version']='forged'
     if n=='wrong-reference-set':r['reference_set_version']='forged';nt['reference_set_version']='forged'
     if n=='wrong-matched-reference':nt['matched_reference']='4G'
     if n=='wrong-stream-digest':nt['stdout_sha256']='0'*64
     if n=='wrong-argv':r['evaluator_argv']=['other.py']
     if n=='wrong-schema':r['schema']='unexpected'
     if n=='wrong-exit-verdict':r['verdict']='FAIL'
     if n=='wrong-collection':r['collection']['run_id']='0'*32
     if n=='wrong-reference-provenance':nt['references']['3G.stdout.txt']['sha256']='0'*64
     dst.write_text(json.dumps(r))
    return code
   rc,result=X.export_and_evaluate(actual_doc['meta']['root_source'],actual_doc['meta']['run_id'],str(parent),hashlib.sha256((HERE/'collector.py').read_bytes()).hexdigest(),run=fake_run,evaluator=evaluator)
   dst=pathlib.Path(result['destination']);r=json.loads((dst/'precheck-result.json').read_text())
   if n=='clean':
    ok=rc==0 and result.get('nft_policy')==r.get('nft_policy') and result.get('evaluator_argv')==r.get('evaluator_argv') and result.get('precheck_result_sha256')==hashlib.sha256((dst/'precheck-result.json').read_bytes()).hexdigest() and result.get('nft_policy',{}).get('matched_reference')=='3G'
   else:ok=rc==4 and result.get('status')=='EVALUATION_ERROR' and not result.get('current_ready')
   t('export-'+n,ok,{'rc':rc,'status':result.get('status'),'error':result.get('error'),'policy':result.get('nft_policy')})
 if a.json:pathlib.Path(a.json).write_text(json.dumps({'tests':TESTS,'details':DETAILS},ensure_ascii=True,indent=2)+'\n')
 print('NFT-POLICY-SELFTEST:',sum(TESTS.values()),'/',len(TESTS));return 0 if all(TESTS.values()) else 1
if __name__=='__main__':sys.exit(main(sys.argv[1:]))
