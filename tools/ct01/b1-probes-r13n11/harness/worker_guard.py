"""Root-issued read-only use proof: final freshness check immediately before QEMU spawn.
Proof does not approve a run or prove host immutability. Root runtime/RO mount+trusted reviewed image are required.
"""
import json,math,os,re,time
COLLECTOR='8300562e055e9f900c1cd0e3cc46ae774e914fd132529ccdf75c318a1c6ab85e'
def require_use_proof(arch,path=None,launch_id=None,now=None):
    def fail(msg):raise RuntimeError('current launch proof rejected: '+msg)
    def pairs(rows):
        d={}
        for k,v in rows:
            if k in d:fail('duplicate JSON key')
            d[k]=v
        return d
    def bad(s):fail('nonfinite '+s)
    path=path or os.environ.get('CT01_USE_PROOF');launch_id=launch_id or os.environ.get('CT01_LAUNCH_ID');now=time.time() if now is None else now
    if not path or not re.fullmatch('[0-9a-f]{32}',launch_id or ''):fail('path/launch identity missing')
    with open(path,'rb') as f:d=json.loads(f.read(),object_pairs_hook=pairs,parse_constant=bad)
    keys={'schema','launch_id','phase','collection','reads_sha256','context_sha256','policy_version','reference_set_version','max_age_s','not_before','checked_at'}
    if not isinstance(d,dict) or set(d)!=keys or d['schema']!='ct01-arp-use-proof/1':fail('schema')
    if d['phase']!=arch or arch not in ('ARM','MIPS') or d['launch_id']!=launch_id:fail('architecture/launch mismatch')
    if d['policy_version']!='ct01-nft-exact-channels/1' or d['reference_set_version']!='ct01-nft-historical-4G-3G-MGR-MGR2-MGR3/4':fail('policy mismatch')
    for k in ('reads_sha256','context_sha256'):
        if not isinstance(d[k],str) or not re.fullmatch('[0-9a-f]{64}',d[k]):fail('digest schema')
    c=d['collection']
    if not isinstance(c,dict) or set(c)!={'run_id','root_source','collector_sha256','host','t_start','t_end'}:fail('collection schema')
    if not re.fullmatch('[0-9a-f]{32}',c.get('run_id','')) or not re.fullmatch(r'/var/tmp/ct01-precheck\.[A-Za-z0-9]{8}/out',c.get('root_source','')) or c.get('collector_sha256')!=COLLECTOR:fail('collection identity')
    if not isinstance(c['host'],str) or not c['host'] or any(0xd800<=ord(x)<=0xdfff for x in c['host']):fail('host schema')
    for v in (now,d['max_age_s'],d['not_before'],d['checked_at'],c['t_start'],c['t_end']):
        if not isinstance(v,(int,float)) or isinstance(v,bool) or not math.isfinite(v):fail('timestamp/window schema')
    if d['max_age_s']<=0 or not d['not_before']<=c['t_start']<=c['t_end']<=d['checked_at']<=now:fail('timestamp order')
    if now-c['t_start']>d['max_age_s']:fail('expired before QEMU spawn; no automatic extension')
    return {'launch_id':launch_id,'phase':arch,'checked_at':now,'age_s':now-c['t_start'],'max_age_s':d['max_age_s'],'context_sha256':d['context_sha256'],'reads_sha256':d['reads_sha256']}
