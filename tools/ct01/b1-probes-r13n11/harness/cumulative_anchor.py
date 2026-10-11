"""Candidate cumulative drain contract; requires independent review before operation.
All source snapshots retained. A cumulative-counter plateau is a candidate,
never PASS until original raw binding, stop/await, final stats and closed pcap agree.
"""
import copy
import capture_drain as B
POLICY='ct01-capture-drain-cumulative-anchor/1'
QUIET_S=.25
MIN_SNAPSHOTS=3

def observe(specs, backend, budget_s=10):
    B.validate_specs(specs)
    if not B.finite(budget_s) or not 0 < budget_s <= 10:raise B.Invalid('budget')
    start=backend.monotonic();deadline=start+budget_s
    result=dict(schema=B.SCHEMA,status='OPEN',policy_version=POLICY,budget_s=budget_s,elapsed_s=0,
                quiet_s=QUIET_S,min_snapshots=MIN_SNAPSHOTS,captures=[])
    for spec in specs:result['captures'].append(dict(spec=spec.copy(),ready=False,reason='deadline',snapshots=[],flushed=False,anchor_index=None,committed_elapsed_s=None))
    try:
        while backend.monotonic()<deadline:
            for row in result['captures']:
                if row['ready']:continue
                s=backend.snapshot(row['spec'],deadline);s['received_elapsed_s']=backend.monotonic()-start;old=row['snapshots'];previous=old[-1] if old else None;old.append(s)
                B.validate_snapshot(s,row['spec'])
                if previous and (s['sent_at']<previous['received_at'] or any(s[k]<previous[k] for k in ('C','R','D'))):raise B.Invalid('stats reversed/decreased')
                if s['D']!=0:raise B.Invalid('kernel drops')
                changed=previous is None or s['R']!=previous['R']
                if changed:row['anchor_index']=len(old)-1
                anchor=old[row['anchor_index']]
                if len(old)-row['anchor_index']>=MIN_SNAPSHOTS and s['received_elapsed_s']-anchor['received_elapsed_s']>=QUIET_S and s['C']==s['R']:
                    row.update(ready=True,reason='candidate cumulative plateau; not PASS',committed_elapsed_s=backend.monotonic()-start)
            if all(r['ready'] for r in result['captures']):break
            backend.sleep(min(.05,max(0,deadline-backend.monotonic())))
        if backend.monotonic()>=deadline:
            for row in result['captures']:row.update(ready=False,reason='common deadline reached')
        for row in result['captures']:backend.flush(row['spec']);row['flushed']=True
        if all(r['ready'] and r['flushed'] for r in result['captures']):result['status']='PREPARED'
    except (Exception,KeyboardInterrupt) as e:
        result.update(status='UNKNOWN',error=f'{type(e).__name__}: {e}')
        for row in result['captures']:row.update(ready=False,reason=result['error'])
    result['elapsed_s']=backend.monotonic()-start
    return result

def finalize(observation,exit_rows,reader=B.regular_read,counter=B.count_pcap):
    """Validate the ENTIRE prefix, then reuse strict final proof on the anchored suffix.
    The original observation is returned intact; derived suffix is not a rewrite of evidence.
    """
    result=dict(schema=B.SCHEMA,policy_version=POLICY,status='UNKNOWN',observation=observation)
    try:
        if observation.get('policy_version')!=POLICY or observation.get('quiet_s')!=QUIET_S or observation.get('min_snapshots')!=MIN_SNAPSHOTS:raise B.Invalid('cumulative policy mismatch')
        B.validate_specs([row['spec'] for row in observation['captures']])
        derived=copy.deepcopy(observation)
        for i,row in enumerate(observation['captures']):
            spec=row['spec'];snaps=row['snapshots'];raw,ident=reader(spec['stderr']);last=None
            if len(snaps)<2:raise B.Invalid('missing snapshots')
            for s in snaps:
                B.validate_snapshot(s,spec)
                elapsed=s.get('received_elapsed_s')
                if not B.finite(elapsed) or not 0<=elapsed<=observation['elapsed_s']:raise B.Invalid('snapshot monotonic time')
                if last and elapsed<last['received_elapsed_s']:raise B.Invalid('snapshot monotonic reversal')
                if s['D']!=0:raise B.Invalid('drops anywhere in original history')
                if s['source_identity']!=ident or s['process_identity']!=snaps[0]['process_identity']:raise B.Invalid('history identity')
                a,b=s['start_offset'],s['offset']
                if b>len(raw) or B.digest(raw[a:b])!=s['raw_sha256'] or B.digest(raw[:b])!=s['prefix_sha256']:raise B.Invalid('history raw binding')
                if B.parse_snapshot(raw[a:b])!={k:s[k] for k in ('C','R','D')}:raise B.Invalid('history stats values')
                if last and (a!=last['offset'] or s['sent_at']<last['received_at'] or any(s[k]<last[k] for k in ('C','R','D'))):raise B.Invalid('history continuity/order/counter decrease')
                last=s
            if observation['status']!='PREPARED' or not row['ready']:
                continue
            idx=row['anchor_index'];commit=row['committed_elapsed_s']
            if type(idx) is not int or not 0<=idx<len(snaps) or not B.finite(commit) or not snaps[-1]['received_elapsed_s']<=commit<observation['budget_s'] or commit>observation['elapsed_s']:raise B.Invalid('invalid/late anchor')
            suffix=snaps[idx:]
            # Earliest point in this observed R plateau, not arbitrarily the last pair.
            if idx and snaps[idx-1]['R']==suffix[0]['R']:raise B.Invalid('anchor does not start plateau')
            if len(suffix)<MIN_SNAPSHOTS or suffix[-1]['received_elapsed_s']-suffix[0]['received_elapsed_s']<QUIET_S:raise B.Invalid('plateau observation missing')
            if any(s['R']!=suffix[0]['R'] for s in suffix) or suffix[-1]['C']!=suffix[-1]['R']:raise B.Invalid('plateau R/gap')
            derived['captures'][i]['snapshots']=suffix
        final=B._finalize_legacy(derived if observation['status']=='PREPARED' else observation,exit_rows,reader,counter)
        result.update(status=final['status'],captures=final.get('captures', []),final_proof=final)
    except Exception as e:result.update(status='UNKNOWN',error=f'{type(e).__name__}: {e}')
    return result
