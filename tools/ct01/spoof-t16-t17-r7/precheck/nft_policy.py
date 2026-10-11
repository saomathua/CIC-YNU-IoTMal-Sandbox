#!/usr/bin/env python3
"""Candidate exact-byte NFT channel policy. Hardcoded historical references only; NO rule sorting/semantic comparison.
Reference metadata documents sources, never authorizes an extra snapshot. Awaiting independent review before operation.
"""
import pathlib,hashlib,json,difflib
HERE=pathlib.Path(__file__).resolve().parent
POLICY_VERSION='ct01-nft-exact-channels/1'
SET_VERSION='ct01-nft-historical-4G-3G-MGR-MGR2-MGR3/4'
REFERENCE_IDS=('4G','3G','MGR','MGR2','MGR3')
PINS={'4G.source.txt': 'a51d1c413ef6e5c62918778cba827f55c9ab3e558aaf36b982e77b2a38df636d', '4G.stdout.txt': '828ee67984253965b9aad35482dc0f5a3eca2fd18f19b7360a0e96b95de6ef94', '4G.stderr.txt': '7d41d9d93f1ef141dbc8f901a3f98f37d1bc8f5cf72d4c4ce8d17cc6e90cfa61', '3G.source.txt': 'dc51b3bec870e0b2685fa4eb9904c9d547ce0d7dc581d2935bf56143c1730db1', '3G.stdout.txt': '8aa127a290bf59fe2f334ea353111b68d7258b67df57d3c58d7de607518f59bd', '3G.stderr.txt': '7d41d9d93f1ef141dbc8f901a3f98f37d1bc8f5cf72d4c4ce8d17cc6e90cfa61', 'provenance.json': '338f169afcf81602a8cd54b1ba80a37eae7f37a118170b3146fa77ca83edc4ad', 'MGR.stdout.txt': '5fe6fd7f232e22e2b503348ec3e50c606f473ba124fecf84ec30b067f3de5d69', 'MGR.stderr.txt': '7d41d9d93f1ef141dbc8f901a3f98f37d1bc8f5cf72d4c4ce8d17cc6e90cfa61', 'MGR2.stdout.txt': 'de001830bc0e770ba345c8714c96ac34098f54ca1a0e5c5ad3ae50d30d140cb7', 'MGR2.stderr.txt': '7d41d9d93f1ef141dbc8f901a3f98f37d1bc8f5cf72d4c4ce8d17cc6e90cfa61', 'MGR3.stdout.txt': '4723a9b074a2afcbd2299b4e6c3c9b143f7f79eac12e86bf0ed6e83f152543bf', 'MGR3.stderr.txt': '7d41d9d93f1ef141dbc8f901a3f98f37d1bc8f5cf72d4c4ce8d17cc6e90cfa61'}
def digest(data):return hashlib.sha256(data).hexdigest()
def protected_paths():return [str(HERE/'references'/n) for n in PINS]
def difference(expected,actual,reference,channel):
    if actual is None:return None
    return ''.join(difflib.unified_diff(expected.decode('utf-8').splitlines(True),actual.decode('utf-8',errors='backslashreplace').splitlines(True),fromfile=reference+'/'+channel,tofile='observed/'+channel))
def compare(stdout,stderr,legacy_text=None,legacy_path=None):
    """Return provenance + issues. Preserve original bytes/order; both stdout and diagnostic must match exactly."""
    issues=[];data={};artifacts={}
    for name,pinned in PINS.items():
        path=HERE/'references'/name
        entry={'path_raw':str(path),'path_resolved':str(path.resolve()),'expected_sha256':pinned}
        try:
            raw=path.read_bytes();entry.update(sha256=digest(raw),size_bytes=len(raw))
            if entry['sha256']!=pinned:issues.append('pinned reference hash mismatch: '+name)
            else:data[name]=raw
        except OSError as e:entry['error']=str(e);issues.append('reference unreadable: '+name+': '+str(e))
        artifacts[name]=entry
    trace={'policy_version':POLICY_VERSION,'reference_set_version':SET_VERSION,'policy_module_sha256':digest(pathlib.Path(__file__).read_bytes()),
           'comparison':'exact-bytes-both-channels','reference_set_deployment':'pending independent review; not operational approval',
           'references':artifacts,'matched_reference':None,'stdout_sha256':None,'stderr_sha256':None,'stdout_size_bytes':None,'stderr_size_bytes':None,
           'diagnostic':{'verdict':'UNKNOWN','reason':'usable nft read required'},'verdict':'UNKNOWN','reason':'usable nft read required'}
    # Provenance is pinned along with artifacts. It is explanatory, not a source of candidate IDs or hashes.
    if 'provenance.json' in data:trace['historical_sources']=json.loads(data['provenance.json'])['references']
    legacy_raw=data.get('4G.source.txt');legacy_entry=dict(artifacts['4G.source.txt'])
    if legacy_path is not None:
        path=pathlib.Path(legacy_path);legacy_entry={'path_raw':str(path),'path_resolved':str(path.resolve()),'expected_sha256':PINS['4G.source.txt']}
        try:
            raw=path.read_bytes();legacy_entry.update(sha256=digest(raw),size_bytes=len(raw))
            if digest(raw)!=PINS['4G.source.txt']:issues.append('legacy reference override must be exact pinned 4G source')
            else:legacy_raw=raw
        except OSError as e:issues.append('legacy reference unreadable: '+str(e));legacy_entry['error']=str(e)
    elif legacy_text is not None:
        raw=legacy_text.encode('utf-8');legacy_entry={'kind':'API supplied text','sha256':digest(raw),'size_bytes':len(raw),'expected_sha256':PINS['4G.source.txt']}
        if digest(raw)!=PINS['4G.source.txt']:issues.append('legacy API reference must be exact pinned 4G source')
        else:legacy_raw=raw
    if isinstance(stdout,str):trace.update(stdout_sha256=digest(stdout.encode('utf-8')),stdout_size_bytes=len(stdout.encode('utf-8')))
    if isinstance(stderr,str):trace.update(stderr_sha256=digest(stderr.encode('utf-8')),stderr_size_bytes=len(stderr.encode('utf-8')))
    if issues:
        trace.update(verdict='UNUSABLE',reason='reference integrity/source validation failed',reference_issues=issues)
        trace['legacy_4g_merged_text']={'reference':legacy_entry,'verdict':'UNKNOWN','reason':'reference integrity failed'}
        trace['strict_4g_channels']={'verdict':'UNKNOWN','reason':'reference integrity failed'}
        return trace,issues
    out=stdout.encode('utf-8') if isinstance(stdout,str) else None
    err=stderr.encode('utf-8') if isinstance(stderr,str) else None
    if out is not None:trace.update(stdout_sha256=digest(out),stdout_size_bytes=len(out))
    if err is not None:trace.update(stderr_sha256=digest(err),stderr_size_bytes=len(err))
    diag_ok=err is not None and err==data['4G.stderr.txt']
    trace['diagnostic']={'verdict':'UNKNOWN' if err is None else 'PASS' if diag_ok else 'FAIL',
                         'reason':'usable stderr required' if err is None else 'exact three pinned warning lines, same bytes/order' if diag_ok else 'diagnostic missing/extra/changed/reordered',
                         'expected_sha256':PINS['4G.stderr.txt'],'diff':difference(data['4G.stderr.txt'],err,'4G','stderr')}
    candidates={}
    for ident in REFERENCE_IDS:
        expected=data[ident+'.stdout.txt'];stderr_expected=data[ident+'.stderr.txt']
        stdout_equal=out is not None and out==expected
        stderr_equal=err is not None and err==stderr_expected
        candidates[ident]={'stdout_exact':stdout_equal,'stderr_exact':stderr_equal,
                           'stdout_diff':difference(expected,out,ident,'stdout'),'stderr_diff':difference(stderr_expected,err,ident,'stderr')}
        if stdout_equal and stderr_equal:trace['matched_reference']=ident
    trace['candidates']=candidates
    known=out is not None and err is not None
    trace.update(verdict='UNKNOWN' if not known else 'PASS' if trace['matched_reference'] else 'FAIL',
                 reason='usable stdout/stderr required' if not known else 'exact match to '+trace['matched_reference'] if trace['matched_reference'] else 'stdout not in pinned set or diagnostic mismatch')
    c=candidates['4G'];trace['strict_4g_channels']={'verdict':'UNKNOWN' if not known else 'PASS' if c['stdout_exact'] and c['stderr_exact'] else 'FAIL',**c,
                                                'note':'diagnostic only; not the reference-set verdict'}
    trace['legacy_4g_merged_text']={'reference':legacy_entry,'comparison':'legacy merged-4G text versus observed stdout',
                                   'verdict':'UNKNOWN' if out is None else 'PASS' if out==legacy_raw else 'FAIL',
                                   'diff':difference(legacy_raw,out,'legacy-4G-merged','stdout'),
                                   'note':'explains old comparison only; does not rewrite the historical FAIL'}
    return trace,issues
