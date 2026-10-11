#!/usr/bin/env python3
"""Bounded tcpdump drain observation; finalize only after parent's stop/await.
No guest commands. PREPARED is never PASS. Parent owns captures and watcher.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import time

SCHEMA='ct01-capture-drain/1'
class Invalid(ValueError): pass

def finite(x): return type(x) in (int,float) and math.isfinite(x)
def digest(b): return hashlib.sha256(b).hexdigest()
def parse_stats(raw):
    # Exactly one complete block, never last-value selection or missing -> zero.
    m=re.fullmatch(rb'\s*(\d+) packets? captured\n(\d+) packets? received by filter\n(\d+) packets? dropped by kernel\s*',raw)
    if not m: raise Invalid('missing/mixed/malformed statistics block')
    return dict(zip(('C','R','D'),map(int,m.groups())))

# R7: tcpdump 4.99.4 answers SIGUSR1 with ONE line on stderr ("tcpdump: C packets captured, R packets received by filter, D packets dropped by
# kernel", observed in the stderr of launch 8fb528de); the three-line block is what it prints on exit. A snapshot (reply to a request) is exactly one
# complete line of the first form, or exactly one complete three-line block; anything else is not a snapshot. The final (exit) statistics stay
# three-line only (parse_stats).
SNAPSHOT_LINE=re.compile(rb'tcpdump: (\d+) packets? captured, (\d+) packets? received by filter, (\d+) packets? dropped by kernel\n')
def parse_snapshot(raw):
    m=SNAPSHOT_LINE.fullmatch(raw)
    if m: return dict(zip(('C','R','D'),map(int,m.groups())))
    if not raw.endswith(b'\n'): raise Invalid('statistics reply is not complete (no final newline)')
    return parse_stats(raw)

def regular_read(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode): raise Invalid('source is not regular file')
        with os.fdopen(fd,'rb',closefd=False) as f: b=f.read(1048577)
        if len(b)>1048576: raise Invalid('stderr exceeds 1 MiB limit')
        return b,[s.st_dev,s.st_ino]
    finally: os.close(fd)

def process_identity(spec):
    p=spec['pid']; base=Path('/proc')/str(p)
    s=(base/'stat').read_text().rsplit(')',1)[1].split()
    if s[0] in ('Z','X'): raise Invalid('capture dead')
    exe=os.readlink(base/'exe')
    args=(base/'cmdline').read_bytes().split(b'\0')
    if Path(exe).name!='tcpdump' or args.count(b'-i')!=1: raise Invalid('PID is not configured tcpdump')
    if args[args.index(b'-i')+1]!=spec['interface'].encode(): raise Invalid('PID interface mismatch')
    if args.count(b'-w')!=1 or args[args.index(b'-w')+1]!=b'-': raise Invalid('capture writer mismatch')
    return f'{p}:{s[19]}:{exe}'  # /proc stat field22 starttime, after comm

def signal_caught(pid, signum):
    """R5 (integration-time addition): SIGUSR1/SIGUSR2 terminate a process that has no handler. Send them only to a process whose
    /proc/PID/status says the signal is caught and not ignored; otherwise refuse (nothing is sent, nothing is killed)."""
    mask=1<<(signum-1); caught=ignored=None
    for line in (Path('/proc')/str(pid)/'status').read_text().splitlines():
        if line.startswith('SigCgt:'): caught=int(line.split()[1],16)
        elif line.startswith('SigIgn:'): ignored=int(line.split()[1],16)
    if caught is None or ignored is None: raise Invalid('signal disposition unreadable')
    if not caught&mask or ignored&mask: raise Invalid(f'capture does not catch {signal.Signals(signum).name}: not signalled')

class Live:
    monotonic=staticmethod(time.monotonic)
    sleep=staticmethod(time.sleep)
    def __init__(self): self.state={}
    def snapshot(self,spec,deadline):
        key=spec['name']; token=process_identity(spec)
        data,identity=regular_read(spec['stderr'])
        if key not in self.state:
            listens=re.findall(rb'^(?:tcpdump: )?listening on ([^,\s]+)',data,re.M)
            if listens!=[spec['interface'].encode()] or re.search(rb'\d+ packets? (captured|received by filter|dropped by kernel)',data):
                raise Invalid('startup interface missing/ambiguous or stale statistics')
            self.state[key]=(identity,token,len(data),digest(data))
        ident,oldtoken,offset,prefixhash=self.state[key]
        if identity!=ident or token!=oldtoken or digest(data[:offset])!=prefixhash or len(data)!=offset:
            raise Invalid('source changed or unsolicited statistics before request')
        signal_caught(spec['pid'],signal.SIGUSR1)
        sent=time.time(); os.kill(spec['pid'],signal.SIGUSR1)
        while self.monotonic()<deadline:
            if process_identity(spec)!=token: raise Invalid('capture PID changed')
            data,identity=regular_read(spec['stderr'])
            if identity!=ident or digest(data[:offset])!=prefixhash: raise Invalid('stderr replaced/rewritten')
            raw=data[offset:]
            if len(raw)>65536: raise Invalid('statistics segment too large')
            try: values=parse_snapshot(raw)
            except Invalid:
                # Incomplete output can arrive in several writes; no snapshot until complete.
                self.sleep(min(.02,max(0,deadline-self.monotonic()))); continue
            received=time.time()
            end=len(data)
            self.state[key]=(ident,token,end,digest(data))
            return dict(values,pid=spec['pid'],interface=spec['interface'],sent_at=sent,
                        received_at=received,start_offset=offset,offset=end,
                        source_identity=ident,process_identity=token,raw_sha256=digest(raw),
                        prefix_sha256=digest(data))
        raise Invalid('deadline waiting for complete statistics')
    def flush(self,spec):
        if process_identity(spec)!=self.state[spec['name']][1]: raise Invalid('capture died before flush')
        signal_caught(spec['pid'],signal.SIGUSR2)
        os.kill(spec['pid'],signal.SIGUSR2)

def validate_specs(specs):
    if not isinstance(specs,list) or not specs: raise Invalid('empty capture list')
    names=set(); pids=set(); sources=set()
    for s in specs:
        if not isinstance(s,dict) or set(s)!=set(('name','pid','interface','stderr','pcap')): raise Invalid('capture schema')
        if type(s['pid']) is not int or s['pid']<=1: raise Invalid('capture PID')
        for k in ('name','interface'):
            if not isinstance(s[k],str) or not re.fullmatch(r'[A-Za-z0-9_.-]+',s[k]): raise Invalid('capture identity')
        for k in ('stderr','pcap'):
            if not isinstance(s[k],str) or not os.path.isabs(s[k]): raise Invalid('capture path')
        if s['name'] in names or s['pid'] in pids or s['stderr'] in sources: raise Invalid('duplicate capture')
        names.add(s['name']);pids.add(s['pid']);sources.add(s['stderr'])

def validate_snapshot(s,spec):
    if not isinstance(s,dict): raise Invalid('snapshot schema')
    for k in ('C','R','D'):
        if type(s.get(k)) is not int or s[k]<0: raise Invalid('invalid stats field')
    if s.get('pid')!=spec['pid'] or s.get('interface')!=spec['interface']: raise Invalid('snapshot mixed identity')
    if not finite(s.get('sent_at')) or not finite(s.get('received_at')) or s['sent_at']>s['received_at']: raise Invalid('snapshot timestamps')
    if s['C']>s['R']: raise Invalid('captured exceeds received')
    if not isinstance(s.get('process_identity'),str) or not s['process_identity']: raise Invalid('missing process binding')
    ident=s.get('source_identity')
    if not isinstance(ident,list) or len(ident)!=2 or any(type(x) is not int or x<0 for x in ident): raise Invalid('source identity')
    for k in ('raw_sha256','prefix_sha256'):
        if not isinstance(s.get(k),str) or not re.fullmatch('[0-9a-f]{64}',s[k]): raise Invalid('snapshot hash')
    if type(s.get('start_offset')) is not int or type(s.get('offset')) is not int or not 0<=s['start_offset']<s['offset']: raise Invalid('snapshot offsets')

def _observe_legacy(specs,backend,budget_s=10):
    validate_specs(specs)
    if not finite(budget_s) or not 0<budget_s<=10: raise Invalid('budget must be finite, >0 and <=10 seconds')
    start=backend.monotonic(); deadline=start+budget_s
    result=dict(schema=SCHEMA,status='OPEN',budget_s=budget_s,captures=[],elapsed_s=0)
    for spec in specs:
        row=dict(spec=spec.copy(),ready=False,reason='deadline',snapshots=[],flushed=False,explanation='unresolved')
        result['captures'].append(row)
    try:
        while backend.monotonic()<deadline:
            for row in result['captures']:
                if row['ready']: continue
                s=backend.snapshot(row['spec'],deadline)
                validate_snapshot(s,row['spec']); old=row['snapshots']
                if old and (s['sent_at']<old[-1]['received_at'] or any(s[k]<old[-1][k] for k in ('C','R','D'))): raise Invalid('stats reversed/decreased')
                old.append(s)
                if s['D']!=0: raise Invalid('kernel drops')
                if len(old)>1 and s['R']==old[0]['R'] and s['C']==s['R']:
                    row.update(ready=True,reason='stable received and captured caught up',
                               explanation='backlog_observed_drained' if old[0]['C']<s['C'] else 'no_gap_observed')
                # Growth in R throughout observation must not be called drained backlog.
            if all(r['ready'] for r in result['captures']): break
            backend.sleep(min(.05,max(0,deadline-backend.monotonic())))
        if backend.monotonic()>=deadline:
            for r in result['captures']: r.update(ready=False,reason='drain deadline reached')
        # Flush every capture, including unresolved ones, before parent's stop/await.
        for row in result['captures']:
            backend.flush(row['spec']); row['flushed']=True
        if all(r['ready'] and r['flushed'] for r in result['captures']): result['status']='PREPARED'
    except (Exception,KeyboardInterrupt) as e:
        result['status']='UNKNOWN'
        result['error']=f'{type(e).__name__}: {e}'
        for row in result['captures']: row.update(ready=False,reason=result['error'])
    result['elapsed_s']=backend.monotonic()-start
    return result

def count_pcap(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    sha=hashlib.sha256()
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode): raise Invalid('pcap not regular file')
        with os.fdopen(fd,'rb',closefd=False) as f:
            def read(n):
                b=f.read(n);sha.update(b);return b
            header=read(24)
            formats={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>',b'\x4d\x3c\xb2\xa1':'<',b'\xa1\xb2\x3c\x4d':'>'}
            if len(header)!=24 or header[:4] not in formats: raise Invalid('not complete classic pcap')
            endian=formats[header[:4]]
            major,minor,_,_,snaplen,link=struct.unpack(endian+'HHiIII',header[4:])
            if (major,minor)!=(2,4) or not 0<snaplen<=1048576: raise Invalid('pcap header/snaplen')
            n=0
            while True:
                h=read(16)
                if not h: break
                if len(h)!=16: raise Invalid('truncated pcap record header')
                sec,sub,inc,orig=struct.unpack(endian+'IIII',h)
                if inc>snaplen or inc>orig or len(read(inc))!=inc: raise Invalid('truncated/invalid pcap record')
                n+=1
        after=os.fstat(fd)
        if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise Invalid('pcap changed during closed-file count')
        return n,sha.hexdigest()
    finally: os.close(fd)

def _finalize_legacy(observation,exit_rows,reader=regular_read,counter=count_pcap):
    # exit_rows supplied ONLY from parent's wait results, not inferred from dead PID.
    out=dict(schema=SCHEMA,status='UNKNOWN',observation=observation,captures=[])
    try:
        if not isinstance(observation,dict) or observation.get('schema')!=SCHEMA: raise Invalid('observation schema')
        if not finite(observation.get('budget_s')) or not 0<observation['budget_s']<=10 or not finite(observation.get('elapsed_s')) or observation['elapsed_s']<0: raise Invalid('measurement timing schema')
        if observation.get('status')=='PREPARED' and observation['elapsed_s']>=observation['budget_s']: raise Invalid('prepared after deadline')
        rows=observation['captures'];validate_specs([r['spec'] for r in rows])
        if not isinstance(exit_rows,dict) or set(exit_rows)!=set(r['spec']['name'] for r in rows): raise Invalid('missing/mixed wait results')
        for row in rows:
            spec=row['spec']; name=spec['name']; rec=dict(name=name,status='UNKNOWN');out['captures'].append(rec)
            if type(exit_rows[name]) is not int or exit_rows[name]!=0: raise Invalid('capture stop/await not clean')
            snaps=row['snapshots']
            if len(snaps)<2: raise Invalid('S0/S1 missing')
            for s in snaps: validate_snapshot(s,spec)
            last=snaps[-1]
            b,ident=reader(spec['stderr'])
            previous_offset=None
            for snapshot in snaps:
                start=snapshot.get('start_offset'); end=snapshot.get('offset')
                if type(start) is not int or type(end) is not int or not 0<=start<end<=len(b): raise Invalid('snapshot offsets')
                if previous_offset is not None and start!=previous_offset: raise Invalid('snapshot source continuity')
                segment=b[start:end]
                if snapshot.get('source_identity')!=ident or snapshot.get('process_identity')!=last.get('process_identity'):
                    raise Invalid('mixed snapshot source')
                if digest(segment)!=snapshot.get('raw_sha256') or digest(b[:end])!=snapshot.get('prefix_sha256'):
                    raise Invalid('snapshot raw binding')
                if parse_snapshot(segment)!={k:snapshot[k] for k in ('C','R','D')}: raise Invalid('snapshot raw values')
                previous_offset=end
            if ident!=last['source_identity'] or digest(b[:last['offset']])!=last['prefix_sha256']: raise Invalid('raw evidence changed')
            raw=b[last['offset']:]; final=parse_stats(raw)
            n,sha=counter(spec['pcap'])
            rec.update(final=final,N=n,pcap_sha256=sha,final_raw_sha256=digest(raw),
                       final_stats_text=raw.decode('ascii'))
            if final['D']!=0: raise Invalid('final kernel drops')
            if n!=final['C']: raise Invalid('N != C: closed pcap record inconsistency')
            if observation.get('status')!='PREPARED' or row.get('ready') is not True or row.get('flushed') is not True:
                rec.update(status='OPEN',reason=row.get('reason','drain unresolved'));continue
            if final!=dict(C=last['C'],R=last['R'],D=last['D']) or final['C']!=final['R']:
                rec.update(status='OPEN',reason='stats changed after S1 or final R != C');continue
            if any(s['R']!=snaps[0]['R'] for s in snaps) or any(s['D']!=0 for s in snaps): raise Invalid('stable R/no-drop proof missing')
            if any(b['C']<a['C'] or b['sent_at']<a['received_at'] for a,b in zip(snaps,snaps[1:])): raise Invalid('snapshot order')
            if snaps[-1]['C']-snaps[0]['C']!=snaps[0]['R']-snaps[0]['C']: raise Invalid('backlog growth mismatch')
            rec.update(status='PASS',reason='valid S0/S1, stable R, flush + parent wait0, closed N=C=R')
        out['status']='PASS' if all(r['status']=='PASS' for r in out['captures']) else 'OPEN'
    except Exception as e: out.update(status='UNKNOWN',error=f'{type(e).__name__}: {e}')
    return out


def observe(specs, backend, budget_s=10):
    import cumulative_anchor
    return cumulative_anchor.observe(specs, backend, budget_s)


def finalize(observation, exit_rows, reader=regular_read, counter=count_pcap):
    import cumulative_anchor
    return cumulative_anchor.finalize(observation, exit_rows, reader, counter)


def cli():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['observe','finalize'])
    p.add_argument('--capture',nargs=5,action='append',metavar=('NAME','PID','IFACE','STDERR','PCAP'))
    p.add_argument('--final-stats-dir');p.add_argument('--budget-s',type=float,default=10);p.add_argument('--observation');p.add_argument('--exit-file');p.add_argument('--output',required=True)
    a=p.parse_args()
    try:
        if a.mode=='observe':
            specs=[dict(zip(('name','pid','interface','stderr','pcap'),[x[0],int(x[1]),*x[2:]])) for x in (a.capture or [])]
            def interrupted(sig,frame): raise InterruptedError(f'signal {sig}')
            for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
            result=observe(specs,Live(),a.budget_s)
        else:
            observation=json.loads(Path(a.observation).read_text());exit_rows={}
            expected={r['spec']['name'] for r in observation['captures']}
            seen=set()
            for line in Path(a.exit_file).read_text().splitlines():
                name,rc=line.split()
                if name in seen: raise Invalid('duplicate wait result')
                seen.add(name)
                if name in expected: exit_rows[name]=int(rc) # KILLED_AT_DEADLINE is UNKNOWN, never 0
                elif name not in ('alert','alert_eth'): raise Invalid('unexpected additional wait result')
                # alert / alert_eth: not part of the ARP drain; their own exit-0 check in the script is unchanged
            result=finalize(observation,exit_rows)
    except (Exception,KeyboardInterrupt) as e: result=dict(schema=SCHEMA,status='UNKNOWN',error=f'{type(e).__name__}: {e}')
    try:
        # Fresh output only; never invalidate or overwrite raw/older evidence.
        if a.final_stats_dir:
            if a.mode!='finalize': raise Invalid('stats export only after stop/await')
            for row in result.get('captures',[]):
                if 'final_stats_text' in row:
                    with open(Path(a.final_stats_dir)/(row['name']+'.final-stats.err'),'x',encoding='ascii') as f:f.write(row['final_stats_text'])
        with open(a.output,'x',encoding='ascii') as f:json.dump(result,f,ensure_ascii=True,allow_nan=False,indent=2);f.write('\n')
    except Exception as e:
        print(json.dumps(dict(schema=SCHEMA,status='OUTPUT_ERROR',error=str(e)),ensure_ascii=True),file=sys.stderr);return 2
    return 0 if result['status'] in ('PREPARED','PASS') else 5
if __name__=='__main__':
    # -I removes script-directory imports; only the pinned module in this stage may load.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.modules['capture_drain'] = sys.modules[__name__]
    sys.exit(cli())
