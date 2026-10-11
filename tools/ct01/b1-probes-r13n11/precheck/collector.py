#!/usr/bin/python3
"""06B-4IR3R standalone precheck collector: selected read-only data, strict payloads, provenance v2.
Prepared offline. Root collection was NOT performed. Root must use the reviewed copy/hash procedure;
no user-tree imports. No container start/create/stop, ruleset changes, probes, guest commands, or Config.Env.

Reads: Docker version/info/image id/ps/networks/container metadata; only if a valid manager inspect says
already running, read-only manager ip/proc/sysfs commands. Host pgrep/nft/AppArmor. Manager/host aren't worker/ctl.
Each record preserves exact argv, rc, raw stdout/stderr files AND inline values, status and reason.
OK / NONZERO / TIMEOUT / EXEC_ERROR / PAYLOAD_ERROR / SKIPPED. Malformed rc0 payload can't prove absence/state.
Meta records UUID, root source, host/uid, finite wall-clock collection start/end and SHA of this verified file.
Evaluator independently recomputes completeness and revalidates the input; data_complete is informational.
Exit 0 = all required reads/payloads succeeded (NOT precheck verdict), 3 incomplete/collection error,
2 refused before collection. Output FD writes stay in the checked directory; full path/content trust is
still a precondition, described in RUN-PROCEDURE. No automatic removal of old evidence.
"""
import json
import os
import stat
import subprocess
import sys
import time
import math
import hashlib
import ipaddress
import re
import uuid
import datetime

EXPECTED_IMAGE_ID = "sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153"
IMAGE = "sandbox-worker:latest"
MANAGER = "cic-ynu-iotmal-sandbox-sandbox-manager-1"
MONGO = "mongo-db"
HARNESS_CONTAINERS = ("ct01-06b3b-guest", "ct01-06b3b-ctl")
NETWORK_LABELS = {"sandboxnet": "com.docker.compose.network=sandboxnet", "dbnet": "com.docker.compose.network=dbnet"}
BINS = {"docker": "/usr/bin/docker", "pgrep": "/usr/bin/pgrep", "nft": "/usr/sbin/nft", "aa-status": "/usr/sbin/aa-status"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}   # nothing inherited
TIMEOUT_S = 60
SCHEMA = "ct01-precheck-collector/2"


class Refused(Exception):
    """Collection refused before any read (exit 2)."""


# ------------------------------------------------------------------ output directory (PC-4)
def prepare_outdir(path, owner_uid=0):
    """Open the output directory WITHOUT following a symlink and check it is a real, empty directory owned by
    owner_uid with no group/other permission. Returns its fd; every file is then created relative to that fd."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as e:
        raise Refused(f"output directory {path!r} not openable as a real directory (symlink?): {e}")
    st = os.fstat(fd)
    problems = []
    if st.st_uid != owner_uid:
        problems.append(f"owned by uid {st.st_uid}, expected {owner_uid}")
    if stat.S_IMODE(st.st_mode) & 0o077:
        problems.append(f"mode {stat.S_IMODE(st.st_mode):o} gives group/other access (expected 0700)")
    if os.listdir(fd):
        problems.append("not empty")
    if problems:
        os.close(fd)
        raise Refused(f"output directory {path!r} unsafe: {'; '.join(problems)}")
    return fd


def write_new(dfd, name, data):
    """Create a NEW file in the output directory (O_EXCL | O_NOFOLLOW, mode 0600): an existing name or a planted
    symlink makes it fail instead of writing elsewhere."""
    if "/" in name or name in (".", ".."):
        raise ValueError(f"bad output name {name!r}")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def trusted_bins(bins=BINS, owner_uid=0):
    """Validate lexical AND resolved ancestors. Symlink owner and its containing path are checked, then target chain.
    Metadata only: trust also requires approved installed tools and protection from privileged writers.
    This does not claim O_NOFOLLOW on a final component pins an entire path chain.
    """
    problems=[]
    for name,path in bins.items():
        if not os.path.isabs(path):problems.append(name+': executable path not absolute');continue
        targets=set()
        for p in (os.path.abspath(path),os.path.realpath(path)):
            while True:
                targets.add(p)
                parent=os.path.dirname(p)
                if parent==p:break
                p=parent
        for p in sorted(targets):
            try:st=os.lstat(p)
            except OSError as e:problems.append(name+': '+str(e));continue
            if st.st_uid!=owner_uid or (not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022):
                problems.append(name+': untrusted ancestor/target '+p)
        try:
            if not stat.S_ISREG(os.stat(path).st_mode):problems.append(name+': executable not regular file')
        except OSError:pass
    return problems


# ------------------------------------------------------------------ reads
def subprocess_runner(argv):
    """-> (rc, stdout bytes, stderr bytes, error) with the fixed environment; never a shell."""
    try:
        r = subprocess.run(argv, env=dict(ENV), stdin=subprocess.DEVNULL, capture_output=True, timeout=TIMEOUT_S)
        return r.returncode, r.stdout, r.stderr, None
    except subprocess.TimeoutExpired as e:
        return None, e.stdout or b"", e.stderr or b"", "TIMEOUT"
    except OSError as e:
        return None, b"", b"", f"EXEC_ERROR: {type(e).__name__}: {e}"


# This contract is intentionally in the single, hash-verified collector file. Root needs no user-tree imports.
OPTIONAL = ('manager-ip-version', 'manager-ip-j-neigh', 'manager-proc-net-arp', 'manager-sys-class-net')
STATES = {'created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead'}
ID = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*')

class PayloadError(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise PayloadError(reason)

def finite_number(x):
    return type(x) in (int, float) and math.isfinite(x)

def valid_json_values(value):
    """Reject non-finite numbers and surrogate code points at any depth; never normalize evidence."""
    pending=[('$',value,False)];active=set()
    while pending:
        path,v,closing=pending.pop()
        if closing:
            active.remove(id(v));continue
        if isinstance(v,float) and not math.isfinite(v):
            raise ValueError('non-finite number at '+path)
        if isinstance(v,str) and any(0xD800<=ord(ch)<=0xDFFF for ch in v):
            raise ValueError('surrogate code point at '+path)
        if isinstance(v,(dict,list,tuple)):
            if id(v) in active:raise ValueError('non-JSON cyclic container at '+path)
            active.add(id(v));pending.append((path,v,True))
            if isinstance(v,dict):
                for k,x in v.items():
                    pending.append((path+'[key '+ascii(k)+']',k,False))
                    pending.append((path+'['+ascii(k)+']',x,False))
            else:
                pending.extend((path+'['+str(i)+']',x,False) for i,x in enumerate(v))
    return value

def strict_json(text):
    def pairs(ps):
        d = {}
        for k, v in ps:
            if k in d:
                raise ValueError('duplicate JSON key: ' + k)
            d[k] = v
        return d
    return valid_json_values(json.loads(text, object_pairs_hook=pairs, parse_constant=lambda s: (_ for _ in ()).throw(ValueError('nonfinite JSON: ' + s))))

def endpoint_mac_problem(mac):
    if not isinstance(mac, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac):
        return 'MAC missing or malformed'
    bs = bytes.fromhex(mac.replace(':', ''))
    if bs == b'\0'*6 or bs[0] & 1:
        return 'MAC zero or multicast/broadcast'
    return None

def rows(text, columns, label, allow_empty=False):
    need(isinstance(text, str), label + ': stdout not string')
    rs = [l.split('\t') for l in text.splitlines() if l.strip()]
    need(bool(rs) or allow_empty, label + ': empty payload')
    need(all(len(r) == columns for r in rs), label + ': wrong column count')
    return rs

def ip(value, family=None, prefix=False, blank=False):
    need(isinstance(value, str), 'IP not string')
    if blank and value == '':
        return
    try:
        v = ipaddress.ip_interface(value) if prefix else ipaddress.ip_address(value)
    except ValueError as e:
        raise PayloadError('invalid IP: ' + repr(value)) from e
    need(family is None or v.version == family, 'wrong IP family')
    if prefix:
        need('/' in value, 'address/prefix missing prefix')

def parse_ps(text):
    rs = rows(text, 4, 'ps', allow_empty=True); names=set(); ids=set()
    for name, state, image, ident in rs:
        need(NAME.fullmatch(name) is not None and state in STATES and bool(image) and ID.fullmatch(ident) is not None,
             'ps: invalid name/state/image/id')
        need(name not in names and ident not in ids, 'ps: duplicate name or id')
        names.add(name);ids.add(ident)
    return {r[0]: {'state': r[1], 'image': r[2], 'id': r[3]} for r in rs}

def parse_network_list(text):
    rs = rows(text, 2, 'network list', allow_empty=True); seen_ids=set();seen_names=set()
    for ident, name in rs:
        need(ID.fullmatch(ident) is not None and NAME.fullmatch(name) is not None, 'network list: invalid id/name')
        need(ident not in seen_ids and name not in seen_names, 'network list: duplicate id/name')
        seen_ids.add(ident);seen_names.add(name)
    return rs

def parse_network(text):
    rs = rows(text, 6, 'network inspect');need(len(rs)==1, 'network inspect: expected one row')
    ident,name,driver,internal,ipam_s,ctrs_s=rs[0]
    need(ID.fullmatch(ident) is not None and NAME.fullmatch(name) is not None and bool(driver) and internal in ('true','false'),
         'network inspect: invalid id/name/driver/internal')
    try:ipam,ctrs = strict_json(ipam_s),strict_json(ctrs_s)
    except ValueError as e:raise PayloadError('network inspect JSON: '+str(e)) from e
    need(isinstance(ipam,list) and bool(ipam), 'network IPAM must be nonempty list')
    for c in ipam:
        need(isinstance(c,dict) and isinstance(c.get('Subnet'),str) and isinstance(c.get('Gateway'),str), 'IPAM object/subnet/gateway missing')
        try:n=ipaddress.ip_network(c['Subnet'],strict=True)
        except ValueError as e:raise PayloadError('invalid IPAM subnet') from e
        ip(c['Gateway']);need(ipaddress.ip_address(c['Gateway']) in n, 'gateway outside subnet')
    need(isinstance(ctrs,dict), 'network Containers must be object')
    for ident_c,c in ctrs.items():
        need(ID.fullmatch(ident_c) is not None and isinstance(c,dict), 'network Containers entry/id invalid')
        need(isinstance(c.get('Name'),str) and NAME.fullmatch(c['Name']) is not None and isinstance(c.get('EndpointID'),str)
             and ID.fullmatch(c['EndpointID']) is not None, 'network endpoint name/id invalid')
        need(endpoint_mac_problem(c.get('MacAddress')) is None, 'network endpoint MAC unusable')
        ip(c.get('IPv4Address'),4,prefix=True,blank=True);ip(c.get('IPv6Address'),6,prefix=True,blank=True)
    return {'id':ident,'name':name,'driver':driver,'internal':internal=='true','ipam':ipam,'containers':ctrs}

def parse_container(text):
    rs=rows(text,5,'container inspect');need(len(rs)==1,'container inspect: expected one row')
    state,ident,restarts,started,nets_s=rs[0]
    need(state in STATES and ID.fullmatch(ident) is not None and re.fullmatch(r'\d+',restarts) is not None,
         'container state/id/restart invalid')
    need(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)',started) is not None,
         'container StartedAt invalid')
    try:datetime.datetime.fromisoformat(started.replace('Z','+00:00'));nets=strict_json(nets_s)
    except ValueError as e:raise PayloadError('container date/networks invalid: '+str(e)) from e
    need(isinstance(nets,dict), 'container networks must be object')
    for name,n in nets.items():
        need(isinstance(name,str) and NAME.fullmatch(name) is not None and isinstance(n,dict), 'container network mapping invalid')
        ip(n.get('IPAddress'),4,blank=True)
        mac=n.get('MacAddress');need(isinstance(mac,str) and (mac=='' or endpoint_mac_problem(mac) is None),'container network MAC unusable')
        if 'NetworkID' in n:need(isinstance(n['NetworkID'],str) and (not n['NetworkID'] or ID.fullmatch(n['NetworkID']) is not None),'container NetworkID invalid')
    return {'state':state,'id':ident,'restarts':int(restarts),'started_at':started,'networks':nets}

def parse_payload(name,text,rc=0):
    if name=='ps-all':return parse_ps(text)
    if name.startswith('network-ls-'):return parse_network_list(text)
    if name.startswith('network-inspect-'):return parse_network(text)
    if name.startswith('inspect-'):return parse_container(text)
    need(isinstance(text,str),'stdout not string')
    if name=='docker-version':
        m=re.fullmatch(r'client=([0-9]+(?:\.[0-9]+){1,2}(?:[-+][A-Za-z0-9_.-]+)?) server=([0-9]+(?:\.[0-9]+){1,2}(?:[-+][A-Za-z0-9_.-]+)?) api=(\d+\.\d+)\s*',text)
        need(m is not None and m[2] not in ('<no','<no value>','null'), 'version format invalid');return m.groups()
    if name=='docker-info':
        need(re.fullmatch(r'driver=\S+ cgroup=\S+/\S+ kernel=\S+ os=.+ running=\d+\s*',text) is not None,'info format invalid');return text
    if name=='image-id':need(re.fullmatch(r'sha256:[0-9a-f]{64}\s*',text) is not None,'image id invalid');return text.strip()
    if name.startswith('pgrep-'):
        if rc==1:need(not text.strip(),'pgrep rc1 contradicts process output');return []
        need(bool(text.strip()),'pgrep rc0 has empty output');need(all(re.fullmatch(r'\d+\s+\S.*',l) for l in text.splitlines() if l.strip()),'pgrep row malformed');return text.splitlines()
    if name=='nft-ruleset':need(bool(text.strip()),'empty nft ruleset');return text
    if name=='aa-status':need(bool(text.strip()),'empty AppArmor payload');return text
    return text  # informational manager reads cannot establish worker/ctl state

def read_contract(network_ids=None):
    d=BINS['docker'];network_ids=network_ids or {}
    spec={
      'docker-version': [d,'version','--format','client={{.Client.Version}} server={{.Server.Version}} api={{.Server.APIVersion}}'],
      'docker-info':[d,'info','--format','driver={{.Driver}} cgroup={{.CgroupDriver}}/{{.CgroupVersion}} kernel={{.KernelVersion}} os={{.OperatingSystem}} running={{.ContainersRunning}}'],
      'image-id':[d,'image','inspect','--format','{{.Id}}',IMAGE],
      'ps-all':[d,'ps','-a','--no-trunc','--format','{{.Names}}\t{{.State}}\t{{.Image}}\t{{.ID}}'],
    }
    for net,label in NETWORK_LABELS.items():
        spec['network-ls-'+net]=[d,'network','ls','--no-trunc','--filter','label='+label,'--format','{{.ID}}\t{{.Name}}']
        spec['network-inspect-'+net]=None if net not in network_ids else [d,'network','inspect','--format','{{.Id}}\t{{.Name}}\t{{.Driver}}\t{{.Internal}}\t{{json .IPAM.Config}}\t{{json .Containers}}',network_ids[net]]
    for who,name in [('manager',MANAGER),('mongo',MONGO)]:
        spec['inspect-'+who]=[d,'inspect','--type','container','--format','{{.State.Status}}\t{{.Id}}\t{{.RestartCount}}\t{{.State.StartedAt}}\t{{json .NetworkSettings.Networks}}',name]
    for name,args in zip(OPTIONAL,[['sh','-c','command -v ip && ip -V'],['ip','-j','neigh','show'],['cat','/proc/net/arp'],['sh','-c','for i in /sys/class/net/*; do echo "$(basename $i) $(cat $i/address) $(cat $i/operstate)"; done']]):
        spec[name]=[d,'exec',MANAGER]+args
    spec.update({'pgrep-qemu':[BINS['pgrep'],'-a','qemu-system'],'pgrep-capture':[BINS['pgrep'],'-a','tcpdump|tshark|dumpcap'],
                 'nft-ruleset':[BINS['nft'],'-s','list','ruleset'],'aa-status':[BINS['aa-status']]})
    return spec

def accepted_rcs(name):
    return [0,1] if name.startswith('pgrep-') else [0]

class Collector:
    def __init__(self,dfd,runner):self.dfd,self.runner,self.reads=dfd,runner,[]
    def add(self,name,argv,rc,out,err,error,status):
        seq=len(self.reads)+1;base=f'{seq:02d}-{name}'
        write_new(self.dfd,base+'.stdout',out);write_new(self.dfd,base+'.stderr',err)
        r={'name':name,'argv':argv,'required':name not in OPTIONAL,'rc':rc,'status':status,'error':error,'ok_rcs':accepted_rcs(name),
           'stdout_file':base+'.stdout','stderr_file':base+'.stderr','stdout':out.decode(errors='replace'),'stderr':err.decode(errors='replace')}
        self.reads.append(r);return r
    def read(self,name,argv):
        rc,out,err,error=self.runner(argv)
        status='OK' if error is None and type(rc) is int and rc in accepted_rcs(name) else (error.split(':')[0] if error else 'NONZERO')
        if status=='OK':
            try:parse_payload(name,out.decode(errors='replace'),rc)
            except (PayloadError,ValueError,TypeError) as e:status,error='PAYLOAD_ERROR',str(e)
        return self.add(name,argv,rc,out,err,error,status)
    def skip(self,name,reason):return self.add(name,None,None,b'',b'',reason,'SKIPPED')

def collect(dfd,runner,bins=BINS,clock=time.time):
    if bins!=BINS:raise Refused('contract pins binaries; runner injection is for offline tests only')
    c=Collector(dfd,runner);t0=clock();contract=read_contract();resolved={};ids={}
    for name in ('docker-version','docker-info','image-id','ps-all'):c.read(name,contract[name])
    for net in NETWORK_LABELS:
        r=c.read('network-ls-'+net,contract['network-ls-'+net]);rs=parse_network_list(r['stdout']) if r['status']=='OK' else []
        if r['status']!='OK':c.skip('network-inspect-'+net,'network list not usable: '+r['status'])
        elif len(rs)!=1:c.skip('network-inspect-'+net,'network resolution requires exactly one row; got '+str(len(rs)))
        else:
            ids[net],resolved[net]=rs[0];c.read('network-inspect-'+net,read_contract(ids)['network-inspect-'+net])
    for name in ('inspect-manager','inspect-mongo'):c.read(name,contract[name])
    m=next(r for r in c.reads if r['name']=='inspect-manager')
    running=m['status']=='OK' and parse_container(m['stdout'])['state']=='running'
    for name in OPTIONAL:
        if running:c.read(name,contract[name])
        else:c.skip(name,'manager not running' if m['status']=='OK' else 'manager state unknown: '+m['status'])
    for name in ('pgrep-qemu','pgrep-capture','nft-ruleset','aa-status'):c.read(name,contract[name])
    complete=all(r['status']=='OK' for r in c.reads if r['required'])
    meta={'schema':SCHEMA,'run_id':uuid.uuid4().hex,'root_source':os.path.realpath('/proc/self/fd/'+str(dfd)),
          'collector_sha256':hashlib.sha256(open(__file__,'rb').read()).hexdigest(),'host':os.uname().nodename,'execution_uid':os.geteuid(),
          't_start':t0,'t_end':clock(),'expected_image_id':EXPECTED_IMAGE_ID,'image':IMAGE,'manager':MANAGER,'mongo':MONGO,
          'harness_containers':list(HARNESS_CONTAINERS),'networks_resolved':resolved,'bins':BINS,'env':ENV,'data_complete':complete,
          'note':'collector output, NOT a precheck verdict or proof that host is unchanged after collection'}
    write_new(dfd,'reads.json',json.dumps({'meta':meta,'reads':c.reads},indent=1,ensure_ascii=False,allow_nan=False))
    return 0 if complete else 3

def main(argv):
    if len(argv)!=1:print('usage: collector.py <root-stage/out>',file=sys.stderr);return 2
    try:
        if os.geteuid()!=0:raise Refused('must run as root')
        path=os.path.realpath(argv[0])
        if not re.fullmatch(r'/var/tmp/ct01-precheck\.[A-Za-z0-9]{8}/out',path) or path!=argv[0]:raise Refused('fixed canonical root staging required')
        parent=os.stat(os.path.dirname(path))
        if parent.st_uid!=0 or stat.S_IMODE(parent.st_mode)!=0o700:raise Refused('root staging parent must be root-owned 0700')
        bad=trusted_bins()
        if bad:raise Refused('; '.join(bad))
        dfd=prepare_outdir(path)
    except (Refused,OSError) as e:print('REFUSED: '+str(e),file=sys.stderr);return 2
    try:
        rc=collect(dfd,subprocess_runner)
        for name in os.listdir(dfd):
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=dfd);os.fchmod(fd,0o644);os.close(fd)
        os.fchmod(dfd,0o755)
    except Exception as e:print('COLLECTION_ERROR: '+type(e).__name__+': '+str(e),file=sys.stderr);return 3
    finally:os.close(dfd)
    print('collector exit '+str(rc)+'; NOT a precheck verdict');return rc

if __name__=='__main__':sys.exit(main(sys.argv[1:]))
