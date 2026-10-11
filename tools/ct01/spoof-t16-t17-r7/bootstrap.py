#!/usr/bin/env python3
"""Standalone stdlib root bootstrap: copy payload as DATA, hash staged copies, then run staged launcher.
Must itself be copied and hash-checked in an operator-pasted env-i root wrapper first.
Installed Python/binaries + ancestry + absence of privileged concurrent changes are separate trust assumptions.
"""
import argparse,hashlib,importlib.util,json,os,pathlib,re,signal,stat,subprocess,sys,tempfile,time,types,uuid
P=pathlib.Path
class Refused(ValueError):pass
def require(ok,msg):
    if not ok:raise Refused(msg)
def hash_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()
def open_regular(path):
    """Descriptor traversal; no symlink at ANY path component, regular final only (no FIFO/device reads)."""
    p=P(path);require(p.is_absolute() and '..' not in p.parts,'absolute non-traversal source required')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for component in p.parts[1:-1]:
            nextfd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nextfd
        f=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        if not stat.S_ISREG(os.fstat(f).st_mode):os.close(f);raise Refused('source not a regular file')
        return f
    finally:os.close(fd)
def copy_checked(src,dst,pin):
    require(re.fullmatch('[0-9a-f]{64}',pin or '') is not None,'external digest required')
    fd=open_regular(src)
    try:
        with os.fdopen(fd,'rb') as source,open(dst,'xb') as target:
            while True:
                data=source.read(1024*1024)
                if not data:break
                target.write(data)
        os.chmod(dst,0o400);require(hash_file(dst)==pin,'staged COPY hash mismatch: '+str(dst))
    except BaseException:raise # stage retained root-only for diagnosis; never execute failed copy

def stage_payload(source,stage,pinned_manifest):
    source=P(source);stage=P(stage);copy_checked(source/'SHA256SUMS',stage/'SHA256SUMS',pinned_manifest)
    seen=set()
    for line in (stage/'SHA256SUMS').read_text().splitlines():
        pin,name=line.split(None,1);name=name.removeprefix('./');rel=P(name)
        require(not rel.is_absolute() and '..' not in rel.parts and rel.parts and all(re.fullmatch('[A-Za-z0-9_.-]+',c) for c in rel.parts) and name not in seen,'unsafe/duplicate payload path');seen.add(name)
        require(name!='SHA256SUMS','manifest cannot list itself');dest=stage/rel;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);copy_checked(source/rel,dest,pin)
    require('launcher.py' in seen and 'bootstrap.py' in seen,'runtime entrypoints missing')
    return stage

def supervise(argv,**kw):
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
        raw_rc=child.wait();code=128+state['signals'][0]['number'] if state['signals'] else 128-raw_rc if raw_rc in (-1,-2,-15) else raw_rc
        return types.SimpleNamespace(returncode=code,raw_returncode=raw_rc,signal_state=state)
    finally:
        for number,handler in previous.items():signal.signal(number,handler)

def main(argv):
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='mode',required=True)
    a=sub.add_parser('collect');a.add_argument('source');a.add_argument('manifest_sha')
    a=sub.add_parser('launch');a.add_argument('stage');a.add_argument('manifest_sha');a.add_argument('context');a.add_argument('context_sha')
    args=parser.parse_args(argv)
    try:
        require(os.geteuid()==0,'must be root; no production invocation from offline tests');os.umask(0o077)
        s=os.lstat('/var/tmp');require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o1777,'trusted real root /var/tmp1777 required')
        if args.mode=='collect':
            stage=P('/var/tmp')/('ct01-arp-runtime.'+uuid.uuid4().hex[:8]);stage.mkdir(mode=0o700);stage_payload(P(args.source),stage,args.manifest_sha)
            command=['/usr/bin/python3','-I','-B',str(stage/'launcher.py'),'collect',str(stage),args.manifest_sha]
        else:
            stage=P(args.stage);require(re.fullmatch(r'/var/tmp/ct01-arp-runtime\.[A-Za-z0-9]{8}',str(stage)) is not None,'fixed root runtime stage required')
            # Validate tree/payload before any code in it is imported or invoked.
            q=stage
            while True:
                st=q.lstat();require(st.st_uid==0 and not stat.S_ISLNK(st.st_mode),'non-root/symlink runtime ancestry')
                require(str(q)=='/var/tmp' or not stat.S_IMODE(st.st_mode)&0o022,'runtime ancestry writable')
                if q.parent==q:break
                q=q.parent
            require(hash_file(stage/'SHA256SUMS')==args.manifest_sha,'runtime manifest differs from external pin')
            for line in (stage/'SHA256SUMS').read_text().splitlines():
                pin,name=line.split(None,1);rel=P(name.removeprefix('./'));require(not rel.is_absolute() and '..' not in rel.parts,'bad manifest path')
                p=stage/rel;fd=open_regular(p)
                try:st=os.fstat(fd);require(st.st_uid==0 and not stat.S_IMODE(st.st_mode)&0o022,'runtime payload ownership/mode changed')
                finally:os.close(fd)
                require(hash_file(p)==pin,'runtime payload hash mismatch')
            spec=importlib.util.spec_from_file_location('pinned_layout_validator',stage/'launcher.py');validator=importlib.util.module_from_spec(spec);spec.loader.exec_module(validator);validator.verify_stage(stage,args.manifest_sha)
            command=['/usr/bin/python3','-I','-B',str(stage/'launcher.py'),'launch',str(stage),args.manifest_sha,args.context,args.context_sha]
        print(json.dumps({'schema':'ct01-arp-bootstrap/1','stage':str(stage),'manifest_sha256':args.manifest_sha,'argv':command,'note':'staged copies verified; receipt/context do not confer approval'}),flush=True)
        return supervise(command,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'},stdin=subprocess.DEVNULL).returncode
    except Exception as e:print(json.dumps({'schema':'ct01-arp-bootstrap-error/1','status':'REJECTED','reason':type(e).__name__+': '+str(e)},ensure_ascii=True));return 2
if __name__=='__main__':sys.exit(main(sys.argv[1:]))
