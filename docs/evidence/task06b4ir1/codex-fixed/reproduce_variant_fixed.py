#!/usr/bin/env python3
"""Independent offline fixtures. Runs real wiring with simulated worker/guest only."""
import ast
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'harness'))
import selftest_arp_wiring as T
import arp_harness as H

VARIANT = sys.argv[1] if len(sys.argv) > 1 else None   # 06B-4IR1 (Claude): captured at import; scenario_main()
                                                       # rewrites sys.argv before this thread starts


def control_thread(path, mode, stop):
    variant = VARIANT
    with open(path, 'a', buffering=1) as f:
        while not stop.is_set():
            ts = time.time()
            detail = {'hw': T.ETH0_MAC, 'flags': '0x2', 'device': 'eth0'}
            if variant == 'a1-wrong-interface':
                detail['device'] = 'eth9'
            if variant == 'a1-missing-interface':
                detail.pop('device')
            rows = [
                {'ts':ts,'target':H.ctl_target_http_worker(T.CFG['worker_ip']), 'ok':True,'detail':'HTTP 200'},
                {'ts':ts,'target':H.ctl_target_arp_worker(T.CFG['worker_ip']), 'ok':True,'detail':detail},
                {'ts':ts,'target':H.ctl_target_http_manager(T.CFG['manager_ip']), 'ok':True,'detail':'HTTP 200'}]
            if variant == 'duplicate-control':
                rows += copy.deepcopy(rows)
            if variant == 'http-missing-detail':
                for r in rows:
                    if not r['target'].startswith('arp '):
                        r.pop('detail')
            for r in rows:
                f.write(json.dumps(r)+'\n')
            stop.wait(0.15)

def scenario(variant):
    if variant.startswith('boot-'):
        original = T.write_stubs
        real_src=(ROOT/'configure-network-extracted.py').read_text()
        def write_stubs(sb, marker_file, marker_left):
            original(sb, marker_file, marker_left)
            d=Path(sb).parent
            event_path=d/'hostcap'/('alert.txt' if 'leak' in variant else 'capture-dead.txt')
            # Unchanged real configure-network method; console and expect are fakes.
            extra='''
import types,json,pathlib
pexpect=types.SimpleNamespace(TIMEOUT='TIMEOUT',EOF='EOF',spawn=object)
guestnet=types.SimpleNamespace(GUEST_PREFIX=30)
ArchConfig=object
logger=types.SimpleNamespace(info=lambda *a:None)
'''+real_src+f'''
def _sendline(self, cmd):
    path=pathlib.Path({str(d/'boot-console.jsonl')!r})
    with path.open('a') as f:f.write(json.dumps(cmd)+'\\n')
    if cmd.startswith('ip addr add '):
        pathlib.Path({str(event_path)!r}).write_text('independent startup event\\n')
FakeProc.sendline=_sendline
FakeProc.expect=lambda *a:1
def _configured(self, proc, cfg):
    self.qemu_ip,self.qemu_gw='10.200.0.2','10.200.0.1'
    cfg.boot_ready_prompt,cfg.network_ready_prompt_optional,cfg.extra_prompt_after_dns='# ',False,False
    return _configure_network(self,proc,cfg)
Analysis._configure_network=_configured
'''
            with (Path(sb)/'service'/'analysis.py').open('a') as f:f.write(extra)
        T.write_stubs=write_stubs
    if variant in ('a1-wrong-interface','a1-missing-interface','duplicate-control','http-missing-detail','codex-thread-unmodified'):
        T.ctl_loop_thread = control_thread
    if variant.startswith('topology-'):
        original = T.guest_class
        def guest_class(SA, GS):
            base = original(SA, GS)
            class Guest(base):
                def run(self, cmd, timeout=60):
                    result = super().run(cmd, timeout)
                    if cmd == 'ip addr':
                        T.fire('leak' if variant == 'topology-leak' else 'marker')
                    return result
            return Guest
        T.guest_class = guest_class
    if variant == 'guard-callback-error':
        original = T.guest_class
        def guest_class(SA, GS):
            base = original(SA, GS)
            class Guest(base):
                def run(self, cmd, timeout=60):
                    result = super().run(cmd, timeout)
                    if '-s 1402 192.168.60.10' in cmd:
                        def error(*args, **kw):
                            raise KeyError('independent guard callback fixture')
                        T.W.pm.captures_alive = error
                    return result
            return Guest
        T.guest_class = guest_class
    if variant == 'fail-and-outer-error':
        T.SCENARIOS['clean'] = {'neigh':{('T14-A3 after',0):'guest_mac_eth0'},
                                'events':[('ip link set dev eth1 up','tap0_gone')]}
    d = Path(os.environ.get('REVIEW_FIXTURE_ROOT',str(ROOT/'fixtures')))/variant
    d.mkdir(parents=True)
    if variant.startswith('real-collector-'):
        # Execute the actual run_checked implementation with an ip stub on a private PATH.
        # nft/tshark/HTTP remain simulated; no real ip executable can be reached.
        import selftest_arp as SA
        fakebin = d/'fakebin'; fakebin.mkdir()
        (d/'neigh.json').write_text(SA.NEIGH)
        ip = fakebin/'ip'
        ip.write_text('''#!/usr/bin/python3
import json,os,pathlib,sys
r=pathlib.Path(os.environ['REVIEW_COLLECTOR_DIR'])
log=r/'subprocess.jsonl'
n=len(log.read_text().splitlines())+1 if log.exists() else 1
with log.open('a') as f: f.write(json.dumps({'n':n,'argv':sys.argv[1:],'cwd':os.getcwd()})+'\\n')
if os.environ['REVIEW_COLLECTOR_MODE']=='real-collector-error' and n==4:
    print('independent rc7 fixture',file=sys.stderr);sys.exit(7)
print((r/'neigh.json').read_text())
''')
        ip.chmod(0o755)
        tree=ast.parse((ROOT/'harness'/'probe_matrix.py').read_text())
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run_checked')
        ns={'subprocess':subprocess};exec(compile(ast.Module(body=[fn],type_ignores=[]),'probe_matrix.py','exec'),ns)
        real = ns['run_checked']; old = T.fake_run_checked
        def dispatch(cmd):
            if cmd[:3] == ['ip','-j','neigh']:
                # Explicit override only for the child subprocess, not the host environment.
                saved_path=os.environ.get('PATH')
                os.environ['PATH']=str(fakebin)
                os.environ['REVIEW_COLLECTOR_DIR']=str(d)
                os.environ['REVIEW_COLLECTOR_MODE']=variant
                try:return real(cmd)
                finally:
                    if saved_path is None:os.environ.pop('PATH',None)
                    else:os.environ['PATH']=saved_path
            return old(cmd)
        T.fake_run_checked=dispatch
    T.scenario_main('clean', str(d))
    sc = json.loads((d/'scenario.json').read_text())
    out = Path(sc['out'])
    result = json.loads((out/'result.json').read_text())
    ev = json.loads((out/'arp-eval.json').read_text()) if (out/'arp-eval.json').exists() else None
    group = json.loads((out/'arp-group.json').read_text()) if (out/'arp-group.json').exists() else None
    outcome = H.arch_outcome(result, ev, 'ARM')
    cmd = [c for kind,c in sc['commands'] if kind == 'run']
    summary = {'variant':variant,'rc':sc['rc'],'status':result['status'],
               'outcome':outcome,'cli':T.cli_outcome(str(out/'result.json'),str(out/'arp-eval.json')),
               'script_mapping':T.script_mapping(sc['rc'],outcome),
               'categories':{c['id']:c['category'] for c in (ev or {}).get('cases',[])},
               'commands':cmd,'control_A1':next((c['control'] for c in (group or {}).get('cases',[]) if c['id']=='T14-A1'),None),
               'infrastructure':[{k:r.get(k) for k in ('test','ok','error')} for r in result['results']
                   if r['test'] in ('QEMU exit confirmed','fixture, marker and temporary guest disk removed')],
               'files':str(out)}
    if (d/'boot-console.jsonl').exists():
        summary['boot_console']=[json.loads(x) for x in (d/'boot-console.jsonl').read_text().splitlines()]
    (d/'review-result.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False))
    print(json.dumps({k:v for k,v in summary.items() if k not in ('commands','control_A1')},ensure_ascii=False))

if __name__ == '__main__':
    scenario(sys.argv[1])
