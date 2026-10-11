"""Offline-only runner. No subprocess, Docker, or network activity. Synthetic payloads, not saved host observations."""
import time
from pathlib import Path
IMAGE='sha256:1ab784c76aa235cae41c2d1beaa4a96c41e13a25d54488211923e542bf419153'
SB='a'*64; DB='b'*64; MAN='c'*64; MONGO='d'*64
SN='cic-ynu-iotmal-sandbox_sandboxnet'; DN='cic-ynu-iotmal-sandbox_dbnet'
REF=(Path(__file__).parent/'references/4G.source.txt').read_text()
NFT_STDOUT=(Path(__file__).parent/'references/4G.stdout.txt').read_bytes()
NFT_STDERR=(Path(__file__).parent/'references/4G.stderr.txt').read_bytes()
SB_INSPECT=f'{SB}\t{SN}\tbridge\tfalse\t[{{"Subnet":"192.168.60.0/24","Gateway":"192.168.60.1"}}]\t{{}}\n'
DB_INSPECT=f'{DB}\t{DN}\tbridge\tfalse\t[{{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"}}]\t{{"{MONGO}":{{"Name":"mongo-db","EndpointID":"{MONGO}","MacAddress":"92:95:79:0b:84:90","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}}\n'
MANAGER=f'exited\t{MAN}\t0\t2026-10-08T08:42:17Z\t{{"{SN}":{{"IPAddress":"","MacAddress":"","NetworkID":"{SB}"}}}}\n'
MONGO_PAYLOAD=f'running\t{MONGO}\t0\t2026-10-08T08:42:17Z\t{{"{DN}":{{"IPAddress":"172.18.0.2","MacAddress":"92:95:79:0b:84:90","NetworkID":"{DB}"}}}}\n'
def fake_runner(spec=None):
 spec=spec or {};calls=[]
 def answer(argv):
  calls.append(list(argv));j=' '.join(argv)
  if argv[0]=='/usr/bin/docker':
   if 'docker_all' in spec:return spec['docker_all']
   if argv[1]=='version':key,default='version',b'client=29.8.2 server=29.8.2 api=1.51\n'
   elif argv[1]=='info':key,default='info',b'driver=overlay2 cgroup=systemd/2 kernel=6.8.0 os=Ubuntu running=1\n'
   elif argv[1:3]==['image','inspect']:key,default='image',(IMAGE+'\n').encode()
   elif argv[1]=='ps':key,default='ps',f'cic-ynu-iotmal-sandbox-sandbox-manager-1\texited\tsandbox-manager\t{MAN}\nmongo-db\trunning\tmongo\t{MONGO}\n'.encode()
   elif argv[1:3]==['network','ls']:
    sb='sandboxnet' in j;key='ls-sandboxnet' if sb else 'ls-dbnet';default=f'{SB if sb else DB}\t{SN if sb else DN}\n'.encode()
   elif argv[1:3]==['network','inspect']:
    sb=argv[-1] in (SB,'n1');key='inspect-sb' if sb else 'inspect-db';default=(SB_INSPECT if sb else DB_INSPECT).encode()
   elif argv[1]=='inspect':key,default=('manager',MANAGER.encode()) if argv[-1]=='cic-ynu-iotmal-sandbox-sandbox-manager-1' else ('mongo',MONGO_PAYLOAD.encode())
   elif argv[1]=='exec':key,default='exec',b'[]\n'
   else:raise AssertionError('Unexpected Docker fixture verb '+repr(argv))
  elif argv[0]=='/usr/bin/pgrep':key,default='pgrep',b'';return spec.get(key,(1,default,b'',None))
  elif argv[0]=='/usr/sbin/nft':return spec.get('nft',(0,NFT_STDOUT,NFT_STDERR,None))
  elif argv[0]=='/usr/sbin/aa-status':key,default='aa',b'apparmor module is loaded.\n   tcpdump\n'
  else:raise AssertionError('Unexpected external fixture argv '+repr(argv))
  return spec.get(key,(0,default,b'',None))
 answer.calls=calls;return answer
