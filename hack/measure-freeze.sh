#!/usr/bin/env bash
# Native hosted x86_64 relative measurements. JSON output contains raw samples too.
set -euo pipefail
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { echo 'requires disposable hosted runner' >&2; exit 2; }
handover() {
  local prior
  prior=$(systemctl show -p MainPID --value briqyardd)
  sudo systemctl kill --kill-whom=main --signal=SIGUSR2 briqyardd
  for _ in $(seq 1 100); do [ "$(systemctl show -p MainPID --value briqyardd)" != "$prior" ] && break; sleep .1; done
  sudo systemctl start briqyardd
  for _ in $(seq 1 30); do briqyard status >/dev/null 2>&1 && return; sleep 1; done
  return 1
}
measure_config=$(mktemp)
sudo cp /etc/briqyard/config.yaml "$measure_config"
cleanup() { local rc=$?; trap - EXIT; sudo cp "$measure_config" /etc/briqyard/config.yaml; rm -f "$measure_config"; unset BRIQYARD_TOKEN; handover; exit "$rc"; }
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
sudo python3 - <<'CONFIG'
from pathlib import Path
import yaml,hashlib
p=Path('/etc/briqyard/config.yaml'); c=yaml.safe_load(p.read_text())
c['token']='native-freeze-measure'
c['templates']={'enabled':True,'init_ready_init_sha256':hashlib.sha256(Path('/usr/local/bin/briqyard-init').read_bytes()).hexdigest()}
p.write_text(yaml.safe_dump(c,sort_keys=False))
CONFIG
export BRIQYARD_TOKEN=native-freeze-measure
handover
python3 - <<'PY'
import json, os, platform, statistics, subprocess, time, urllib.request
base=os.getenv('BRIQYARD_URL','http://127.0.0.1:7420')
assert base.startswith('http://127.0.0.1:'), 'native loopback host required'
headers={'Content-Type':'application/json'}
if os.getenv('BRIQYARD_TOKEN'): headers['Authorization']='Bearer '+os.environ['BRIQYARD_TOKEN']
def api(method,path,body=None):
    data=None if body is None else json.dumps(body).encode()
    with urllib.request.urlopen(urllib.request.Request(base+'/v1'+path,data,headers,method=method),timeout=180) as r:
        b=r.read(); return json.loads(b) if b else None
def cli(*args): return subprocess.check_output(['briqyard','machine',*args],text=True)
def wait(mid,state):
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        m=api('GET','/machines/'+mid)
        if m['state']==state:return m
        if m['state']=='error': raise RuntimeError('machine failed')
        time.sleep(.02)
    raise TimeoutError(state)
def measure(fn):
    t=time.monotonic();fn();return (time.monotonic()-t)*1000
def summary(xs):
    xs=sorted(xs);return {'n':len(xs),'p50_ms':statistics.median(xs),'p95_ms':xs[max(0,__import__('math').ceil(.95*len(xs))-1)],'max_ms':max(xs),'samples_ms':xs}
samples={}
def record(name,fn,n=20): samples[name]=[measure(fn) for _ in range(n)]
ns='freeze-measure-'+str(os.getpid());ids=[]
def create(cmd=None):
    m=api('POST','/machines',{'namespace':ns,'image':'python:3.12-alpine','size':{'vcpus':1,'memory_mb':512},'cmd':cmd or ['sleep','3600'],'sleep':'never','disk_limits':{'bandwidth_mb':32,'burst_sec':0} if cmd else None})
    ids.append(m['id']);wait(m['id'],'running');return m['id']
def fork(crash=False):
    spec={'machine_id':source}
    if crash:spec['consistency']='crash'
    t=time.monotonic()
    m=api('POST','/machines',{'namespace':ns,'fork':spec,'start':False});ids.append(m['id'])
    wait(m['id'],'created');elapsed=(time.monotonic()-t)*1000
    api('DELETE','/machines/'+m['id']);ids.remove(m['id']);return elapsed
try:
    source=create(); idle_source=source
    # Alternate paired samples to reduce drift; delete timing excluded below by separately
    # measuring the admission and creation boundary.
    for busy in (False,True):
        if busy:
            writer="import os,time,json; f=open('/root/busy','wb',buffering=0); log=open('/tmp/stalls','w',buffering=1); b=os.urandom(1048576)\nwhile not os.path.exists('/tmp/end-writer'):\n t=time.monotonic(); f.seek(0); f.write(b*32); os.fsync(f.fileno()); log.write(str((time.monotonic()-t)*1000)+'\\n')"
            source=create(['python3','-c',writer])
        for i in range(20):
            for crash in (True,False):
                name=('busy' if busy else 'idle')+('_crash_fork_ms' if crash else '_frozen_fork_ms')
                before=[]
                if busy:before=cli('exec',source,'--','cat','/tmp/stalls').splitlines()
                samples.setdefault(name,[]).append(fork(crash))
                if busy:
                    after=cli('exec',source,'--','cat','/tmp/stalls').splitlines()
                    samples.setdefault('writer_'+('crash' if crash else 'frozen')+'_fork_ms',[]).extend(float(x) for x in after[len(before):])
        if busy:
            before_backup=cli('exec',source,'--','cat','/tmp/stalls').splitlines()
            record('busy_backup_ms',lambda:api('POST','/machines/'+source+'/backups',{}))
            all_writes=cli('exec',source,'--','cat','/tmp/stalls').splitlines()
            samples['writer_backup_ms']=[float(x) for x in all_writes[len(before_backup):]]
            api('DELETE','/machines/'+source);ids.remove(source);source=idle_source
    record('backup_ms',lambda:api('POST','/machines/'+source+'/backups',{}))
    for dirty in (1,128):
        def sleep_once():
            cli('exec',source,'--','sh','-c',f'dd if=/dev/zero of=/root/dirty bs=1M count={dirty} 2>/dev/null')
            t=time.monotonic();api('POST','/machines/'+source+'/stop',{'suspend':True});wait(source,'stopped')
            samples.setdefault(f'stop_{dirty}MiB_ms',[]).append((time.monotonic()-t)*1000)
            api('POST','/machines/'+source+'/start',{});wait(source,'running')
        for _ in range(20):sleep_once()
    # Creation ends at running; cleanup is outside the timed interval.
    def create_control():
        t=time.monotonic();mid=create();elapsed=(time.monotonic()-t)*1000
        api('DELETE','/machines/'+mid);ids.remove(mid);return elapsed
    samples['create_ms']=[create_control() for _ in range(20)]
    builder=api('POST','/machines',{'namespace':ns,'name':'warm-builder','image':'docker.io/library/alpine@sha256:85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f','size':{'vcpus':1,'memory_mb':256},'template_build':'init-ready-v1','sleep':'never'})
    ids.append(builder['id']);wait(builder['id'],'running')
    sealed=api('POST','/machines/'+builder['id']+'/snapshots',{'memory':True,'template':True})
    entry={'id':'freeze-control','namespace':ns,'type':'shell','source_machine':builder['id'],'snapshot':sealed['id'],'generation':sealed['clone_generation'],'size':{'vcpus':1,'memory_mb':256,'cpu_millis':1000},'max_ready':1}
    configure="from pathlib import Path; import yaml,json,sys; p=Path('/etc/briqyard/config.yaml'); c=yaml.safe_load(p.read_text()); c['templates'].update(warm_pools=True,warm_policy={'budget':{'memory_mb':2048,'cpu_millis':4000,'root_disk_gb':32},'headroom':{'memory_mb':128,'cpu_millis':0,'disk_free_gb':1},'min_mem_available_mb':128,'max_fills':1,'catalog':[json.loads(sys.argv[1])]}); p.write_text(yaml.safe_dump(c,sort_keys=False))"
    subprocess.run(['sudo','python3','-c',configure,json.dumps(entry)],check=True)
    prior=subprocess.check_output(['systemctl','show','-p','MainPID','--value','briqyardd'],text=True).strip()
    subprocess.run(['sudo','systemctl','kill','--kill-whom=main','--signal=SIGUSR2','briqyardd'],check=True)
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        if subprocess.check_output(['systemctl','show','-p','MainPID','--value','briqyardd'],text=True).strip()!=prior:break
        time.sleep(.1)
    subprocess.run(['sudo','systemctl','start','briqyardd'],check=True)
    for _ in range(30):
        try:api('GET','/namespaces');break
        except Exception:time.sleep(1)
    api('PUT','/namespaces/'+ns+'/warm-catalog/freeze-control',{'desired':1})
    for i in range(20):
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            pools=api('GET','/namespaces/'+ns+'/warm-pools')
            if any(pool['ready'] for pool in pools):break
            time.sleep(.1)
        else:raise TimeoutError('warm refill')
        t=time.monotonic()
        claimed=api('POST','/namespaces/'+ns+'/warm-pools/freeze-control/claims',{'name':'claim-'+str(i),'request_id':'measure-'+str(i)})
        samples.setdefault('warm_claim_ms',[]).append((time.monotonic()-t)*1000)
        ids.append(claimed['id']);api('DELETE','/machines/'+claimed['id']);ids.remove(claimed['id'])
    api('DELETE','/namespaces/'+ns+'/warm-pools/freeze-control')
    for load in ('idle','busy'):
        samples[load+'_fork_added_ms']=[f-c for f,c in zip(samples[load+'_frozen_fork_ms'],samples[load+'_crash_fork_ms'])]
    print(json.dumps({'runner':platform.machine(),'cpus':os.cpu_count(),'shared_hosted_runner':True,'measurements':{k:summary(v) if v else {'n':0} for k,v in samples.items()},'warm_claim':'qualified init-ready-v1, admission through host readiness'},indent=2))
except Exception as error:
    print(json.dumps({'runner':platform.machine(),'cpus':os.cpu_count(),'complete':False,'error':type(error).__name__,'measurements':{k:summary(v) if v else {'n':0} for k,v in samples.items()}},indent=2),flush=True)
    raise
finally:
    try:api('DELETE','/namespaces/'+ns+'/warm-pools/freeze-control')
    except Exception:pass
    for mid in ids:
        try:api('DELETE','/machines/'+mid)
        except Exception:pass
    for machine in api('GET','/machines?namespace='+ns):
        try:api('DELETE','/machines/'+machine['id'])
        except Exception:pass
    api('DELETE','/namespaces/'+ns)
PY
