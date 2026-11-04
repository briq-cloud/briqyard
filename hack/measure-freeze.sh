#!/usr/bin/env bash
# Native hosted x86_64 relative measurements. JSON output contains raw samples too.
set -euo pipefail
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
samples={}
def record(name,fn,n=20): samples[name]=[measure(fn) for _ in range(n)]
ns='freeze-measure-'+str(os.getpid());ids=[]
api('POST','/namespaces',{'name':ns})
def create(cmd=None):
    m=api('POST','/machines',{'namespace':ns,'image':'python:3.12-alpine','size':{'vcpus':1,'memory_mb':512},'cmd':cmd or ['sleep','3600'],'sleep':'never'})
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
            writer="import os,time,json; f=open('/root/busy','wb',buffering=0); log=open('/tmp/stalls','w',buffering=1); b=b'x'*1048576\nwhile not os.path.exists('/tmp/end-writer'):\n t=time.monotonic(); f.seek(0); f.write(b*32); os.fsync(f.fileno()); log.write(str((time.monotonic()-t)*1000)+'\\n')"
            source=create(['python3','-c',writer])
        for i in range(20):
            for crash in (True,False):
                name=('busy' if busy else 'idle')+('_crash_fork_ms' if crash else '_frozen_fork_ms')
                samples.setdefault(name,[]).append(fork(crash))
        if busy:
            record('busy_backup_ms',lambda:api('POST','/machines/'+source+'/backups',{}))
            samples['writer_write_fsync_ms']=[float(x) for x in cli('exec',source,'--','cat','/tmp/stalls').splitlines()]
            api('DELETE','/machines/'+source);ids.remove(source);source=idle_source
    record('backup_ms',lambda:api('POST','/machines/'+source+'/backups',{}))
    for dirty in (1,128):
        def sleep_once():
            cli('exec',source,'--','sh','-c',f'dd if=/dev/zero of=/root/dirty bs=1M count={dirty} 2>/dev/null')
            t=time.monotonic();api('POST','/machines/'+source+'/stop',{'suspend':True});wait(source,'stopped')
            samples.setdefault(f'stop_{dirty}MiB_ms',[]).append((time.monotonic()-t)*1000)
            api('POST','/machines/'+source+'/start',{});wait(source,'running')
        for _ in range(20):sleep_once()
    # Create control: same script on baseline and candidate. Warm claim needs an operator's
    # qualified catalog; report unavailable rather than invent a synthetic substitute.
    def create_control():
        mid=create();api('DELETE','/machines/'+mid);ids.remove(mid)
    record('create_ms',create_control)
    def summary(xs):
        xs=sorted(xs);return {'n':len(xs),'p50_ms':statistics.median(xs),'p95_ms':xs[max(0,__import__('math').ceil(.95*len(xs))-1)],'max_ms':max(xs),'samples_ms':xs}
    print(json.dumps({'runner':platform.machine(),'cpus':os.cpu_count(),'shared_hosted_runner':True,'measurements':{k:summary(v) for k,v in samples.items()},'warm_claim':'not measured: requires qualified catalog'},indent=2))
finally:
    for mid in ids:
        try:api('DELETE','/machines/'+mid)
        except Exception:pass
    api('DELETE','/namespaces/'+ns)
PY
