#!/usr/bin/env python3
"""Disposable native host: real sends, automatic recovery, retained endpoint traffic.

SIGKILL is the regression; SIGUSR2 is a graceful drain control, not an old-code
failure claim. --kill-only runs the differential check against an older source.
"""
import http.client
import json
import os
from pathlib import Path
import signal
import select
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

IMAGE = 'alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc'
NS = f'recovery-helper-{os.getpid()}'

def interrupted(signum, _frame):
    raise SystemExit(128 + signum)

for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, interrupted)

def cli(*args, timeout=60):
    return subprocess.check_output(['briqyard', *args], timeout=timeout, text=True, stderr=subprocess.DEVNULL)

def mainpid():
    return int(subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', 'briqyardd'], text=True, timeout=5))

def status():
    req = urllib.request.Request(os.environ.get('BRIQYARD_URL', 'http://127.0.0.1:7420') + '/v1/status')
    if os.environ.get('BRIQYARD_TOKEN'):
        req.add_header('Authorization', 'Bearer ' + os.environ['BRIQYARD_TOKEN'])
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError):
        return None

def fault():
    current = status()
    return next((c for c in current['conditions'] if c['type'] == 'memory_protection' and c['status']), None) if current else None

def until(predicate, seconds, why):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError(why)

def paused_send(daemon):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        for proc in Path('/proc').glob('[0-9]*'):
            fd = None
            keep = False
            try:
                stat = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
                args = (proc / 'cmdline').read_bytes().split(b'\0')
                if int(stat[1]) != daemon or args[1:2] != [b'send'] or (proc / 'exe').resolve().name != 'zfs':
                    continue
                fd = os.pidfd_open(int(proc.name))
                if (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19] != stat[19]:
                    continue
                signal.pidfd_send_signal(fd, signal.SIGSTOP)
                keep = True
                return fd
            except (FileNotFoundError, ProcessLookupError):
                pass
            finally:
                if fd is not None and not keep:
                    os.close(fd)
        time.sleep(0.01)
    raise AssertionError('no daemon-owned zfs send caught')

def resume(fd):
    try:
        signal.pidfd_send_signal(fd, signal.SIGCONT)
    except ProcessLookupError:
        pass

def run_case(machine, endpoint, kind):
    cli('machine', 'exec', '--timeout', '120s', machine, '--', 'sh', '-c',
        'head -c 300000000 /dev/urandom > /data/helper-cut; sync', timeout=130)
    daemon = mainpid()
    cursor = subprocess.check_output(['journalctl', '-u', 'briqyardd', '-n', '0', '--show-cursor'], text=True, timeout=5).split('-- cursor: ')[1].strip()
    client = subprocess.Popen(['briqyard', 'machine', 'backup', machine], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    held = None
    vmfd = None
    created = None
    stop = threading.Event()
    samples = []
    failures = []
    def traffic():
        while not stop.is_set():
            # Process exit can reset an accepted connection (ADR 0051). Retry
            # transport cuts within one request budget; sustained listener loss
            # throughout the 65-second diagnostic window still fails this check.
            deadline = time.monotonic() + 25
            while not stop.is_set():
                conn = http.client.HTTPConnection('127.0.0.1', endpoint['host_port'],
                                                  timeout=max(0.1, deadline - time.monotonic()))
                try:
                    conn.request('GET', '/marker')
                    response = conn.getresponse()
                    assert response.status == 200 and response.read().strip() == b'helper-alive'
                    samples.append(time.monotonic())
                    break
                except (OSError, http.client.HTTPException):
                    if time.monotonic() >= deadline:
                        failures.append(True)
                        break
                    stop.wait(0.1)
                except Exception:
                    failures.append(True)
                    break
                finally:
                    conn.close()
            stop.wait(0.1)
    probe = threading.Thread(target=traffic)
    try:
        group = Path('/sys/fs/cgroup/firecracker') / machine.replace('_', '-') / 'cgroup.procs'
        vmm = int(group.read_text().strip())  # Exactly one existing VMM.
        vmfd = os.pidfd_open(vmm)
        exited = select.poll()
        exited.register(vmfd, select.POLLIN)
        assert group.read_text().split() == [str(vmm)] and not exited.poll(0)
        held = paused_send(daemon)
        probe.start()
        os.kill(daemon, signal.SIGUSR2 if kind == 'handover' else signal.SIGKILL)
        if kind == 'handover':
            # Release during the OLD daemon's drain, before SHUTDOWN (60 s).
            # This control proves healthy hand-over, not a legacy recovery regression.
            until(lambda: 'shutting down' in subprocess.check_output(
                ['journalctl', '-u', 'briqyardd', '--after-cursor', cursor, '-o', 'cat', '--no-pager'], text=True, timeout=5), 20, 'handover did not begin draining')
            resume(held)
        elif kind == 'late':
            condition = until(fault, 30, 'timeout never reported memory_protection')
            assert 'recovery_unresolved' in condition['message']
            diagnostic_pid = mainpid()
            # Longer than the production alert's one-minute pending interval.
            began = time.monotonic()
            while time.monotonic() - began < 65:
                assert mainpid() == diagnostic_pid, 'persistent helper caused a restart loop'
                current = fault()
                assert current and current['since'] == condition['since'], 'fault age reset'
                time.sleep(0.5)
            assert samples and not failures, 'endpoints stopped serving during the timeout'
            resume(held)
            until(lambda: mainpid() not in (0, diagnostic_pid), 30, 'no automatic restart after helper exit')
        else:
            # Candidate: observe its wait. Old source: observe its latched fault.
            # Both branches resume the helper and test actual admission afterwards.
            def waiting_or_faulted():
                logs = subprocess.check_output(['journalctl', '-u', 'briqyardd', '--after-cursor', cursor, '-o', 'cat', '--no-pager'], text=True, timeout=5)
                return mainpid() not in (0, daemon) and ('waiting for previous daemon service members to exit' in logs or fault())
            until(waiting_or_faulted, 30, 'replacement daemon did not reach recovery')
            resume(held)
        until(lambda: mainpid() not in (0, daemon) and (s := status()) and not any(c['type'] == 'memory_protection' and c['status'] for c in s['conditions']), 35, 'host stayed fenced after helper exit')
        assert not exited.poll(0) and group.read_text().split() == [str(vmm)], 'original VMM did not survive recovery'
        assert json.loads(cli('machine', 'get', machine))['state'] == 'running', 'source VM was not adopted'
        created = json.loads(cli('machine', 'run', '--namespace', NS, '--name', f'create-{kind}', '--image', IMAGE, '--sleep', 'never', '--', 'sleep', '60', timeout=30))
        cli('machine', 'wait', '--for', 'running', created['id'], timeout=30)
        cli('machine', 'rm', created['id'])
        created = None
        assert samples and not failures, 'endpoint traffic failed across recovery'
        print(f'helper check passed: {kind}; endpoint samples={len(samples)}', flush=True)
    finally:
        if vmfd is not None:
            os.close(vmfd)
        if held is not None:
            resume(held)
            os.close(held)
        stop.set()
        if probe.ident is not None:
            probe.join(timeout=26)
            assert not probe.is_alive(), 'endpoint probe did not end'
        if client.poll() is None:
            client.terminate()
        try:
            client.wait(timeout=5)
        except subprocess.TimeoutExpired:
            client.kill()
            client.wait()
        if created is not None:
            cli('machine', 'rm', created['id'])

machine = None
kinds = ['kill'] if '--kill-only' in sys.argv else ['kill', 'late', 'handover']
passed = 0
try:
    machine = json.loads(cli('machine', 'run', '--namespace', NS, '--name', 'source', '--image', IMAGE,
        '--memory', '256', '--volume', '1G:/data', '--sleep', 'never', '--', 'sh', '-c',
        'echo helper-alive > /data/marker; exec httpd -f -p 8080 -h /data'))['id']
    cli('machine', 'wait', '--for', 'running', machine)
    endpoint = json.loads(cli('endpoint', 'add', machine, '8080'))
    for kind in kinds:
        run_case(machine, endpoint, kind)
        passed += 1
finally:
    print(f'helper cases passed {passed}/{len(kinds)}', flush=True)
    # Recover the disposable fixture even when an old binary latches its fault.
    if fault():
        subprocess.run(['systemctl', 'restart', 'briqyardd'], timeout=30, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if machine:
        cli('machine', 'rm', machine)
    cli('namespace', 'rm', NS)
