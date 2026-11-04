#!/usr/bin/env python3
"""Disposable native host: crash and hand-over with a real daemon-owned send stopped."""
import json
import os
from pathlib import Path
import signal
import select
import subprocess
import sys
import time

machine, namespace, image = sys.argv[1:]

def cli(*args, timeout=60):
    return subprocess.check_output(['briqyard', *args], timeout=timeout, text=True)

def mainpid():
    return int(subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', 'briqyardd'], text=True, timeout=5))

for sig in (signal.SIGKILL, signal.SIGUSR2):
    cli('machine', 'exec', '--timeout', '120s', machine, '--', 'sh', '-c',
        'head -c 300000000 /dev/urandom > /data/helper-cut; sync', timeout=130)
    daemon = mainpid()
    cursor = subprocess.check_output(['journalctl', '-u', 'briqyardd', '-n', '0', '--show-cursor'], text=True, timeout=5).split('-- cursor: ')[1].strip()
    client = subprocess.Popen(['briqyard', 'machine', 'backup', machine], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    held = None
    success = False
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and held is None:
            for proc in Path('/proc').glob('[0-9]*'):
                fd = None
                try:
                    stat = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
                    args = (proc / 'cmdline').read_bytes().split(b'\0')
                    if int(stat[1]) != daemon or args[1:2] != [b'send'] or (proc / 'exe').resolve().name != 'zfs':
                        continue
                    fd = os.pidfd_open(int(proc.name))
                    # Recheck after retaining the incarnation; never signal a reused numeric PID.
                    if (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19] != stat[19]:
                        continue
                    signal.pidfd_send_signal(fd, signal.SIGSTOP)
                    held = fd
                    break
                except (FileNotFoundError, ProcessLookupError):
                    continue
                finally:
                    if fd is not None and fd != held:
                        os.close(fd)
            time.sleep(0.01)
        assert held is not None, 'no daemon-owned zfs send caught'
        os.kill(daemon, sig)
        # Hold it until the NEW daemon reports the wait. Old code never emits this event.
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            logs = subprocess.check_output(['journalctl', '-u', 'briqyardd', '--after-cursor', cursor, '-o', 'cat', '--no-pager'], text=True, timeout=5)
            if mainpid() not in (0, daemon) and (
                'waiting for previous daemon service members to exit' in logs
                or (sig == signal.SIGUSR2 and select.select([held], [], [], 0)[0])
            ):
                break
            time.sleep(0.1)
        else:
            raise AssertionError('new daemon never waited on the stopped helper')
        try:
            signal.pidfd_send_signal(held, signal.SIGCONT)
        except ProcessLookupError:
            pass
        started = time.monotonic()
        created = json.loads(cli('machine', 'run', '--namespace', namespace, '--name', f'helper-{sig.value}', '--image', image, '--sleep', 'never', '--', 'sleep', '60', timeout=30))
        assert time.monotonic() - started < 30
        cli('machine', 'wait', '--for', 'running', created['id'], timeout=30)
        cli('machine', 'rm', created['id'])
        success = True
        print(f'  helper recovery after {sig.name}: create accepted within 30 s', flush=True)
    finally:
        if held is not None:
            try:
                signal.pidfd_send_signal(held, signal.SIGCONT)
            except ProcessLookupError:
                pass
            os.close(held)
        if client.poll() is None:
            client.terminate()
        try:
            client.wait(timeout=5)
        except subprocess.TimeoutExpired:
            client.kill()
            client.wait()

        if not success:
            subprocess.run(['systemctl', 'restart', 'briqyardd'], timeout=30, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
