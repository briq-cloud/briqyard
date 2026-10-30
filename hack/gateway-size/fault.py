"""One native gateway kill/recovery check; no request is silently retried.

Usage: fault.py GATEWAY_IP (or fault.py fault 1 GATEWAY_IP ...).
After the first validated SSE event, create /tmp/fault-ready. The parent writes
/tmp/fault-injected before killing Firecracker, verifies its replacement, and writes
/tmp/fault-release. One fresh request must then work with the original CA trust.
"""
import hashlib
import http.client
import json
import signal
import ssl
import sys
import time
from pathlib import Path

from server import PLACEHOLDER, configured_secrets

READY = Path('/tmp/fault-ready')
INJECTED = Path('/tmp/fault-injected')
RELEASE = Path('/tmp/fault-release')
CA = Path('/tmp/gateway-ca.pem')
IO_TIMEOUT = 10
RELEASE_TIMEOUT = 90
MAX_REPLY = 4096
EVENT = b'data: ' + PLACEHOLDER.encode()
INTERRUPTIONS = (OSError, http.client.IncompleteRead, http.client.RemoteDisconnected)


def no_leak(data, secrets):
    if any(secret in data for secret in secrets):
        raise ValueError('a synthetic secret leaked during the fault scenario')


def headers(response, secrets):
    # http.client decodes the wire headers as Latin-1; recover the original bytes.
    no_leak('\r\n'.join(f'{k}: {v}' for k, v in response.getheaders()).encode('latin-1'), secrets)


class Events:
    def __init__(self, response, secrets):
        self.response = response
        self.secrets = secrets
        self.pending = b''

    def next(self):
        while b'\n\n' not in self.pending:
            try:
                data = self.response.read1(MAX_REPLY + 1)
            except http.client.IncompleteRead as error:
                no_leak(self.pending + error.partial, self.secrets)
                raise
            if not data:
                # A naturally completed HTTP body is not evidence of an injected failure,
                # even if the parent already wrote its intention-to-kill marker.
                raise RuntimeError('SSE completed cleanly instead of being interrupted')
            self.pending += data
            no_leak(self.pending, self.secrets)
            if len(self.pending) > 2 * MAX_REPLY:
                raise ValueError('unexpectedly large SSE event')
        event, _, self.pending = self.pending.partition(b'\n\n')
        if event not in (EVENT, b': waiting'):
            raise ValueError('SSE event was not correctly scrubbed')
        return event


def connect(gateway, context):
    connection = http.client.HTTPSConnection(gateway, 3128, context=context, timeout=IO_TIMEOUT)
    connection.set_tunnel('bench.internal', 443)
    return connection


def request(connection, path):
    connection.request('GET', path, headers={'Host': 'bench.internal', 'Authorization': PLACEHOLDER})
    return connection.getresponse()


def run_fault(gateway, *, ca_path=CA, ready=READY, injected=INJECTED, release=RELEASE,
              connection_factory=connect, clock=time.monotonic, sleep=time.sleep):
    if any(path.exists() for path in (ready, injected, release)):
        raise RuntimeError('fault markers already exist; a fresh fixture is required')
    original_ca = ca_path.read_bytes()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=original_ca.decode('ascii'))
    secrets = [s['value'].encode('utf-8') for s in configured_secrets()]
    connection = recovery = None
    owned = False
    try:
        connection = connection_factory(gateway, context)
        response = request(connection, '/stream')
        headers(response, secrets)
        if response.status != 200 or response.getheader('content-type', '').split(';')[0] != 'text/event-stream':
            raise ValueError('initial SSE request did not return a stream')
        events = Events(response, secrets)
        if events.next() != EVENT:
            raise ValueError('first SSE event was not the expected scrubbed data')
        with ready.open('x') as marker:
            marker.write('first scrubbed SSE event observed\n')
        owned = True
        event_count = 1
        try:
            while True:
                if events.next() == EVENT:
                    event_count += 1
        except INTERRUPTIONS as error:
            if not injected.exists():
                raise RuntimeError('stream failed before the fault-injected marker') from error
            interruption = type(error).__name__
        finally:
            connection.close()
            connection = None
        # Wait only for the parent's explicit verification; never retry a failed request.
        wait_started = clock()
        deadline = wait_started + RELEASE_TIMEOUT
        while not release.exists():
            remaining = deadline - clock()
            if remaining <= 0:
                raise TimeoutError('parent did not release recovery within 90 seconds')
            sleep(min(.05, remaining))
        waited = clock() - wait_started
        if ca_path.read_bytes() != original_ca:
            raise ValueError('gateway CA changed across the restart')
        recovery_started = clock()
        recovery = connection_factory(gateway, context)
        response = request(recovery, '/echo')
        headers(response, secrets)
        body = response.read(MAX_REPLY + 1)
        no_leak(body, secrets)
        if response.status != 200 or body != EVENT + b'\n\n':
            raise ValueError('fresh recovery request was not correctly scrubbed')
        if ca_path.read_bytes() != original_ca:
            raise ValueError('gateway CA changed during recovery')
        return dict(mode='fault', concurrency=1, established=1, completed=1,
                    interrupted_after_injection=True, interruption=interruption,
                    events_before_interruption=event_count, release_wait_seconds=waited,
                    recovered=True, recovery_seconds=clock() - recovery_started,
                    ca_unchanged=True, original_ca_sha256=hashlib.sha256(original_ca).hexdigest(),
                    error_count=0, errors=[])
    finally:
        for current in (connection, recovery):
            if current is not None:
                current.close()
        # Only a worker that created ready owns this scenario's coordination markers.
        if owned:
            for path in (ready, injected, release):
                path.unlink(missing_ok=True)


class CommandTimeout(RuntimeError):
    pass


def main():
    if len(sys.argv) == 2:
        gateway = sys.argv[1]
    elif len(sys.argv) >= 4 and sys.argv[1:3] == ['fault', '1']:
        gateway = sys.argv[3]
        if len(sys.argv) > 5 and sys.argv[5] != 'proxy':
            raise ValueError('fault requires the proxy route')
    else:
        raise ValueError('usage: fault.py GATEWAY_IP or fault.py fault 1 GATEWAY_IP ...')
    def expired(signum, frame):
        raise CommandTimeout('fault command exceeded 120 seconds')
    def stopped(signum, frame):
        raise RuntimeError(f'fault command stopped by signal {signum}')
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, stopped)
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 120)
    try:
        print(json.dumps(run_fault(gateway)), flush=True)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    main()
