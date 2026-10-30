"""One explicit large-config refusal/recovery scenario, never a load-test retry policy.

Three requests must return capacity 503 on one TLS connection. Then the fixture switches to
its small config and only capacity 503 is polled for up to 15s; transport errors and other
statuses fail immediately. A success leaves the small-config marker until fixture teardown.
Configure the gateway refresh interval to 1s or less for this dedicated scenario.
"""
import contextlib
import http.client
import json
import signal
import ssl
import sys
import time

from server import PLACEHOLDER, SECRET, SMALL_CONFIG, configured_secrets

CAPACITY = b'credential gateway capacity exceeded\n'
MAX_REPLY = 4096
IO_TIMEOUT = 3
RECOVERY_TIMEOUT = 15


def exchange(connection, socket, secrets, timeout):
    if connection.sock is not socket:
        raise RuntimeError('the original TLS connection was lost')
    socket.settimeout(timeout)
    connection.request('GET', '/echo', headers={'Host': 'bench.internal', 'Authorization': PLACEHOLDER})
    response = connection.getresponse()
    headers = '\r\n'.join(f'{key}: {value}' for key, value in response.getheaders()).encode('latin-1')
    body = response.read(MAX_REPLY + 1)
    if len(body) > MAX_REPLY:
        raise ValueError('unexpectedly large guard response')
    if any(secret in headers or secret in body for secret in secrets):
        raise ValueError('a synthetic secret leaked in the guard response')
    if connection.sock is not socket:
        raise RuntimeError('the gateway closed the original TLS connection')
    if response.status == 503 and body != CAPACITY:
        raise ValueError('503 was not a rewrite-capacity refusal')
    return response.status, body


@contextlib.contextmanager
def recovery_deadline():
    """A hard wall deadline also interrupts a peer that trickles individual HTTP reads."""
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_delay, interval = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    def expired(signum, frame):
        raise TimeoutError('small config did not recover within 15 seconds')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(RECOVERY_TIMEOUT, previous_delay) if previous_delay else RECOVERY_TIMEOUT)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_delay:
            signal.setitimer(signal.ITIMER_REAL, max(.001, previous_delay - (time.monotonic() - started)), interval)


def run_guard(connection, marker=SMALL_CONFIG, secrets=None, clock=time.monotonic, sleep=time.sleep):
    secrets = secrets if secrets is not None else [s['value'].encode('utf-8') for s in configured_secrets()]
    if marker.exists():
        raise RuntimeError('small config is already enabled; guard requires a fresh fixture')
    switched = False
    recovered = False
    try:
        connection.connect()
        socket = connection.sock
        if socket is None:
            raise RuntimeError('TLS connection was not established')
        for _ in range(3):
            status, _ = exchange(connection, socket, secrets, IO_TIMEOUT)
            if status != 503:
                raise ValueError(f'large config was not refused: status {status}')
        # This is the sole intentional state transition. No failed load is retried above.
        with marker.open('x') as f:
            f.write('serve only the primary benchmark credential\n')
        switched = True
        started = clock()
        deadline = started + RECOVERY_TIMEOUT
        polls = 0
        with recovery_deadline():
            while True:
                remaining = deadline - clock()
                if remaining <= 0:
                    raise TimeoutError('small config did not recover within 15 seconds')
                status, body = exchange(connection, socket, secrets, min(IO_TIMEOUT, remaining))
                polls += 1
                if status == 200:
                    if body != b'data: ' + PLACEHOLDER.encode() + b'\n\n':
                        raise ValueError('recovery response was not correctly scrubbed')
                    elapsed = clock() - started
                    if elapsed > RECOVERY_TIMEOUT:
                        raise TimeoutError('recovery response missed its deadline')
                    recovered = True
                    return dict(mode='guard', concurrency=1, established=1, completed=1,
                                refused=3, recovered=True, same_tls_connection=True,
                                recovery_seconds=elapsed, recovery_polls=polls,
                                secret_count=len(secrets), secret_bytes=sum(map(len, secrets)),
                                error_count=0, errors=[])
                if status != 503:
                    raise ValueError(f'unexpected config-recovery status {status}')
                sleep(min(.2, max(0, deadline - clock())))
    finally:
        connection.close()
        if switched and not recovered:
            marker.unlink(missing_ok=True)


def main():
    if len(sys.argv) < 4 or sys.argv[1] != 'guard' or int(sys.argv[2]) != 1:
        raise ValueError('usage: guard.py guard 1 GATEWAY_IP [body_mb proxy ...]')
    if len(sys.argv) > 5 and sys.argv[5] != 'proxy':
        raise ValueError('guard requires the proxy route')
    def expired(signum, frame):
        raise TimeoutError('guard command exceeded 35 seconds')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 35)
    connection = None
    try:
        context = ssl.create_default_context(cafile='/tmp/gateway-ca.pem')
        connection = http.client.HTTPSConnection(sys.argv[3], 3128, context=context, timeout=IO_TIMEOUT)
        connection.set_tunnel('bench.internal', 443)
        print(json.dumps(run_guard(connection)), flush=True)
    finally:
        if connection is not None:
            connection.close()
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    main()
