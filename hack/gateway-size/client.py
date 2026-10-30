"""Synthetic load; any incomplete or incorrect worker makes the command fail."""
import asyncio, collections, json, ssl, sys, time, statistics, uuid

PLACEHOLDER = b'briq_secret_a1b2c3d4e5f6a7b8'
SECRET = b'benchmark-secret-value-0123456789'
EVENT = b'data: ' + PLACEHOLDER + b'\n\n'
IO_TIMEOUT = 10
MIN_STREAM_OVERLAP = 5

async def bounded(awaitable):
    return await asyncio.wait_for(awaitable, IO_TIMEOUT)

async def headers(r):
    head = await bounded(r.readuntil(b'\r\n\r\n'))
    lines = head.split(b'\r\n')
    if lines[0].split()[1] != b'200':
        raise ValueError('unexpected response: ' + repr(lines[0]))
    return {k.lower(): v.strip() for k, v in
            (line.split(b':', 1) for line in lines[1:] if line)}

async def chunk(r):
    line = await bounded(r.readline())
    if not line:
        raise EOFError('stream closed before its terminating chunk')
    n = int(line.strip().split(b';', 1)[0], 16)
    if not 0 <= n <= 1024 * 1024:
        raise ValueError('invalid or unexpectedly large response chunk')
    data = await bounded(r.readexactly(n))
    if await bounded(r.readexactly(2)) != b'\r\n':
        raise ValueError('invalid chunk terminator')
    return data

async def response(r, expected=EVENT):
    h = await headers(r)
    if h.get(b'transfer-encoding') == b'chunked':
        body = bytearray()
        while True:
            data = await chunk(r)
            if not data:
                break
            body.extend(data)
            if len(body) > 65536:
                raise ValueError('unexpectedly large echo response')
    else:
        n = int(h[b'content-length'])
        if not 0 <= n <= 65536:
            raise ValueError('unexpected echo response length')
        body = await bounded(r.readexactly(n))
    if body != expected:
        raise ValueError('echo was not correctly scrubbed')

async def main():
    mode, concurrency, gateway = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    body_mb = int(sys.argv[4] if len(sys.argv) > 4 else '8')
    route = sys.argv[5] if len(sys.argv) > 5 else 'proxy'
    connect_limit = int(sys.argv[6]) if len(sys.argv) > 6 else 0
    ramp_per_second = float(sys.argv[7]) if len(sys.argv) > 7 else 0
    if route not in ('proxy', 'direct') or connect_limit < 0 or ramp_per_second < 0:
        raise ValueError('invalid route or connection limit')
    if mode not in ('bodies', 'streams', 'throughput') or concurrency <= 0 or body_mb <= 0:
        raise ValueError('invalid workload arguments')
    tls = ssl.create_default_context(cafile='/tmp/gateway-ca.pem' if route == 'proxy' else '/tmp/bench-ca.pem')
    expected_event = EVENT if route == 'proxy' else b'data: ' + SECRET + b'\n\n'
    connect_slots = asyncio.Semaphore(connect_limit or concurrency)
    stage_times = collections.defaultdict(list)
    error_stages = collections.Counter()
    loop_lags = []
    async def monitor_loop():
        while True:
            before = time.monotonic()
            await asyncio.sleep(.05)
            loop_lags.append(max(0, time.monotonic() - before - .05) * 1000)
    errors, ttft, latencies = [], [], []
    established = completed = live = peak_live = 0
    active_streams = peak_streams = 0
    all_streams_since = None
    all_streams_seconds = 0.0
    stream_group = uuid.uuid4().hex
    body_ready = asyncio.Event()

    async def worker(index):
        nonlocal established, completed, live, peak_live
        nonlocal active_streams, peak_streams, all_streams_since, all_streams_seconds
        w = None
        counted = False
        streaming = False
        slot = False
        stage = 'queued'
        stage_started = time.monotonic()
        def mark(next_stage):
            nonlocal stage, stage_started
            now = time.monotonic()
            stage_times[stage].append((now - stage_started) * 1000)
            stage, stage_started = next_stage, now
        try:
            async with asyncio.timeout(100):
                if ramp_per_second:
                    mark('ramp_delay')
                    await asyncio.sleep(index / ramp_per_second)
                mark('queued')
                start = time.monotonic()
                await connect_slots.acquire()
                slot = True
                mark('tcp_connect')
                target, port = (gateway, 3128) if route == 'proxy' else ('bench.internal', 443)
                r, w = await bounded(asyncio.open_connection(target, port))
                if route == 'proxy':
                    mark('connect_response')
                    w.write(b'CONNECT bench.internal:443 HTTP/1.1\r\nHost: bench.internal:443\r\n\r\n')
                    await bounded(w.drain())
                    await headers(r)
                mark('tls_handshake')
                await bounded(w.start_tls(tls, server_hostname='bench.internal'))
                mark('request')
                if mode != 'streams':
                    connect_slots.release()
                    slot = False
                live += 1
                counted = True
                peak_live = max(peak_live, live)
                auth = b'Host: bench.internal:443\r\nAuthorization: ' + (PLACEHOLDER if route == 'proxy' else SECRET) + b'\r\n'
                if mode == 'bodies':
                    n = body_mb * 1024 * 1024
                    mark('body_upload')
                    w.write(b'POST /echo HTTP/1.1\r\n' + auth +
                            f'Content-Length: {n}\r\nX-Benchmark-Body-Length: {n}\r\n\r\n'.encode())
                    w.write(PLACEHOLDER)
                    remaining = n - len(PLACEHOLDER) - 1
                    block = b'x' * (64 * 1024)
                    while remaining:
                        size = min(remaining, len(block))
                        w.write(block[:size])
                        await bounded(w.drain())
                        remaining -= size
                        # SSL write is synchronous; bound each encryption batch and yield.
                        await asyncio.sleep(0)
                    established += 1
                    if established == concurrency:
                        body_ready.set()
                    mark('body_barrier')
                    await asyncio.wait_for(body_ready.wait(), 60)
                    mark('body_hold')
                    # Hold all bodies together, then trigger the rewrite allocation peak.
                    await asyncio.sleep(5)
                    mark('body_final_byte')
                    w.write(b'x')
                    await bounded(w.drain())
                    mark('body_response')
                    await response(r, expected_event)
                elif mode == 'streams':
                    group_headers = f'X-Benchmark-Stream-Group: {stream_group}\r\nX-Benchmark-Stream-Count: {concurrency}\r\n'.encode()
                    w.write(b'GET /stream HTTP/1.1\r\n' + auth + group_headers + b'\r\n')
                    await bounded(w.drain())
                    mark('response_headers')
                    h = await headers(r)
                    mark('first_event')
                    if h.get(b'transfer-encoding') != b'chunked':
                        raise ValueError('stream response must be chunked')
                    pending = bytearray()
                    events = 0
                    while True:
                        data = await chunk(r)
                        if not data:
                            break
                        pending.extend(data)
                        # HTTP chunk boundaries need not coincide with SSE boundaries.
                        while b'\n\n' in pending:
                            end = pending.index(b'\n\n') + 2
                            event = bytes(pending[:end])
                            del pending[:end]
                            if event == b': waiting\n\n':
                                continue
                            if event != expected_event:
                                raise ValueError('stream event was not correctly scrubbed')
                            events += 1
                            if events == 1:
                                mark('stream_read')
                                ttft.append((time.monotonic() - start) * 1000)
                                established += 1
                                active_streams += 1
                                streaming = True
                                peak_streams = max(peak_streams, active_streams)
                                if active_streams == concurrency:
                                    all_streams_since = time.monotonic()
                                # Pace both TLS legs, through the first upstream event.
                                connect_slots.release()
                                slot = False
                        if len(pending) > len(expected_event) or events > 30:
                            raise ValueError('unexpected stream payload')
                    if events != 30 or pending:
                        raise ValueError(f'incomplete stream: {events}/30 events')
                else:
                    established += 1
                    until = time.monotonic() + 10
                    while time.monotonic() < until:
                        before = time.monotonic()
                        w.write(b'GET /echo HTTP/1.1\r\n' + auth + b'\r\n')
                        await bounded(w.drain())
                        await response(r, expected_event)
                        latencies.append((time.monotonic() - before) * 1000)
                mark('complete')
                completed += 1
        except Exception as e:
            error_stages[stage] += 1
            errors.append(stage + ': ' + type(e).__name__ + ': ' + str(e))
        finally:
            if streaming:
                if active_streams == concurrency and all_streams_since is not None:
                    all_streams_seconds += time.monotonic() - all_streams_since
                    all_streams_since = None
                active_streams -= 1
            if slot:
                connect_slots.release()
            if counted:
                live -= 1
            if w:
                w.close()
                try:
                    await asyncio.wait_for(w.wait_closed(), 2)
                except Exception:
                    pass

    start = time.monotonic()
    monitor = asyncio.create_task(monitor_loop())
    try:
        await asyncio.gather(*(worker(i) for i in range(concurrency)))
    finally:
        monitor.cancel()
        try:
            await monitor
        except asyncio.CancelledError:
            pass
    elapsed = time.monotonic() - start
    if mode == 'streams' and (peak_streams != concurrency or all_streams_seconds < MIN_STREAM_OVERLAP):
        errors.append(f'insufficient stream overlap: peak={peak_streams}, seconds={all_streams_seconds:.3f}')
    def summary(a):
        a = sorted(a)
        return {'p50': statistics.median(a), 'p95': a[min(len(a)-1, int(len(a)*.95))], 'max': a[-1]} if a else None
    print(json.dumps({'mode': mode, 'route': route, 'connect_limit': connect_limit, 'ramp_per_second': ramp_per_second,
          'peak_active_streams': peak_streams, 'all_streams_seconds': all_streams_seconds,
          'python': sys.version, 'openssl': ssl.OPENSSL_VERSION,
          'stage_ms': {key: summary(value) for key, value in stage_times.items()},
          'event_loop_lag_ms': summary(loop_lags), 'error_stages': dict(error_stages),
          'concurrency': concurrency, 'established': established,
          'completed': completed, 'peak_live_connections': peak_live,
          'io_timeout_s': IO_TIMEOUT, 'worker_timeout_s': 100,
          'seconds': elapsed, 'requests': len(latencies), 'rps': len(latencies)/elapsed,
          'latency_ms': summary(latencies), 'ttft_ms': summary(ttft),
          'errors': errors[:5], 'error_count': len(errors)}), flush=True)
    return 1 if errors or completed != concurrency else 0

if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
