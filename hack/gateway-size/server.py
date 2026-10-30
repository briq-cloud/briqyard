import asyncio, json, os, signal, ssl, time
from pathlib import Path

SECRET = 'benchmark-secret-value-0123456789'
PLACEHOLDER = 'briq_secret_a1b2c3d4e5f6a7b8'
STREAM_GROUPS = {}

async def wait_for_peers(headers, w):
    group_id = headers.get(b'x-benchmark-stream-group', b'')
    count = int(headers.get(b'x-benchmark-stream-count', b'1'))
    if not group_id or count == 1:
        return
    if not 1 <= count <= 10000:
        raise ValueError('invalid stream group size')
    group = STREAM_GROUPS.setdefault(group_id, {'count': count, 'arrived': 0, 'event': asyncio.Event()})
    if group['count'] != count:
        raise ValueError('inconsistent stream group size')
    group['arrived'] += 1
    if group['arrived'] == count:
        group['event'].set()
        STREAM_GROUPS.pop(group_id, None)
    deadline = time.monotonic() + 60
    try:
        while not group['event'].is_set():
            if time.monotonic() >= deadline:
                raise TimeoutError('stream group never reached its target')
            try:
                await asyncio.wait_for(group['event'].wait(), 1)
            except TimeoutError:
                # Keep the established stream responsive while connection setup ramps.
                heartbeat = b': waiting\n\n'
                w.write(f'{len(heartbeat):x}\r\n'.encode() + heartbeat + b'\r\n')
                await w.drain()
    except BaseException:
        STREAM_GROUPS.pop(group_id, None)
        raise

async def body_chunks(r, headers):
    """Yield bounded body pieces without quadratic concatenation or large copies."""
    if headers.get(b'transfer-encoding', b'').strip() == b'chunked':
        while True:
            n = int((await r.readline()).strip().split(b';', 1)[0], 16)
            if n < 0:
                raise ValueError('negative chunk length')
            if not n:
                if await r.readexactly(2) != b'\r\n':
                    raise ValueError('unexpected request trailers')
                return
            while n:
                size = min(n, 64 * 1024)
                yield await r.readexactly(size)
                n -= size
            if await r.readexactly(2) != b'\r\n':
                raise ValueError('invalid request chunk terminator')
    else:
        remaining = int(headers.get(b'content-length', b'0'))
        if remaining < 0:
            raise ValueError('negative content length')
        while remaining:
            size = min(remaining, 64 * 1024)
            yield await r.readexactly(size)
            remaining -= size

async def validate_body(r, headers):
    original = int(headers[b'x-benchmark-body-length'])
    prefix = SECRET.encode()
    expected_length = original - len(PLACEHOLDER) + len(prefix)
    if original < len(PLACEHOLDER):
        raise ValueError('invalid original body length')
    received = 0
    async for piece in body_chunks(r, headers):
        prefix_size = min(len(piece), max(0, len(prefix) - received))
        if piece[:prefix_size] != prefix[received:received + prefix_size]:
            raise ValueError('body prefix was not rewritten')
        tail = piece[prefix_size:]
        if tail.count(b'x') != len(tail):
            raise ValueError('body content changed or retained a placeholder')
        received += len(piece)
        if received > expected_length:
            raise ValueError('rewritten body is too long')
        await asyncio.sleep(0)
    if received != expected_length:
        raise ValueError('rewritten body is incomplete')

async def handle(r, w):
    try:
        while True:
            head = await r.readuntil(b'\r\n\r\n')
            method, path, _ = head.split(b'\r\n')[0].split()
            headers = {k.lower(): v.strip() for k, v in (line.split(b':', 1) for line in head.split(b'\r\n')[1:] if b':' in line)}
            if method == b'POST' and path == b'/echo':
                await validate_body(r, headers)
                body = b''
            else:
                body = bytearray()
                async for piece in body_chunks(r, headers):
                    body.extend(piece)
                    if len(body) > 1024 * 1024:
                        raise ValueError('unexpectedly large fixture API body')
                    await asyncio.sleep(0)
            if path.endswith(b'/config'):
                data = {'secrets': [{'name': 'TOKEN', 'placeholder': PLACEHOLDER, 'value': SECRET,
                         'hosts': ['bench.internal'], 'locations': ['header', 'body']}],
                        'briqs': [{'id': 'bench', 'host': 'bench.internal', 'secrets': ['TOKEN']}]}
                reply = json.dumps(data).encode()
            elif path.endswith(b'/ca'):
                Path('/tmp/gateway-ca.pem').write_text(json.loads(body)['cert'])
                reply = b'{}'
            elif path.endswith(b'/events'):
                reply = b'{}'
            else:
                # Prove this went through interception, not an ordinary CONNECT tunnel.
                if headers.get(b'authorization', b'').strip().decode() != SECRET:
                    raise ValueError('secret was not injected')
                reply = ('data: ' + SECRET + '\n\n').encode()
                if path == b'/stream':
                    w.write(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n')
                    for event_index in range(30):
                        w.write(f'{len(reply):x}\r\n'.encode() + reply + b'\r\n')
                        await w.drain()
                        if event_index == 0:
                            await wait_for_peers(headers, w)
                        await asyncio.sleep(1)
                    w.write(b'0\r\n\r\n')
                    await w.drain()
                    continue
            w.write(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(reply)).encode() + b'\r\n\r\n' + reply)
            await w.drain()
    except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
        pass
    finally:
        w.close()

async def main():
    use_rust = os.environ.get('BENCH_TLS_SERVER', 'python') == 'rust'
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    child = api = upstream = None
    tasks = []
    try:
        if use_rust:
            child = await asyncio.create_subprocess_exec('/bench-server')
            Path('/tmp/bench-server.pid').write_text(str(child.pid))
            print(json.dumps({'kind': 'benchmark_tls_child', 'pid': child.pid}), flush=True)
        else:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain('/tmp/cert.pem', '/tmp/key.pem')
            upstream = await asyncio.start_server(handle, '0.0.0.0', 443, ssl=tls, backlog=2048)
        api = await asyncio.start_server(handle, '0.0.0.0', 8399)
        stopped = asyncio.create_task(stop.wait())
        tasks = [stopped, asyncio.create_task(api.serve_forever())]
        child_exit = asyncio.create_task(child.wait()) if child else None
        tasks.append(child_exit if child_exit else asyncio.create_task(upstream.serve_forever()))
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        if child_exit is not None and child_exit in done:
            raise RuntimeError(f'Rust TLS fixture exited unexpectedly: {child.returncode}')
        if stopped not in done:
            for task in done:
                await task
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for server in (api, upstream):
            if server is not None:
                server.close()
                await server.wait_closed()
        if child is not None:
            if child.returncode is None:
                child.terminate()
                try:
                    await asyncio.wait_for(child.wait(), 5)
                except TimeoutError:
                    child.kill()
                    await asyncio.wait_for(child.wait(), 5)
            Path('/tmp/bench-server.pid').unlink(missing_ok=True)

if __name__ == '__main__':
    asyncio.run(main())
