"""Validate established streams, rejection at admission capacity, and recovery."""
import asyncio
import http.client
import json
import ssl
import sys
import time
from pathlib import Path

TOKEN = b'briq_secret_a1b2c3d4e5f6a7b8'
SECRET = b'benchmark-secret-value-0123456789'
READY = Path('/tmp/overload-ready')
RELEASE = Path('/tmp/overload-release')

async def chunks(reader):
    while True:
        line = await reader.readline()
        if not line:
            raise EOFError('stream closed before its terminating chunk')
        size = int(line.strip().split(b';', 1)[0], 16)
        if size == 0:
            assert await reader.readexactly(2) == b'\r\n'
            return
        assert 0 < size <= 65536, size
        data = await reader.readexactly(size)
        assert await reader.readexactly(2) == b'\r\n'
        yield data

async def messages(reader):
    pending = bytearray()
    async for data in chunks(reader):
        pending.extend(data)
        assert len(pending) <= 65536 and SECRET not in pending
        while b'\n\n' in pending:
            event, _, rest = pending.partition(b'\n\n')
            pending = bytearray(rest)
            assert event in (b'data: ' + TOKEN, b': waiting'), event
            yield event
    assert not pending, pending

async def active(gateway, ctx, count, group, sem, writers, ready):
    async with sem:
        reader, writer = await asyncio.open_connection(gateway, 3128)
        writers.append(writer)
        writer.write(b'CONNECT bench.internal:443 HTTP/1.1\r\nHost: bench.internal:443\r\n\r\n')
        await writer.drain()
        assert (await reader.readuntil(b'\r\n\r\n')).startswith(b'HTTP/1.1 200')
        await writer.start_tls(ctx, server_hostname='bench.internal')
        writer.write(b'GET /stream HTTP/1.1\r\nHost: bench.internal\r\nAuthorization: ' + TOKEN +
                     f'\r\nX-Benchmark-Stream-Group: {group}\r\nX-Benchmark-Stream-Count: {count}\r\n\r\n'.encode())
        await writer.drain()
        head = await reader.readuntil(b'\r\n\r\n')
        assert head.startswith(b'HTTP/1.1 200') and SECRET not in head
        assert b'transfer-encoding: chunked' in head.lower()
        body = messages(reader)
        # Only setup holds the semaphore; the full group must be able to join.
        assert await anext(body) == b'data: ' + TOKEN
        ready.put_nowait(None)
    events = 1
    async for event in body:
        if event.startswith(b'data: '):
            events += 1
            assert events <= 30
    assert events == 30, events
    return events

async def excess(gateway, sem):
    async with sem:
        reader, writer = await asyncio.open_connection(gateway, 3128)
        try:
            try:
                data = await asyncio.wait_for(reader.read(1), 3)
            except ConnectionResetError:
                data = b''
            assert data == b'', data
        finally:
            writer.close()

async def workload(gateway, ctx, count):
    writers = []
    ready = asyncio.Queue()
    sem = asyncio.Semaphore(16)
    over_sem = asyncio.Semaphore(32)
    group = 'overload-' + str(time.time_ns())
    tasks = [asyncio.create_task(active(gateway, ctx, count, group, sem, writers, ready))
             for _ in range(count)]
    rejected = []
    try:
        # An establishment error must propagate immediately, not become a barrier timeout.
        for _ in range(count):
            waiter = asyncio.create_task(ready.get())
            try:
                done, _ = await asyncio.wait([waiter, *tasks], return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if task is not waiter:
                        task.result()
                        raise RuntimeError('stream ended before all streams were established')
                await waiter
            finally:
                waiter.cancel()
                await asyncio.gather(waiter, return_exceptions=True)
        READY.write_text('ready')
        deadline = time.monotonic() + 20
        while not RELEASE.exists():
            if any(task.done() for task in tasks):
                raise RuntimeError('stream ended before the host health barrier')
            if time.monotonic() > deadline:
                raise TimeoutError('host health barrier')
            await asyncio.sleep(.05)
        if any(task.done() for task in tasks):
            raise RuntimeError('stream ended before excess connections')
        rejected = [asyncio.create_task(excess(gateway, over_sem)) for _ in range(1000)]
        await asyncio.gather(*rejected)
        if any(task.done() for task in tasks):
            raise RuntimeError('stream ended before all excess connections were rejected')
        await asyncio.gather(*tasks)
        return dict(mode='overload', concurrency=count, established=count, completed=count,
                    events=count * 30, rejected=len(rejected), error_count=0, errors=[])
    finally:
        for task in [*tasks, *rejected]:
            task.cancel()
        await asyncio.gather(*tasks, *rejected, return_exceptions=True)
        for writer in writers:
            writer.close()
        # Await local close so recovery cannot race the client's own TLS close notification.
        async def closed(writer):
            try:
                await asyncio.wait_for(writer.wait_closed(), 2)
            except (OSError, asyncio.TimeoutError):
                pass
        await asyncio.gather(*(closed(writer) for writer in writers))

def main():
    count, gateway = int(sys.argv[2]), sys.argv[3]
    assert count > 0
    ctx = ssl.create_default_context(cafile='/tmp/gateway-ca.pem')
    READY.unlink(missing_ok=True)
    RELEASE.unlink(missing_ok=True)
    try:
        result = asyncio.run(asyncio.wait_for(workload(gateway, ctx, count), 80))
        conn = http.client.HTTPSConnection(gateway, 3128, context=ctx, timeout=10)
        conn.set_tunnel('bench.internal', 443)
        try:
            conn.request('GET', '/echo', headers={'Host': 'bench.internal', 'Authorization': TOKEN.decode()})
            response = conn.getresponse()
            body = response.read()
            assert response.status == 200 and body == b'data: ' + TOKEN + b'\n\n' and SECRET not in body
        finally:
            conn.close()
        result['recovered'] = True
        print(json.dumps(result))
    finally:
        READY.unlink(missing_ok=True)
        RELEASE.unlink(missing_ok=True)

if __name__ == '__main__':
    main()
