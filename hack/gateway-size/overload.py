"""Validate established streams, rejection at admission capacity, and recovery."""
import asyncio
import http.client
import json
import ssl
import sys
import time
import traceback
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

async def close_writer(writer):
    """Cleanup cannot replace a workload failure or mutate its saved traceback."""
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 2)
    except (OSError, asyncio.TimeoutError):
        # Peer resets are expected for rejected sockets and cancelled streams.
        try:
            writer.transport.abort()
        except Exception:
            pass
    except Exception as error:
        return repr(error)
    return None


async def active(gateway, ctx, count, group, sem, writers, ready, progress):
    try:
        return await active_inner(gateway, ctx, count, group, sem, writers, ready, progress)
    except Exception as error:
        # Snapshot before wait_closed can re-raise the protocol's same exception object.
        progress['error'] = f'{type(error).__name__}: {error}'
        raise RuntimeError(f"worker {progress['worker']} at {progress['stage']}: {progress['error']}") from error


async def active_inner(gateway, ctx, count, group, sem, writers, ready, progress):
    async with sem:
        progress['stage'] = 'tcp_connect'
        reader, writer = await asyncio.open_connection(gateway, 3128)
        writers.append(writer)
        progress['stage'] = 'connect_response'
        writer.write(b'CONNECT bench.internal:443 HTTP/1.1\r\nHost: bench.internal:443\r\n\r\n')
        await writer.drain()
        assert (await reader.readuntil(b'\r\n\r\n')).startswith(b'HTTP/1.1 200')
        progress['stage'] = 'tls_handshake'
        await writer.start_tls(ctx, server_hostname='bench.internal')
        progress['stage'] = 'response_headers'
        writer.write(b'GET /stream HTTP/1.1\r\nHost: bench.internal\r\nAuthorization: ' + TOKEN +
                     f'\r\nX-Benchmark-Stream-Group: {group}\r\nX-Benchmark-Stream-Count: {count}\r\n\r\n'.encode())
        await writer.drain()
        head = await reader.readuntil(b'\r\n\r\n')
        assert head.startswith(b'HTTP/1.1 200') and SECRET not in head
        assert b'transfer-encoding: chunked' in head.lower()
        body = messages(reader)
        # Only setup holds the semaphore; the full group must be able to join.
        progress['stage'] = 'first_event'
        assert await anext(body) == b'data: ' + TOKEN
        progress['established'] = True
        progress['stage'] = 'stream_read'
        ready.put_nowait(None)
    events = 1
    async for event in body:
        if event.startswith(b'data: '):
            events += 1
            assert events <= 30
    assert events == 30, events
    progress['stage'] = 'complete'
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
            await close_writer(writer)

async def workload(gateway, ctx, count):
    writers = []
    ready = asyncio.Queue()
    sem = asyncio.Semaphore(16)
    over_sem = asyncio.Semaphore(32)
    group = 'overload-' + str(time.time_ns())
    progress = [dict(worker=i, stage='setup_queue', established=False) for i in range(count)]
    tasks = [asyncio.create_task(active(gateway, ctx, count, group, sem, writers, ready, state))
             for state in progress]
    rejected = []
    failure = None
    phase = 'establishing'
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
        phase = 'health_barrier'
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
        phase = 'excess_connections'
        rejected = [asyncio.create_task(excess(gateway, over_sem)) for _ in range(1000)]
        await asyncio.gather(*rejected)
        if any(task.done() for task in tasks):
            raise RuntimeError('stream ended before all excess connections were rejected')
        phase = 'stream_completion'
        await asyncio.gather(*tasks)
        return dict(mode='overload', concurrency=count, established=count, completed=count,
                    events=count * 30, rejected=len(rejected), error_count=0, errors=[])
    except BaseException as error:
        failure = error
        # Emit before cleanup: asyncio may store and re-raise one socket error object.
        print(json.dumps(dict(kind='overload_failure', phase=phase,
              established=sum(state['established'] for state in progress),
              completed=sum(state['stage'] == 'complete' for state in progress),
              workers=[state for state in progress if 'error' in state],
              traceback=traceback.format_exc())), file=sys.stderr, flush=True)
        raise
    finally:
        for task in [*tasks, *rejected]:
            task.cancel()
        await asyncio.gather(*tasks, *rejected, return_exceptions=True)
        closed = await asyncio.gather(*(close_writer(writer) for writer in writers),
                                      return_exceptions=True)
        unexpected = [str(error) for error in closed if error is not None]
        if unexpected and failure is None:
            raise RuntimeError('unexpected connection cleanup failure: ' + repr(unexpected))

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
