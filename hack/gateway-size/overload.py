import asyncio,ssl,sys,json,time,http.client
from pathlib import Path
COUNT=int(sys.argv[2]);GATEWAY=sys.argv[3]
READY=Path('/tmp/overload-ready');RELEASE=Path('/tmp/overload-release')
ctx=ssl.create_default_context(cafile='/tmp/gateway-ca.pem')
TOKEN=b'briq_secret_a1b2c3d4e5f6a7b8'
SECRET=b'benchmark-secret-value-0123456789'
writers=[]
async def active(sem):
 async with sem:
  r,w=await asyncio.open_connection(GATEWAY,3128);writers.append(w)
  w.write(b'CONNECT bench.internal:443 HTTP/1.1\r\nHost: bench.internal:443\r\n\r\n');await w.drain()
  assert (await r.readuntil(b'\r\n\r\n')).startswith(b'HTTP/1.1 200')
  await w.start_tls(ctx,server_hostname='bench.internal')
  w.write(b'GET /stream HTTP/1.1\r\nHost: bench.internal\r\nAuthorization: '+TOKEN+b'\r\n\r\n');await w.drain()
  head=await r.readuntil(b'\r\n\r\n');assert head.startswith(b'HTTP/1.1 200') and SECRET not in head
  data=bytearray()
  while not data.endswith(b'\n\n'):
   size=int((await r.readline()).strip(),16);assert size>0
   data.extend(await r.readexactly(size));await r.readexactly(2)
   assert SECRET not in data and len(data)<256
  assert data==b'data: '+TOKEN+b'\n\n',data
async def excess(sem):
 async with sem:
  r,w=await asyncio.open_connection(GATEWAY,3128)
  try:
   try:data=await asyncio.wait_for(r.read(1),3)
   except ConnectionResetError:data=b''
   assert data==b'',data
  finally:w.close()
async def main():
 try:
  await asyncio.gather(*(active(async_sem) for _ in range(COUNT)))
  READY.write_text('ready')
  deadline=time.monotonic()+20
  while not RELEASE.exists():
   if time.monotonic()>deadline:raise TimeoutError('host health barrier')
   await asyncio.sleep(.05)
  await asyncio.gather(*(excess(over_sem) for _ in range(1000)))
  assert len(writers)==COUNT
 finally:
  for w in writers:w.close()
async_sem=asyncio.Semaphore(16);over_sem=asyncio.Semaphore(32)
READY.unlink(missing_ok=True);RELEASE.unlink(missing_ok=True)
try:
 asyncio.run(asyncio.wait_for(main(),80))
 c=http.client.HTTPSConnection(GATEWAY,3128,context=ctx,timeout=10)
 c.set_tunnel('bench.internal',443)
 try:
  c.request('GET','/echo',headers={'Host':'bench.internal','Authorization':TOKEN.decode()})
  r=c.getresponse();body=r.read()
  assert r.status==200 and body==b'data: '+TOKEN+b'\n\n' and SECRET not in body
 finally:c.close()
 print(json.dumps(dict(mode='overload',concurrency=COUNT,established=COUNT,completed=COUNT,
     rejected=1000,recovered=True,error_count=0,errors=[])))
finally:
 READY.unlink(missing_ok=True);RELEASE.unlink(missing_ok=True)
