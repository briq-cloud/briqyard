#!/usr/bin/env python3
"""Linux packet regression in disposable network namespaces. No host table changes.

Build: cargo build -p briqyardd --example siblings-rules
Run as root: python3 hack/network-siblings.py target/debug/examples/siblings-rules
Requires iproute2, nftables, Python 3 and Linux bridge/nft support. Uses no public endpoint.
"""
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

PREFIX = f"bysib{os.getpid()}"
OWNED = []
CHILDREN = []
TIMEOUT = 8


def run(args, *, data=None, check=True):
    return subprocess.run(args, input=data, text=True, capture_output=True,
                          timeout=TIMEOUT, check=check)


def ns(name, *args, **kwargs):
    return run(["ip", "netns", "exec", f"{PREFIX}-{name}", *args], **kwargs)


def mac(ip):
    return "06:b1:" + ":".join(f"{int(n):02x}" for n in ip.split("."))


def setup_namespace(name):
    full = f"{PREFIX}-{name}"
    run(["ip", "netns", "add", full])
    OWNED.append(full)
    ns(name, "ip", "link", "set", "lo", "up")


def connect(name, tap, ip, bridge):
    setup_namespace(name)
    ns("host", "ip", "link", "add", tap, "type", "veth", "peer", "name", "peer")
    ns("host", "ip", "link", "set", "peer", "netns", f"{PREFIX}-{name}")
    ns(name, "ip", "link", "set", "peer", "name", "eth0")
    ns(name, "ip", "link", "set", "eth0", "address", mac(ip))
    ns(name, "ip", "address", "add", f"{ip}/24", "dev", "eth0")
    ns(name, "ip", "link", "set", "eth0", "up")
    ns(name, "ip", "route", "add", "default", "via", ip.rsplit(".", 1)[0] + ".1")
    ns("host", "ip", "link", "set", tap, "master", bridge)
    ns("host", "ip", "link", "set", tap, "up")


def parent_death_signal():
    # Linux keeps this across exec; a killed harness must not leave an echo server running.
    import ctypes
    parent = os.getppid()
    if ctypes.CDLL(None).prctl(1, signal.SIGTERM) != 0 or os.getppid() != parent:
        os._exit(101)


def spawn(name, code, *args, pipe=False):
    p = subprocess.Popen(["ip", "netns", "exec", f"{PREFIX}-{name}",
                          sys.executable, "-u", "-c", code, *args],
                         stdin=subprocess.PIPE if pipe else subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, preexec_fn=parent_death_signal)
    CHILDREN.append(p)
    # Readiness is an explicit pipe record, bounded by select, not a sleep.
    import select
    if not select.select([p.stdout], [], [], TIMEOUT)[0] or p.stdout.readline().strip() != "ready":
        raise RuntimeError(f"{name}: server did not bind")
    return p


ECHO = """
import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',9000));s.listen();print('ready',flush=True)
def serve(c):
 with c:
  while True:
   b=c.recv(4096)
   if not b:return
   c.sendall(b)
while True:
 c,_=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
"""
PROBE = """
import socket,sys
try:
 with socket.create_connection((sys.argv[1],int(sys.argv[2])),.45) as s:
  s.settimeout(.45);s.sendall(b'fixture');assert s.recv(7)==b'fixture'
except (OSError,AssertionError):sys.exit(1)
"""


def probe(source, target, allowed, port=9000):
    result = ns(source, sys.executable, "-c", PROBE, target, str(port), check=False)
    assert (result.returncode == 0) == allowed, (source, target, allowed, result.stderr)
    print(f"ok {source} -> {target}:{port} {'allowed' if allowed else 'denied'}")


def cached(source, ip):
    ns(source, "ip", "neighbor", "replace", ip, "lladdr", mac(ip), "nud", "permanent", "dev", "eth0")


def nft(script, *, check=True):
    return ns("host", "nft", "-f", "-", data=script, check=check)


def packet(destination, payload):
    """One IPv4/UDP datagram, for one-way ingress where a denied reply proves nothing."""
    return f"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto({payload!r},({destination!r},9010))"


def one_way(source, destination, allowed):
    listener = spawn(destination, """
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',9010));s.settimeout(.7)
print('ready',flush=True)
try:print(s.recv(64).decode(),flush=True)
except TimeoutError:pass
""")
    ns(source, sys.executable, "-c", packet("10.64.1.5", b"one-way"))
    output, error = listener.communicate(timeout=TIMEOUT)
    assert ("one-way" in output) == allowed, (source, destination, output, error)
    print(f"ok cached-neighbor one-way {source} -> {destination}")


def established_revocation(script):
    server = spawn("database", """
import socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',9001));s.listen();print('ready',flush=True)
c,_=s.accept();c.settimeout(2)
assert c.recv(6)==b'before';c.sendall(b'before')
assert sys.stdin.read(1)=='x';c.sendall(b'after');c.close();s.close()
""", pipe=True)
    client = spawn("client", """
import socket,sys
s=socket.create_connection(('10.64.1.4',9001),2);s.settimeout(.5)
s.sendall(b'before');assert s.recv(6)==b'before';print('ready',flush=True)
try:sys.exit(2 if s.recv(5)==b'after' else 0)
except TimeoutError:sys.exit(0)
""")
    # The server sends on an already established flow only after this transaction commits.
    nft(script)
    _, error = server.communicate(input="x", timeout=TIMEOUT)
    assert server.returncode == 0, error
    _, error = client.communicate(timeout=TIMEOUT)
    assert client.returncode == 0, error
    print("ok established reverse traffic revoked before the next packet")


def ipv6_is_denied():
    for name, address in [("client", "fd64::3"), ("database", "fd64::4")]:
        ns(name, "ip", "-6", "address", "add", address + "/64", "dev", "eth0", "nodad")
    ns("client", "ip", "-6", "neighbor", "replace", "fd64::4", "lladdr", mac("10.64.1.4"), "nud", "permanent", "dev", "eth0")
    listener = spawn("database", """
import socket
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.bind(('fd64::4',9011));s.settimeout(.7)
print('ready',flush=True)
try:s.recv(64);raise SystemExit(2)
except TimeoutError:pass
""")
    ns("client", sys.executable, "-c", "import socket;s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.sendto(b'ipv6',('fd64::4',9011))")
    _, error = listener.communicate(timeout=TIMEOUT)
    assert listener.returncode == 0, error
    print("ok IPv6 remains denied even with a cached neighbor")


def forged_arp_is_denied():
    listener = spawn("gateway", """
import socket,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x806));s.bind(('eth0',0));s.settimeout(.7)
print('ready',flush=True)
try:
 while True:
  b=s.recv(2048)
  if b[28:32]==socket.inet_aton('10.64.1.3'):raise SystemExit(2)
except TimeoutError:pass
""")
    ns("client", sys.executable, "-c", """
import socket,struct
mac=lambda a:bytes.fromhex(a.replace(':',''))
src=mac('06:b1:0a:40:01:03');dst=mac('06:b1:0a:40:01:02');forged=mac('06:b1:0a:40:01:04')
arp=struct.pack('!HHBBH',1,0x800,6,4,1)+forged+socket.inet_aton('10.64.1.3')+dst+socket.inet_aton('10.64.1.2')
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind(('eth0',0));s.send(dst+src+struct.pack('!H',0x806)+arp)
""")
    _, error = listener.communicate(timeout=TIMEOUT)
    assert listener.returncode == 0, error
    print("ok an ARP sender MAC cannot differ from its source pin")


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit("run as root with the compiled siblings-rules example path")
    fixture = json.loads(run([str(Path(sys.argv[1]).resolve())]).stdout)
    setup_namespace("host")
    for bridge, address in [("by1", "10.64.1.1/24"), ("by2", "10.64.2.1/24")]:
        ns("host", "ip", "link", "add", bridge, "type", "bridge")
        ns("host", "ip", "address", "add", address, "dev", bridge)
        ns("host", "ip", "link", "set", bridge, "up")
    for name, tap, ip, bridge in [
        ("gateway", "btgateway", "10.64.1.2", "by1"),
        ("client", "btclient", "10.64.1.3", "by1"),
        ("database", "btdatabase", "10.64.1.4", "by1"),
        ("strict", "btstrict", "10.64.1.5", "by1"),
        ("other", "btother", "10.64.2.2", "by2"),
    ]:
        connect(name, tap, ip, bridge)
        spawn(name, ECHO)
    setup_namespace("outside")
    ns("host", "ip", "link", "add", "uplink", "type", "veth", "peer", "name", "outside")
    ns("host", "ip", "link", "set", "outside", "netns", f"{PREFIX}-outside")
    ns("host", "ip", "address", "add", "192.0.2.1/24", "dev", "uplink")
    ns("host", "ip", "link", "set", "uplink", "up")
    ns("host", "ip", "route", "add", "default", "via", "192.0.2.2")
    ns("outside", "ip", "address", "add", "192.0.2.2/24", "dev", "outside")
    ns("outside", "ip", "link", "set", "outside", "up")
    spawn("outside", ECHO)
    spawn("host", ECHO.replace("9000", "8080"))
    spawn("host", ECHO.replace("9000", "7420"))
    ns("host", "sysctl", "-qw", "net.ipv4.ip_forward=1")
    for knob in ("iptables", "ip6tables", "arptables"):
        ns("host", "sysctl", "-qw", f"net.bridge.bridge-nf-call-{knob}=0", check=False)
    ns("host", "nft", "-c", "-f", "-", data=fixture["rules"])
    nft(fixture["rules"])
    nft(fixture["limited_add"])
    nft(fixture["limited_remove"])
    nft(fixture["limited_remove"])  # Named limits/maps also revoke idempotently.
    nft(fixture["database_add"])  # Complete revocation removed this peer's pins and membership.
    for name in ("client", "strict", "database", "gateway"):
        for ip in ("10.64.1.2", "10.64.1.3", "10.64.1.4", "10.64.1.5"):
            cached(name, ip)
    probe("client", "10.64.1.4", True)
    probe("client", "10.64.1.2", True)
    probe("strict", "10.64.1.2", True)
    probe("strict", "10.64.1.4", False)
    probe("database", "10.64.1.5", False)
    one_way("database", "strict", False)  # Old source-only policy incorrectly delivered this.
    probe("client", "10.64.1.5", False)  # Source permission cannot bypass a strict destination.
    probe("client", "10.64.2.2", False)
    probe("host", "10.64.1.5", True)  # Host-origin ingress is not TAP-to-TAP traffic.
    probe("database", "192.0.2.2", True)  # The controlled endpoint is actually reachable.
    probe("client", "192.0.2.2", False)
    probe("database", "192.0.2.1", True, 8080)  # Explicit host-port opt-in works for open.
    probe("client", "192.0.2.1", False, 8080)
    probe("client", "10.64.1.1", False, 7420)
    ipv6_is_denied()
    forged_arp_is_denied()
    established_revocation(fixture["strict"])
    probe("client", "10.64.1.4", False)
    probe("client", "10.64.1.2", True)
    nft(fixture["opted"])
    probe("client", "10.64.1.4", True)
    # A failing multi-element transaction must not partially remove a member.
    bad = fixture["database_remove"] + 'add element bridge briqyard no_such_set { 1 }\n'
    assert nft(bad, check=False).returncode != 0
    probe("client", "10.64.1.4", True)
    established_revocation(fixture["database_remove"])
    probe("client", "10.64.1.4", False)
    nft(fixture["database_remove"])  # Already absent: a complete revocation is idempotent.
    nft(fixture["database_add"])
    probe("client", "10.64.1.4", True)
    # A hostile source cannot borrow a peer's IP/MAC pin.
    ns("client", "ip", "address", "add", "10.64.1.6/24", "dev", "eth0")
    spoof = PROBE.replace("socket.create_connection((sys.argv[1],int(sys.argv[2])),.45)",
                          "socket.create_connection((sys.argv[1],int(sys.argv[2])),.45,source_address=('10.64.1.6',0))")
    assert ns("client", sys.executable, "-c", spoof, "10.64.1.4", "9000", check=False).returncode != 0
    ns("client", "ip", "link", "set", "eth0", "address", mac("10.64.1.4"))
    probe("client", "10.64.1.4", False)
    ns("client", "ip", "link", "set", "eth0", "address", mac("10.64.1.3"))
    # Replace the gateway with another TAP at the old address; strict policy names its owner.
    ns("host", "ip", "link", "set", "btgateway", "down")
    connect("replacement", "btreplaced", "10.64.1.2", "by1")
    spawn("replacement", ECHO)
    nft(fixture["gateway_replace"])
    probe("strict", "10.64.1.2", False)
    probe("client", "10.64.1.2", True)  # Explicit namespace trust includes the new peer.
    print("packet fixture complete")


def cleanup():
    for child in CHILDREN:
        if child.poll() is None:
            child.terminate()
    for child in CHILDREN:
        try:
            child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=2)
    for name in reversed(OWNED):
        run(["ip", "netns", "delete", name], check=False)


if __name__ == "__main__":
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda signum, frame: sys.exit(128 + signum))
    try:
        main()
    finally:
        cleanup()
