#!/usr/bin/env python3
"""Traffic through a host while something restarts under it: counts what fails, and how.

    upgrade-probe.py --tcp ADDR:PORT --echo ADDR:PORT --http ADDR:PORT --web-host NAME \
        --echo-host NAME --api URL [--api URL ...] [--token T] [--long 4]

Runs until SIGINT or SIGTERM, then prints one JSON object: per probe, the attempts and how they
ended. Probes, each in its own threads:

  tcp        a new connection to a TCP endpoint per attempt, one HTTP/1.0 request through it
  http       a new connection to the HTTP ingress per attempt, one request (Host: --web-host)
  tcp-long   --long connections to an echo server's TCP endpoint, a line each way every 100 ms
  http-long  the same through the HTTP ingress (Host: --echo-host): the head, then lines
  api:<url>  GET <url> every 100 ms (a daemon's /v1/status, a fleet's machine)

An attempt ends `ok`, `refused` (ECONNREFUSED), `reset` (ECONNRESET, EPIPE, or the connection
closed before the answer), `timeout` (no answer within 10 s) or `failed` (anything else: a 5xx,
a wrong answer). A long connection that breaks counts one `cut` and is opened again; its
reopening counts as an attempt. `outage_ms` is the longest time between two `ok`s of a probe;
`slowest_ms` the slowest `ok` (a connection that waited in a listen queue shows here).
"""

import argparse
import json
import signal
import socket
import threading
import time
import urllib.error
import urllib.request

TIMEOUT = 10.0
stop = threading.Event()


class Tally:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts = {k: 0 for k in ("ok", "refused", "reset", "timeout", "failed", "cut")}
        self.last_ok = None
        self.outage = 0.0
        self.slowest = 0.0
        self.first_failure = None

    def add(self, outcome, took=0.0, detail=""):
        now = time.monotonic()
        with self.lock:
            self.counts[outcome] += 1
            if outcome == "ok":
                if self.last_ok is not None:
                    self.outage = max(self.outage, now - self.last_ok)
                self.last_ok = now
                self.slowest = max(self.slowest, took)
            elif outcome != "cut" and self.first_failure is None:
                self.first_failure = detail or outcome

    def report(self):
        with self.lock:
            out = dict(self.counts)
            out["attempts"] = sum(v for k, v in self.counts.items() if k != "cut")
            out["outage_ms"] = round(self.outage * 1000)
            out["slowest_ms"] = round(self.slowest * 1000)
            if self.first_failure:
                out["first_failure"] = self.first_failure
            return out


def outcome_of(err):
    if isinstance(err, ConnectionRefusedError):
        return "refused"
    if isinstance(err, (ConnectionResetError, BrokenPipeError, EOFError)):
        return "reset"
    if isinstance(err, (socket.timeout, TimeoutError)):
        return "timeout"
    return "failed"


def addr(s):
    host, port = s.rsplit(":", 1)
    return host, int(port)


def read_all(sock):
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data += chunk


def one_request(target, head):
    """A new connection, one request, the whole answer: `ok` on a 200."""
    with socket.create_connection(target, timeout=TIMEOUT) as s:
        s.sendall(head)
        answer = read_all(s)
    if not answer:
        raise EOFError("closed before the answer")
    if b" 200 " not in answer.split(b"\r\n", 1)[0]:
        raise ValueError(answer.split(b"\r\n", 1)[0].decode(errors="replace"))


def short(tally, target, head):
    while not stop.is_set():
        t = time.monotonic()
        try:
            one_request(target, head)
            tally.add("ok", time.monotonic() - t)
        except Exception as e:  # noqa: BLE001: every failure is counted by its kind
            tally.add(outcome_of(e), detail=f"{type(e).__name__}: {e}")
        stop.wait(0.05)


def readline(f):
    line = f.readline()
    if not line:
        raise EOFError("closed")
    return line


def long_lived(tally, target, head):
    """One connection kept open: a line out, the same line back, every 100 ms."""
    n = 0
    while not stop.is_set():
        t = time.monotonic()
        try:
            s = socket.create_connection(target, timeout=TIMEOUT)
        except Exception as e:  # noqa: BLE001
            tally.add(outcome_of(e), detail=f"connect: {type(e).__name__}: {e}")
            stop.wait(0.1)
            continue
        f = s.makefile("rb")
        try:
            if head:
                s.sendall(head)
                # The echo server sends the head back, line by line, to its blank line.
                while readline(f) not in (b"\r\n", b"\n"):
                    pass
            tally.add("ok", time.monotonic() - t)
            while not stop.is_set():
                n += 1
                line = f"line {n}\n".encode()
                s.sendall(line)
                if readline(f) != line:
                    raise ValueError("a different line came back")
                stop.wait(0.1)
        except Exception as e:  # noqa: BLE001
            if not stop.is_set():
                tally.add("cut", detail=f"{type(e).__name__}: {e}")
        finally:
            f.close()
            s.close()


def api(tally, url, token):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    while not stop.is_set():
        t = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                r.read()
            tally.add("ok", time.monotonic() - t)
        except urllib.error.HTTPError as e:
            tally.add("failed", detail=f"HTTP {e.code}: {e.read()[:200].decode(errors='replace')}")
        except urllib.error.URLError as e:
            tally.add(outcome_of(e.reason), detail=f"{type(e.reason).__name__}: {e.reason}")
        except Exception as e:  # noqa: BLE001
            tally.add(outcome_of(e), detail=f"{type(e).__name__}: {e}")
        stop.wait(0.1)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--tcp", type=addr, help="a TCP endpoint to an HTTP server")
    p.add_argument("--echo", type=addr, help="a TCP endpoint to a line echo server")
    p.add_argument("--http", type=addr, help="the HTTP ingress")
    p.add_argument("--web-host", default="", help="the HTTP endpoint's host to the HTTP server")
    p.add_argument("--echo-host", default="", help="the HTTP endpoint's host to the echo server")
    p.add_argument("--api", action="append", default=[], help="a URL to GET")
    p.add_argument("--token", default="")
    p.add_argument("--long", type=int, default=4, help="long-lived connections per long probe")
    a = p.parse_args()

    probes, threads = {}, []

    def run(name, fn, *args, copies=1):
        probes[name] = Tally()
        for _ in range(copies):
            threads.append(threading.Thread(target=fn, args=(probes[name], *args), daemon=True))

    if a.tcp:
        run("tcp", short, a.tcp, b"GET / HTTP/1.0\r\n\r\n")
    if a.http and a.web_host:
        head = f"GET / HTTP/1.1\r\nHost: {a.web_host}\r\nConnection: close\r\n\r\n".encode()
        run("http", short, a.http, head)
    if a.echo:
        run("tcp-long", long_lived, a.echo, b"", copies=a.long)
    if a.http and a.echo_host:
        head = f"GET / HTTP/1.1\r\nHost: {a.echo_host}\r\n\r\n".encode()
        run("http-long", long_lived, a.http, head, copies=a.long)
    for url in a.api:
        run(f"api:{url}", api, url, a.token)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    started = time.monotonic()
    for t in threads:
        t.start()
    while not stop.wait(0.2):
        pass
    for t in threads:
        t.join(TIMEOUT + 1)
    out = {"seconds": round(time.monotonic() - started, 1)}
    out.update({name: t.report() for name, t in probes.items()})
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
