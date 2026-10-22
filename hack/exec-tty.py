#!/usr/bin/env python3
"""Runs a command on a terminal of its own and drives it as a person would: the suites' way to
test `briqyard machine exec -it` with no keyboard (ADR 0029).

    exec-tty.py ROWSxCOLS STEP... -- CMD...

The terminal has the size given before the command starts. Steps, in order:

    send:TEXT          type TEXT (backslash escapes: \\n)
    expect:REGEX       wait, 20 s at most, for REGEX in what was printed since the last match
    ask:TEXT=>REGEX    type TEXT until REGEX is printed, again every 2 s: a resize and the
                       keys after it travel apart, and the remote sees them in either order
    resize:ROWSxCOLS   resize the terminal: the command gets SIGWINCH
    kill               SIGKILL the command

Prints what the command printed, then exits with its exit code (128+N for signal N), or 124
when an expect ran out.
"""
import codecs
import fcntl
import os
import re
import select
import signal
import struct
import sys
import termios
import time


def set_size(fd, spec):
    rows, cols = (int(n) for n in spec.split("x"))
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


class Term:
    def __init__(self, geometry, cmd):
        self.master, slave = os.openpty()
        set_size(slave, geometry)
        self.pid = os.fork()
        if self.pid == 0:
            os.close(self.master)
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            for fd in (0, 1, 2):
                os.dup2(slave, fd)
            os.execvp(cmd[0], cmd)
        os.close(slave)
        self.out = ""
        self.seen = 0
        self.open = True

    def read(self, timeout):
        """Reads what is there within `timeout`; False once the command's side is closed."""
        if not self.open:
            return False
        ready, _, _ = select.select([self.master], [], [], timeout)
        if ready:
            try:
                data = os.read(self.master, 65536)
            except OSError:
                data = b""
            if not data:
                self.open = False
                return False
            self.out += data.decode("utf-8", "replace")
        return True

    def expect(self, pattern, within):
        deadline = time.time() + within
        while True:
            m = re.search(pattern, self.out[self.seen:])
            if m:
                self.seen += m.end()
                return True
            left = deadline - time.time()
            if left <= 0 or not self.read(min(left, 0.2)):
                m = re.search(pattern, self.out[self.seen:])
                if m:
                    self.seen += m.end()
                return bool(m)

    def send(self, text):
        os.write(self.master, text.encode())

    def finish(self):
        """Reads to the end, then the command's exit code."""
        deadline = time.time() + 20
        while self.read(0.2) and time.time() < deadline:
            pass
        _, status = os.waitpid(self.pid, 0)
        if os.WIFSIGNALED(status):
            return 128 + os.WTERMSIG(status)
        return os.WEXITSTATUS(status)


def main():
    args = sys.argv[1:]
    split = args.index("--")
    geometry, steps, cmd = args[0], args[1:split], args[split + 1:]
    t = Term(geometry, cmd)
    code = None
    for step in steps:
        kind, _, arg = step.partition(":")
        arg = codecs.decode(arg, "unicode_escape")
        if kind == "send":
            t.send(arg)
        elif kind == "expect":
            if not t.expect(arg, 20):
                code = 124
                break
        elif kind == "ask":
            text, pattern = arg.split("=>", 1)
            for _ in range(10):
                t.send(text)
                if t.expect(pattern, 2):
                    break
            else:
                code = 124
                break
        elif kind == "resize":
            set_size(t.master, arg)
        elif kind == "kill":
            os.kill(t.pid, signal.SIGKILL)
        else:
            sys.exit(f"unknown step {step!r}")
    if code is not None:
        os.kill(t.pid, signal.SIGKILL)
    exit_code = t.finish()
    sys.stdout.write(t.out)
    if code is not None:
        sys.stderr.write(f"exec-tty: step {step!r} ran out; printed so far:\n{t.out}\n")
        sys.exit(code)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
