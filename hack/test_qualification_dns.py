"""Offline checks of the DNS probe embedded in the existing qualification suite."""
from pathlib import Path
import socket
import struct
import subprocess
import unittest
from unittest.mock import patch


SHELL = Path(__file__).with_name("qualify.sh").read_text()
PROGRAM = SHELL.split("<<'DNS_PROBE'\n", 1)[1].split("\nDNS_PROBE\n", 1)[0]
SCOPE = {"__name__": "qualification_dns"}
exec(compile(PROGRAM, "qualify.sh:DNS_PROBE", "exec"), SCOPE)
PROBE = SCOPE["probe"]
BOUNDARY = SHELL[SHELL.index("dns_boundary() {"):
                 SHELL.index('check "DNS: foreign gateways')]


class Datagram:
    def __init__(self, reply=None, failure=None):
        self.reply = reply
        self.failure = failure
        self.closed = False
        self.sent = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def settimeout(self, seconds):
        self.timeout = seconds

    def connect(self, address):
        self.address = address

    def send(self, query):
        self.sent = query
        return len(query)

    def recv(self, size):
        if self.failure:
            raise self.failure
        return self.reply(self.sent)


def answer(query, ip="10.64.2.2", compressed=True, flags=0x8580):
    ident = struct.unpack("!H", query[:2])[0]
    question = query[12:]
    if ip is None:
        return struct.pack("!6H", ident, flags | 3, 1, 0, 0, 0) + question
    name = b"\xc0\x0c" if compressed else question[:-4]
    record = name + struct.pack("!HHIH", 1, 1, 5, 4) + socket.inet_aton(ip)
    return struct.pack("!6H", ident, flags, 1, 1, 0, 0) + question + record


class DnsProbeTests(unittest.TestCase):
    def invoke(self, datagram, expected="10.64.2.2"):
        with patch.object(socket, "socket", return_value=datagram), \
                patch.object(SCOPE["secrets"], "randbits", return_value=0x1234):
            return PROBE("10.64.2.1", "iso-o.internal", expected)

    def test_expected_a_answer_with_both_name_encodings(self):
        for compressed in (False, True):
            datagram = Datagram(lambda q: answer(q, compressed=compressed))
            self.assertEqual(self.invoke(datagram), "answer")
            self.assertEqual(datagram.address, ("10.64.2.1", 53))
            self.assertEqual(datagram.timeout, 2)
            self.assertTrue(datagram.closed)

    def test_nxdomain_is_a_positive_response_not_silence(self):
        datagram = Datagram(lambda q: answer(q, ip=None))
        self.assertEqual(self.invoke(datagram, "nxdomain"), "nxdomain")
        self.assertTrue(datagram.closed)
        with self.assertRaisesRegex(AssertionError, "foreign gateway returned"):
            self.invoke(Datagram(lambda q: answer(q, ip=None)), "silence")

    def test_only_receive_timeout_counts_as_silence(self):
        datagram = Datagram(failure=TimeoutError())
        self.assertEqual(self.invoke(datagram, "silence"), "silence")
        self.assertTrue(datagram.closed)
        with self.assertRaisesRegex(AssertionError, "control did not answer"):
            self.invoke(Datagram(failure=TimeoutError()))
        for error in (ConnectionRefusedError(), OSError("route unavailable")):
            with self.assertRaises(OSError):
                self.invoke(Datagram(failure=error), "silence")

    def test_connect_and_send_errors_do_not_count_as_silence(self):
        for method in ("connect", "send"):
            datagram = Datagram()
            with patch.object(datagram, method, side_effect=TimeoutError()), \
                    self.assertRaises(TimeoutError):
                self.invoke(datagram, "silence")
            self.assertTrue(datagram.closed)

    def test_every_datagram_fails_a_foreign_gateway_probe(self):
        for response in (lambda q: answer(q), lambda q: answer(q, ip=None), lambda _: b""):
            datagram = Datagram(response)
            with self.assertRaisesRegex(AssertionError, "foreign gateway returned"):
                self.invoke(datagram, "silence")
            self.assertTrue(datagram.closed)

    def test_wrong_id_ip_question_or_truncated_reply_fails_controls(self):
        responses = [
            lambda q: b"\0\0" + answer(q)[2:],
            lambda q: answer(q, ip="10.64.2.3"),
            lambda q: answer(q)[:12] + b"x" + answer(q)[13:],
            lambda q: answer(q)[:-1],
            lambda _: b"short",
            lambda q: answer(q, flags=0x8780),
            lambda q: answer(q, flags=0x0580),
        ]
        for response in responses:
            with self.assertRaises((AssertionError, struct.error)):
                self.invoke(Datagram(response))

    def run_boundary(self, timeout_body):
        script = ("timeout() { " + timeout_body + "; }\n" +
                  "O=other A2=open NN=none gw1=10.64.1.1 gw2=10.64.2.1 "
                  "aip=10.64.1.2 oip=10.64.2.2\n" + BOUNDARY + "\ndns_boundary\n")
        return subprocess.run(["bash", "-c", script], capture_output=True,
                              text=True, timeout=5)

    def test_shell_controls_and_foreign_checks_share_a_finite_budget(self):
        result = self.run_boundary("echo attempt >&2; return 0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.count("attempt"), 12)
        self.assertIn("deadline=$((SECONDS + 90))", BOUNDARY)
        self.assertIn('timeout --kill-after=2s "${remaining}s"', BOUNDARY)
        self.assertIn('machine exec --timeout 5s', BOUNDARY)
        for call in (
                'dns_probe "$O" "$gw2" iso-o.internal "$oip"',
                'dns_probe "$A2" "$gw1" iso-a.internal "$aip"',
                'dns_probe "$NN" "$gw1" iso-a.internal "$aip"'):
            self.assertEqual(BOUNDARY.count(call), 2)

    def test_exec_failure_stops_the_case_instead_of_passing_as_isolation(self):
        result = self.run_boundary("echo attempt >&2; return 77")
        self.assertEqual(result.returncode, 77)
        self.assertEqual(result.stderr.count("attempt"), 1)

    def test_expired_budget_does_not_launch_another_exec(self):
        result = self.run_boundary("echo attempt >&2; SECONDS=1000; return 0")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr.count("attempt"), 1)


if __name__ == "__main__":
    unittest.main()
