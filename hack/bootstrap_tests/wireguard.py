import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


from .support import INSTALL_LOCK, SCRIPT


KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
KEY2 = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="
PRIVATE = "private() {" + SCRIPT.split("\nprivate() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
TUNNEL = SCRIPT[SCRIPT.index("TUNNEL=briqyard0") : SCRIPT.index("# Installs the tunnel:")]


TUNNEL_UP = SCRIPT[SCRIPT.index("TUNNEL=briqyard0") : SCRIPT.index("# Downloads a file and checks")]
FIREWALL_RENDER = SCRIPT[SCRIPT.index("  tunnel_line=$(host_tunnel_rule)") : SCRIPT.index("  cat > /etc/systemd/system/briqyard-firewall.service")]
PEER_A = f"{KEY}|10.42.0.12|164.132.1.2"
PEER_B = f"{KEY2}|10.42.0.14|51.68.1.2"
RULE_LINE = "\t\tip saddr { 164.132.1.2 } udp dport 51820 accept # briqyard-tunnel"

MOCKS = {
    # `ip route show` prints a /32 as the bare address, as the real one does.
    "ip": """#!/bin/bash
r=$STATE/routes
touch $r
case "$*" in
  "-4 route show dev "*) cat $r ;;
  "-4 -o addr show dev "*) cat $STATE/addr 2>/dev/null || true ;;
  "route add "*) echo "add $*" >> $STATE/changes; echo "${3%/32} scope link" >> $r ;;
  "route del "*) echo "del $*" >> $STATE/changes; grep -v "^${3%/32} " $r > $r.new || true; mv $r.new $r ;;
esac
""",
    "wg": """#!/bin/bash
case "$1" in
  genkey) echo MFNlY3JldHNlY3JldHNlY3JldHNlY3JldHNlY3JldHM= ;;
  pubkey) echo UHVibGljUHVibGljUHVibGljUHVibGljUHVibGljUHU= ;;
  syncconf) [ -f $STATE/active ] || { echo "wg: no such interface" >&2; exit 1; }; echo syncconf >> $STATE/changes
    # A stuck interface keeps its peers: the change is not applied.
    [ -f $STATE/stuck ] || { grep '^PublicKey' "$3" | sed 's/.* = //' > $STATE/peers || true; } ;;
  show) cat $STATE/peers 2>/dev/null || true ;;
esac
""",
    "wg-quick": "#!/bin/bash\n[ \"$1\" = strip ] && cat $CONF\nexit 0\n",
    # The loaded table is the file the firewall unit loads.
    "nft": "#!/bin/bash\ncat $FWFILE\n[ -f $STATE/stale_rule ] && echo 'udp dport 51820 accept' || true\n",
    "systemctl": """#!/bin/bash
case "$1" in
  is-active) [ -f $STATE/active ]; exit ;;
  start) touch $STATE/active; echo "start $2" >> $STATE/changes
    grep '^PublicKey' $CONF | sed 's/.* = //' > $STATE/peers || true
    grep '^AllowedIPs' $CONF | sed 's/.* = \\(.*\\)\\/32/\\1 scope link/' > $STATE/routes || true ;;
  restart) echo "restart $2" >> $STATE/changes ;;
esac
exit 0
""",
}


class WireguardPeers(unittest.TestCase):
    """The peers a tunnel host is told (ADR 0113): checked before anything is changed."""

    def run_fn(self, call, peers, own="10.42.0.13/16", port="51820"):
        script = 'fail() { echo "$*" >&2; exit 1; }\n' + PRIVATE + TUNNEL + call
        env = {"PATH": os.environ["PATH"], "WIREGUARD_PEERS": peers, "PRIVATE_ADDRESS": own, "WIREGUARD_PORT": port}
        return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)

    def test_peers_and_the_firewall_rule(self):
        peers = f"{KEY}|10.42.0.12|164.132.1.2,{KEY2}|10.42.0.14|51.68.1.2:51999"
        out = self.run_fn("tunnel_peers", peers)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(
            out.stdout.splitlines(),
            [f"{KEY} 10.42.0.12 164.132.1.2 51820", f"{KEY2} 10.42.0.14 51.68.1.2 51999"],
        )
        rule = self.run_fn("tunnel_rule", peers)
        self.assertEqual(
            rule.stdout.strip(),
            "ip saddr { 164.132.1.2, 51.68.1.2 } udp dport 51820 accept # briqyard-tunnel",
        )

    def test_no_peers_no_rule(self):
        self.assertEqual(self.run_fn("tunnel_rule", "").stdout.strip(), "")

    def test_refused(self):
        for peers, want in [
            (f"short|10.42.0.12|164.132.1.2", "not a WireGuard public key"),
            (f"{KEY}|10.42.0.0/16|164.132.1.2", "is a range"),
            (f"{KEY}|10.42.0.300|164.132.1.2", "not an IPv4 address"),
            (f"{KEY}|10.42.0.13|164.132.1.2", "own address"),
            (f"{KEY}|10.42.0.12|10.42.0.99", "private address"),
            (f"{KEY}|10.42.0.12|host.example", "IPv4 address"),
            (f"{KEY}|10.42.0.12|164.132.1.2:x", "endpoint port"),
            (f"{KEY}|10.42.0.12|164.132.1.2,{KEY2}|10.42.0.12|51.68.1.2", "twice"),
            (f"{KEY}|10.42.0.12|164.132.1.2,{KEY}|10.42.0.14|51.68.1.2", "twice"),
        ]:
            out = self.run_fn("tunnel_peers", peers)
            self.assertNotEqual(out.returncode, 0, peers)
            self.assertIn(want, out.stderr, peers)
        out = self.run_fn("tunnel_peers", f"{KEY}|10.42.0.12|164.132.1.2", port="x")
        self.assertIn("WIREGUARD_PORT", out.stderr)


class WireguardRun(unittest.TestCase):
    """tunnel_up, WIREGUARD_ONLY and the host firewall run for real, with ip, wg and systemctl mocked."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        bin_dir = self.root / "bin"
        for d in (self.state, bin_dir, self.root / "etc/briqyard"):
            d.mkdir(parents=True)
        for name, body in MOCKS.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        self.bin = bin_dir
        self.firewall = self.root / "etc/briqyard/firewall.nft"
        self.firewall.write_text("table inet briqyard_host {\n\tchain input {\n\t\tcounter drop\n\t}\n}\n")
        self.routes = self.state / "routes"

    def run_script(self, call, peers=None, wait=True):
        code = 'fail() { echo "$*" >&2; exit 1; }\n' + PRIVATE + TUNNEL_UP + "\n" + call
        code = code.replace("/etc/wireguard", str(self.root / "etc/wireguard")).replace("/etc/briqyard", str(self.root / "etc/briqyard"))
        code = code.replace("/etc/systemd/system", str(self.root / "etc/systemd"))
        env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "STATE": str(self.state), "PRIVATE_ADDRESS": "10.42.0.13/16",
               "WIREGUARD_PORT": "51820", "FLEET_ADDRESS": "", "WIREGUARD_ONLY": "",
               "CONF": str(self.root / "etc/wireguard/briqyard0.conf"), "FWFILE": str(self.firewall)}
        if peers is not None:
            env["WIREGUARD_PEERS"] = peers
            env["WIREGUARD_PEERS_SET"] = "set"
        else:
            env["WIREGUARD_PEERS"] = ""
            env["WIREGUARD_PEERS_SET"] = ""
        (self.root / "etc/systemd").mkdir(exist_ok=True)
        if not wait:
            return subprocess.Popen(["bash", "-euo", "pipefail", "-c", code], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        result = subprocess.run(["bash", "-euo", "pipefail", "-c", code], env=env, capture_output=True, text=True)
        return result

    def changes(self):
        path = self.state / "changes"
        return path.read_text().splitlines() if path.exists() else []

    def only(self, peers):
        result = self.run_script("tunnel_only", peers)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_routes_follow_the_peers_and_an_unchanged_run_changes_none(self):
        self.only(PEER_A)  # not active: wg-quick starts it, and nothing is synced before
        self.assertIn("start wg-quick@briqyard0", self.changes())
        self.assertNotIn("syncconf", self.changes())
        self.routes.write_text("10.42.0.12 scope link\n")
        (self.state / "changes").unlink(missing_ok=True)
        self.only(PEER_A)
        self.assertEqual([c for c in self.changes() if "route" in c], [])
        self.only(f"{PEER_A},{PEER_B}")
        self.assertEqual([c for c in self.changes() if "route" in c], ["add route add 10.42.0.14/32 dev briqyard0"])
        self.assertIn("syncconf", self.changes())  # running now: the peers are synced

    def test_the_last_peer_is_removed_and_with_it_route_and_rule(self):
        self.only(PEER_A)
        self.assertIn(RULE_LINE, self.firewall.read_text())
        self.routes.write_text("10.42.0.12 scope link\n")
        self.only("")
        self.assertEqual(self.routes.read_text(), "")
        self.assertNotIn("briqyard-tunnel", self.firewall.read_text())
        self.assertIn("counter drop", self.firewall.read_text())
        self.assertNotIn("PublicKey", (self.root / "etc/wireguard/briqyard0.conf").read_text())

    def test_a_removal_which_did_not_apply_fails(self):
        self.only(PEER_A)
        (self.state / "stuck").touch()  # the interface keeps its peer
        result = self.run_script("tunnel_only", "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("holds 1 peer(s) where WIREGUARD_PEERS names 0", result.stderr)

    def test_a_route_which_stays_fails(self):
        self.only(PEER_A)
        self.only("")
        self.routes.write_text("10.42.0.12 scope link\n")
        result = self.run_script("tunnel_verify", "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("routes (10.42.0.12)", result.stderr)

    def test_a_loaded_rule_which_stays_fails(self):
        self.only(PEER_A)
        (self.state / "stale_rule").touch()  # the loaded table still has the rule
        self.routes.write_text("10.42.0.12 scope link\n")
        result = self.run_script("tunnel_only", "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loaded firewall holds a different number", result.stderr)

    def test_a_firewall_file_which_keeps_the_rule_fails(self):
        self.only(PEER_A)
        self.only("")
        self.firewall.write_text(self.firewall.read_text().replace("\t\tcounter drop", RULE_LINE + "\n\t\tcounter drop"))
        result = self.run_script("tunnel_verify", "")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different number of tunnel rules", result.stderr)

    def test_an_installed_tunnel_stands_in_for_the_private_network(self):
        self.only(PEER_A)
        (self.state / "addr").write_text("5: briqyard0    inet 10.42.0.13/32 scope global briqyard0\n")
        self.assertEqual(self.run_script("installed_tunnel", None).returncode, 0)
        self.assertNotEqual(self.run_script("installed_tunnel", PEER_A).returncode, 0)  # given peers, they apply
        (self.state / "addr").write_text("5: briqyard0    inet 10.42.0.99/32 scope global briqyard0\n")
        self.assertNotEqual(self.run_script("installed_tunnel", None).returncode, 0)
        (self.state / "addr").write_text("5: briqyard0    inet 10.42.0.13/32 scope global briqyard0\n")
        (self.root / "etc/wireguard/briqyard0.conf").unlink()
        self.assertNotEqual(self.run_script("installed_tunnel", None).returncode, 0)

    def test_the_full_bootstrap_asks_for_the_installed_tunnel_first(self):
        self.assertIn("if ! has_address && ! installed_tunnel &&", SCRIPT)

    def test_the_peers_operation_waits_for_the_installer_lock(self):
        """A fleet upgrade holding the lock rewrites the firewall file: the operation must not edit it meanwhile."""
        dispatch = next(line for line in SCRIPT.splitlines() if line.startswith('if [ "$WIREGUARD_ONLY" = 1 ]'))
        lock = self.root / "etc/briqyard/runtime-install.lock"
        holder = subprocess.Popen(
            [sys.executable, "-c", "import fcntl,os,sys\nfd=os.open(sys.argv[1],os.O_CREAT|os.O_RDWR,0o600)\nfcntl.flock(fd,fcntl.LOCK_EX)\nprint('held',flush=True)\nsys.stdin.readline()", str(lock)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        run = None
        try:
            self.assertEqual(holder.stdout.readline(), "held\n")
            run = self.run_script("WIREGUARD_ONLY=1\n" + dispatch, PEER_A, wait=False)
            with self.assertRaises(subprocess.TimeoutExpired):
                run.wait(timeout=1)
            self.assertEqual(self.changes(), [])
            self.assertNotIn("briqyard-tunnel", self.firewall.read_text())
            holder.stdin.write("done\n"); holder.stdin.flush()
            output, error = run.communicate(timeout=20)
            self.assertEqual(run.returncode, 0, error)
            self.assertIn("waiting for the installer lock", error)
            self.assertIn("briqyard-tunnel", self.firewall.read_text())
        finally:
            for child in (holder, run):
                if child and child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)

    def test_a_full_run_takes_the_lock_before_it_reads_the_firewall_rule(self):
        self.assertLess(SCRIPT.index("python3 python3-yaml >/dev/null\nruntime_install_lock /etc/briqyard"), SCRIPT.index("tunnel_line=$(host_tunnel_rule)"))

    def test_asking_for_the_lock_twice_does_not_wait_on_itself(self):
        result = subprocess.run(["bash", "-c", INSTALL_LOCK + '\nruntime_install_lock "$1"; runtime_install_lock "$1"; echo twice', "x", str(self.root / "lk")],
                                text=True, capture_output=True, timeout=20)
        self.assertEqual(result.stdout, "twice\n", result.stderr)

    def test_unset_peers_are_not_empty_peers(self):
        result = self.run_script("tunnel_only", None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("needs WIREGUARD_PEERS", result.stderr)

    def render(self, peers):
        """The firewall a full bootstrap writes, through its own rendering code."""
        result = self.run_script("public_dev=eth0; ports=22,9000; " + FIREWALL_RENDER, peers)
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.firewall.read_text()

    def test_a_full_bootstrap_without_peers_keeps_the_installed_rule(self):
        self.only(PEER_A)
        text = self.render(None)
        self.assertEqual(text.count(RULE_LINE), 1)
        self.assertLess(text.index(RULE_LINE), text.index("counter drop"))
        # Given peers, theirs replace it.
        text = self.render(PEER_B)
        self.assertIn("51.68.1.2", text)
        self.assertNotIn("164.132.1.2", text)

    def test_the_rendered_firewall_keeps_the_other_ports_and_the_default_drop(self):
        self.only(PEER_A)
        for peers in (None, PEER_B):
            text = self.render(peers)
            self.assertIn("tcp dport { 22, 9000 } accept", text)
            self.assertIn('iifname != "eth0" accept', text)
            self.assertEqual(text.count("udp dport 51820 accept # briqyard-tunnel"), 1)
            self.assertTrue(text.rstrip().endswith("counter drop\n\t}\n}"))

    def test_a_host_without_a_tunnel_renders_no_tunnel_rule(self):
        self.assertNotIn("briqyard-tunnel", self.render(None))
