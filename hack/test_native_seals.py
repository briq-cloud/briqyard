"""Exercise the seal test's configuration and identity checks outside a native host."""
import copy
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

HACK = Path(__file__).parent


class NativeSealIdentity(unittest.TestCase):
    def setUp(self):
        self.source = (HACK / "e2e-seals.sh").read_text()
        self.network = self.source.split("<<'PYNETWORK'\n", 1)[1].split("\nPYNETWORK", 1)[0]
        self.views = [
            {"name": name, "hostname": name + ".internal", "ip": f"10.64.1.{n}",
             "memory_origin": {"source_machine": "m_seed", "stage": "active", "snapshot": "s_seed",
                               "generation": "g_seed", "ram_marker": "shared-ram",
                               "identity": {"ip": f"10.64.1.{n}/24", "hostname": name,
                                            "mac": [2, 0, 0, 0, 0, n]}}}
            for n, name in [(3, "first"), (4, "second")]
        ]
        self.observations = [
            f"02:00:00:00:00:{n:02x}\n10.64.1.{n}/24\n{name}\n"
            f"default via 10.64.1.1 dev eth0\n10.64.1.0/24 dev eth0 scope link src 10.64.1.{n}"
            for n, name in [(3, "first"), (4, "second")]
        ]

    def network_check(self, views, observations):
        args = [{"id": "m_seed", "ip": "10.64.1.2", "snapshot": "s_seed", "generation": "g_seed"},
                *views, {"subnet": "10.64.1.0/24", "router": "10.64.1.1"}]
        return subprocess.run([sys.executable, "-c", self.network, *map(json.dumps, args), *observations],
                              capture_output=True, text=True)

    def test_short_guest_hostname_matches_public_dns_name(self):
        result = self.network_check(self.views, self.observations)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_network_contract_rejects_independent_identity_and_route_mismatches(self):
        for field, value in [("ip", "10.64.1.9"), ("hostname", "other.internal"), ("name", "other")]:
            with self.subTest(public_field=field):
                views = copy.deepcopy(self.views)
                views[0][field] = value
                self.assertNotEqual(self.network_check(views, self.observations).returncode, 0)
        for field, value in [("ip", "10.64.1.9/24"), ("ip", "10.64.1.3/25"),
                             ("hostname", "other"), ("mac", [2, 0, 0, 0, 0, 9])]:
            with self.subTest(receipt_field=field, value=value):
                views = copy.deepcopy(self.views)
                views[0]["memory_origin"]["identity"][field] = value
                self.assertNotEqual(self.network_check(views, self.observations).returncode, 0)
        for before, after in [("02:00:00:00:00:03", "06:b1:0a:40:01:02"),
                              ("10.64.1.3/24", "10.64.1.3/25"),
                              ("10.64.1.3/24", "10.64.1.9/24"), ("\nfirst\n", "\nother\n"),
                              ("via 10.64.1.1", "via 10.64.1.9"), ("dev eth0", "dev eth1"),
                              ("src 10.64.1.3", "src 10.64.1.9"),
                              ("10.64.1.0/24", "10.64.2.0/24")]:
            with self.subTest(guest=before, replacement=after):
                observations = self.observations.copy()
                observations[0] = observations[0].replace(before, after)
                self.assertNotEqual(self.network_check(self.views, observations).returncode, 0)

    def test_source_exec_requires_specific_daemon_refusal_without_nonce(self):
        line = next(line for line in self.source.splitlines() if 'check "seed $seal_gb source keeps' in line)
        check = line.split("'", 1)[1].rsplit("'", 1)[0]
        helper = "seal_source_blocked() {" + self.source.split("seal_source_blocked() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        command = helper + 'seal_source_rc=$1; seal_source_reply=$2; seal_source_nonce=source-nonce; ' + check
        refusal = "error: sealed template builder permits status, memory seal and destroy only (conflict)"
        for code, reply, accepted in [(1, refusal, True),
                                      (1, refusal[:-1] + ", request abc-123)", True),
                                      (0, refusal, False), (2, refusal, False),
                                      (1, "error: connection refused", False),
                                      (1, refusal.replace("conflict", "internal"), False),
                                      (1, "error: clone barrier: operation unavailable (internal)", False),
                                      (1, "source-nonce\n" + refusal, False)]:
            with self.subTest(code=code, reply=reply):
                result = subprocess.run(["bash", "-c", command, "fixture", str(code), reply], capture_output=True)
                self.assertEqual(result.returncode == 0, accepted)


class NativeSealConfig(unittest.TestCase):
    def test_shared_host_setup_does_not_enable_template_recipes(self):
        setup = (HACK / "native-ci.sh").read_text()
        self.assertNotIn("c['templates']", setup)
        self.assertIn("trap 'journal_on_failure $?' EXIT", setup)

    def test_destination_create_explicitly_starts_both_seed_shapes(self):
        source = (HACK / "e2e-seals.sh").read_text()
        query = next(line.strip().split("'", 2)[1] for line in source.splitlines() if "sandbox_seed:{" in line)
        for volume in [None, {"size_gb": 1, "mount": "/work"}]:
            command = ["jq", "-n"]
            for key, value in {"ns": "seal-test", "image": "alpine", "name": "sealed-create-0", "source": "m_seed", "snap": "s_seed", "gen": "g_seed"}.items():
                command.extend(["--arg", key, value])
            command.extend(["--argjson", "volume", json.dumps(volume), query])
            request = json.loads(subprocess.check_output(command, text=True))
            self.assertIs(request.get("start"), True)
            self.assertEqual(request["volume"], volume)
            self.assertEqual(request["cmd"], ["/bin/sh", "-ec", "sleep infinity"])
            self.assertEqual(request["sandbox_seed"]["machine_id"], "m_seed")

    def test_seals_precede_the_only_final_summary(self):
        suite = (HACK / "e2e.sh").read_text()
        self.assertGreater(suite.rfind("suite_summary"), suite.index("e2e-seals.sh"))
        self.assertNotIn("suite_summary", (HACK / "e2e-storage.sh").read_text())

    def test_failed_api_response_body_is_printed(self):
        source = (HACK / "e2e-seals.sh").read_text()
        self.assertIn("seal_api() {", source)
        helper = "seal_api() {" + source.split("seal_api() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        with tempfile.TemporaryDirectory() as directory:
            curl = Path(directory) / "curl"
            curl.write_text("#!/bin/sh\nprintf '%s\\n' '{\"error\":\"fixture rejection\"}'\nexit 22\n")
            curl.chmod(0o700)
            command = 'CURL=("$1"); auth=();\n' + helper + 'seal_api http://fixture/v1/machines'
            result = subprocess.run(["bash", "-c", command, "fixture", str(curl)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 22)
            self.assertEqual(result.stdout, "")
            self.assertIn('{"error":"fixture rejection"}', result.stderr)

    def test_seal_scope_binds_authentication_and_the_installed_init(self):
        fixture = (HACK / "e2e-seals.sh").read_text().split("<<'PYCONFIG'\n", 1)[1].split("\nPYCONFIG", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.yaml"
            installed = root / "briqyard-init"
            installed.write_bytes(b"installed source init")
            config.write_text("token: ''\ninit: " + json.dumps(str(installed)) + "\n")
            fixture = fixture.replace("'/etc/briqyard/config.yaml'", repr(str(config)))
            subprocess.run([sys.executable, "-c", fixture], check=True, cwd=root)
            c = yaml.safe_load(config.read_text())
            self.assertTrue(c["token"])
            self.assertTrue(c["templates"]["enabled"])
            digest = hashlib.sha256(installed.read_bytes()).hexdigest()
            self.assertEqual(c["templates"]["init_ready_init_sha256"], digest)
            recipes = c["templates"]["sandbox_recipes"]
            self.assertEqual([r["volume_gb"] for r in recipes], [0, 1])
            for recipe in recipes:
                self.assertEqual(recipe["init_sha256"], digest)
                self.assertRegex(recipe["image"], r"^docker.io/library/alpine@sha256:[0-9a-f]{64}$")
                self.assertRegex(recipe["image_config_digest"], r"^sha256:[0-9a-f]{64}$")


class NativeUnboundAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("unbound_proof", HACK / "e2e-unbound-proof.py")
        cls.proof = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.proof)

    def test_credentials_fail_closed_on_changed_or_missing_kernel_evidence(self):
        valid = "Uid: 1002 1002 1002 1002\nGid: 1002 1002 1002 1002\nGroups: 1002\n"
        self.proof.credentials(valid, 1002, 1002)
        for invalid in [valid.replace("1002", "0", 1), valid.replace("Groups: 1002", "Groups: 1002 0"),
                        valid.replace("Groups: 1002\n", ""), valid + "Uid: 1002 1002 1002 1002\n"]:
            with self.assertRaises((AssertionError, KeyError)):
                self.proof.credentials(invalid, 1002, 1002)

    def test_device_mapping_rejects_a_stale_zvol_link(self):
        device = mock.Mock()
        device.stat.return_value = mock.Mock(st_mode=0o60600, st_rdev=42)
        with mock.patch.object(self.proof, "Path") as path, mock.patch.object(self.proof.subprocess, "check_output") as run:
            (path.return_value / "pool/m/m_fixture/data").resolve.return_value = device
            run.return_value = "pool/m/another/data\n"
            with self.assertRaisesRegex(AssertionError, "different dataset"):
                self.proof.checked_device("pool/m/m_fixture/data")
            run.return_value = "pool/m/m_fixture/data\n"
            self.assertEqual(self.proof.checked_device("pool/m/m_fixture/data")[1].st_rdev, 42)
            self.assertEqual(run.call_args.args[0][0], "/usr/lib/udev/zvol_id")
            self.assertEqual(run.call_args.kwargs["timeout"], 5)

    def test_root_refusal_requires_room_in_data_budget(self):
        source = (HACK / "e2e-unbound.sh").read_text()
        check = next(line for line in source.splitlines() if line.startswith("check 'root budget alone"))
        prelude = "check() { eval \"$2\"; }; unbound_recipe='{\"root_disk_gb\":8}';\n"
        status = {"budget": {"root_disk_gb": 8, "data_disk_gb": 2},
                  "charged": {"root_disk_gb": 8, "data_disk_gb": 1}, "fills": 0,
                  "blocked": [{"reason": "budget"}], "pools": [{"slots": [{"status": "ready"}]}]}
        for data, expected in [(2, 0), (1, 1)]:
            status["budget"]["data_disk_gb"] = data
            script = prelude + "unbound_status='" + json.dumps(status) + "'\n" + check
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, expected, result.stderr)

    def test_process_incarnation_includes_kernel_start_ticks_and_host_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "42"
            proc.mkdir()
            boot = root / "boot"
            boot.write_text("host-one\n")
            fields = ["S"] + ["0"] * 18 + ["12345"]
            (proc / "stat").write_text("42 (a process ) name) " + " ".join(fields))
            before = self.proof.incarnation(proc, boot)
            self.assertEqual(before, {"pid": 42, "start_ticks": 12345, "host_boot_id": "host-one"})
            fields[-1] = "12346"
            (proc / "stat").write_text("42 (reused) " + " ".join(fields))
            self.assertNotEqual(before, self.proof.incarnation(proc, boot))
            boot.write_text("host-two\n")
            self.assertNotEqual(before, self.proof.incarnation(proc, boot))

    def test_catalog_fixture_uses_observed_recipe_and_full_disk_budgets(self):
        source = (HACK / "e2e-unbound.sh").read_text()
        fixture = source.split("sudo python3 -c '\n", 1)[1].split("'\nunbound_config=", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text("templates: {enabled: true}\n")
            fixture = fixture.replace('"/etc/briqyard/config.yaml"', repr(str(config)))
            observed = {"profile": "sandbox-ready-v1", "data_device": {"bytes": 1 << 30, "logical_sector_bytes": 512},
                        "root_disk_gb": 11, "namespace": "observed-namespace", "source_machine": "m_observed",
                        "snapshot": "s_observed", "generation": "g_observed", "size": {"vcpus": 1, "memory_mb": 256}}
            subprocess.run([sys.executable, "-c", fixture], input=json.dumps(observed), text=True, check=True, timeout=5)
            templates = yaml.safe_load(config.read_text())["templates"]
            self.assertTrue(templates["unbound_warm_pools"] and templates["warm_pools"])
            policy = templates["warm_policy"]
            self.assertEqual(policy["budget"]["data_disk_gb"], 2)
            self.assertEqual(policy["budget"]["root_disk_gb"], 11)
            entry = policy["catalog"][0]
            for key in ["namespace", "source_machine", "snapshot", "generation", "size"]:
                self.assertEqual(entry[key], observed[key])
            self.assertEqual(entry["max_ready"], 2)
            self.assertEqual(policy["max_fills"], 1)

    def test_provider_shaped_request_binds_first_command_and_replay_identity(self):
        source = (HACK / "e2e-unbound.sh").read_text()
        function = "unbound_request() {" + source.split("unbound_request() {", 1)[1].split("\n}", 1)[0] + "\n}"
        prelude = """T=test; seal_image=alpine; seal_builder=m_source; seal_snapshot='{"id":"s_exact","clone_generation":"g_exact"}';\n"""
        request = json.loads(subprocess.check_output(["bash", "-c", prelude + function + "\nunbound_request native-first"], text=True, timeout=5))
        self.assertEqual(request["sandbox_seed"], {"machine_id": "m_source", "snapshot": "s_exact", "generation": "g_exact", "request_id": "native-first"})
        self.assertEqual(request["volume"], {"size_gb": 1, "mount": "/work"})
        self.assertNotIn("cpu_millis", request["size"])
        self.assertEqual(request["env"], {"NATIVE_BIND": "native-first"})
        self.assertIn("test ! -e /work/first-sentinel", request["cmd"][2])
        self.assertLess(request["cmd"][2].index("cat /native-bind"), request["cmd"][2].index("/work/activations"))

    def test_native_assertion_expressions_execute_with_observed_status_shape(self):
        source = (HACK / "e2e-unbound.sh").read_text()
        checks = "\n".join(line for line in source.splitlines() if line.strip().startswith("check ") and "root budget alone" not in line)
        prelude = r"""
set -eu
check() { eval "$2"; }
unbound_config='{"source":"file","sha256":"fixture"}'
unbound_recipe='{"root_disk_gb":8}'
unbound_status='{"charged":{"memory_mb":256,"cpu_millis":1000,"root_disk_gb":8,"data_disk_gb":1},"fills":0,"max_fills":1}'
unbound_before='{"devices":[{"guid":"root"},{"guid":"second"}]}'
unbound_after=$unbound_before
unbound_first_data=first
unbound_claim=m_slot; unbound_replay=m_slot; unbound_name=native-first; unbound_code=409
BRIQYARD_URL=http://fixture; unbound_pools=http://fixture/pools; unbound_fallback=m_zero
seal_api() { if [ "$1" = "$unbound_pools" ]; then echo '[]'; else echo '{"observation":{"config":{"source":"file","sha256":"fixture"}}}'; fi; }
briqyard() { if [ "$3" = m_zero ]; then echo native-zero; else echo native-first; fi; }
"""
        subprocess.run(["bash", "-c", prelude + checks], check=True, timeout=5)

    def test_absent_native_evidence_returns_only_a_fixed_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text("data_dir: " + directory + "\ntoken: synthetic-not-for-output\n")
            result = subprocess.run([sys.executable, str(HACK / "e2e-unbound-proof.py"), str(config), "m_missing", "paused"],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr.strip(), "native unbound process/disk proof unavailable or inconsistent")

    def test_handover_budget_covers_runtime_admission_and_shutdown(self):
        source = (HACK / "e2e-seals.sh").read_text()
        daemon = HACK.parent / "crates/briqyardd/src"
        shutdown = int(re.search(r"const SHUTDOWN:.*from_secs\((\d+)\)", (daemon / "main.rs").read_text())[1])
        admission_source = (daemon / "machine/launch_identity.rs").read_text().split("pub async fn handover_admission(", 1)[1]
        admission = int(re.search(r"Duration::from_secs\((\d+)\)", admission_source)[1])
        budget = int(re.search(r"^seal_handover_seconds=(\d+)$", source, re.M)[1])
        self.assertEqual(budget, 22 + admission + shutdown + 5 + 7 + 25 + 4)
        self.assertIn('timeout --kill-after=2 "${seal_handover_seconds}s" bash', source)

    def test_restore_handover_requires_signal_incarnation_readiness_and_config(self):
        source = (HACK / "e2e-seals.sh").read_text()
        function = "seal_restore_handover() {" + source.split("seal_restore_handover() {", 1)[1].split("\n}\n", 1)[0] + "\n}"
        function = next(line for line in source.splitlines() if line.startswith("seal_handover_seconds=")) + "\n" + function
        prelude = r"""
set -u
RUNNER_ENVIRONMENT=offline-fixture
timeout() { shift; shift; "$@"; }
sleep() { SECONDS=$((SECONDS+30)); }
sudo() { if [ "$1" = briqyardd ]; then echo '{"source":"file","sha256":"restored"}'; elif [ "$1" = kill ]; then
  [ "$2 $3" = '-USR2 11' ] || return 99
  [ "$scenario" != refused ] || return 1; echo signaled > "$events"
else "$@"; fi; }
systemctl() {
  case "$1" in
    show) if [ -e "$events" ]; then echo 22; else echo 11; fi;;
    kill) [ "$scenario" != refused ] || return 1; echo signaled > "$events";;
    start) return 0;;
  esac
}
briqyard() {
  if [ ! -e "$events" ]; then echo '{"observation":{"incarnation":"old"}}'; return; fi
  [ "$scenario" != unavailable ] || return 1
  local digest=restored incarnation=new
  [ "$scenario" != wrongconfig ] || digest=fixture
  [ "$scenario" != sameincarnation ] || incarnation=old
  printf '{"observation":{"incarnation":"%s","config":{"source":"file","sha256":"%s"}}}' "$incarnation" "$digest"
}
"""
        for scenario in ["success", "refused", "unavailable", "wrongconfig", "sameincarnation"]:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                script = prelude + '\nevents=$1/events; scenario=$2\n' + function + '\nseal_restore_handover old'
                result = subprocess.run(["bash", "-c", script, "fixture", directory, scenario], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0 if scenario == "success" else 1, result.stderr)

    def test_cleanup_exports_real_bash_handover_with_fixed_failure_categories(self):
        source = (HACK / "e2e-seals.sh").read_text()
        functions = ""
        for name in ["seal_restore_handover", "seal_cleanup"]:
            functions += name + "() {" + source.split(name + "() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        functions = next(line for line in source.splitlines() if line.startswith("seal_handover_seconds=")) + "\n" + functions
        functions = functions.replace('sudo cp "$seal_config" /etc/briqyard/config.yaml', 'sudo cp "$seal_config" "$events/restored"')
        prelude = r"""
set -euo pipefail
RUNNER_ENVIRONMENT=offline-fixture
T=owned; pass=0; fail=0; seal_saved=1
seal_original_token=${3-original}; export scenario=$2 events=$1
export BRIQYARD_URL=http://offline-fixture BRIQYARD_TOKEN=native-seal-test
seal_config=$1/config; seal_counts=$1/counts
printf original > "$seal_config"
timeout() {
  shift; shift
  local boundary=
  case "$1" in
    bash)
      [ "$scenario" != overall_timeout ] || return 124
      # Execute the actual exported function in a new Bash, preserving env only.
      "$@"; return $?;;
    sudo)
      case "$2" in
        briqyardd) boundary=check_config;;
        cp) boundary=copy;;
        systemctl) boundary=$3;;
        kill) boundary=kill;;
      esac;;
    systemctl)
      if [ -e "$events/signaled" ]; then boundary=new_pid_query; else boundary=old_pid_query; fi;;
    briqyard)
      if [ "$2" = warm-maintenance ] || [ "$2" = status ]; then
        if [ -e "$events/signaled" ]; then boundary=readiness_query; else boundary=previous_incarnation; fi
      fi;;
  esac
  if [ "$scenario" = "$boundary" ] || [ "$scenario" = "${boundary}_timeout" ]; then
    echo 'synthetic-private-token/config/path/argument' >&2
    case "$scenario" in *_timeout) return 124;; *) return 1;; esac
  fi
  "$@"
}
sleep() {
  if [[ "$scenario" = accepted_* ]]; then
    local tick=0
    [ ! -e "$events/clock" ] || read -r tick < "$events/clock"
    SECONDS=$((tick+1)); echo "$SECONDS" > "$events/clock"
  else SECONDS=$((SECONDS+30)); fi
}
ok() { pass=$((pass+1)); }
sudo() {
  if [ "$1" = briqyardd ]; then echo '{"source":"file","sha256":"original"}'; elif [ "$1" = kill ]; then
    [ "$2 $3" = '-USR2 11' ] || return 99
    [ ! -e "$events/signaled" ] || return 99
    echo signal > "$events/signaled"
    # Spend every preflight allowance before a full admission/shutdown interval.
    if [ "$scenario" = accepted_caps ]; then SECONDS=22; echo 22 > "$events/clock"; fi
  else "$@"; fi
}
systemctl() {
  case "$1" in
    show)
      local changed_at=64
      [ "$scenario" != accepted_caps ] || changed_at=87
      if [ -e "$events/signaled" ]; then
        if [ "$scenario" = pid_change_exhausted ] || [ "$scenario" = accepted_expired ] || { [[ "$scenario" = accepted_* ]] && [ "$(cat "$events/clock" 2>/dev/null || echo 0)" -lt "$changed_at" ]; }; then echo 11; else echo 22; fi
      elif [ "$scenario" = old_pid_invalid ]; then echo 0; else echo 11; fi;;
    kill) echo signal > "$events/signaled";;
    start) :;;
  esac
}
briqyard() {
  if [ "$1 ${2-}" = 'namespace ls' ]; then echo '[]'; return; fi
  if [ "$1" = warm-maintenance ] || [ "$1" = status ]; then
    [ "$BRIQYARD_URL" = http://offline-fixture ] || return 22
    # Match api/warm.rs: maintenance requires configured auth, even on loopback.
    if [ "$1" = warm-maintenance ] && [ -e "$events/signaled" ] && [ -z "$seal_expected_token" ]; then return 1; fi
    if [ -e "$events/signaled" ]; then
      [ "${BRIQYARD_TOKEN-}" = "${seal_expected_token-}" ] || return 22
      local ready_at=84
      [ "$scenario" != accepted_caps ] || ready_at=107
      if [[ "$scenario" = accepted_* ]] && [ "$(cat "$events/clock")" -lt "$ready_at" ]; then return 1; fi
      echo new >> "$events/queries"
      local incarnation=new digest=original
      [ "$scenario" != sameincarnation ] || incarnation=old
      [ "$scenario" != emptyincarnation ] || incarnation=
      case "$scenario" in wrongconfig|accepted_slow_wrongconfig) digest=fixture;; accepted_slow_sameincarnation) incarnation=old;; esac
      if [ "$scenario" = recovery_fault ]; then echo '{"conditions":[]}'; elif [ "$scenario" = malformed ]; then echo '{'; else
        printf '{"observation":{"incarnation":"%s","config":{"source":"file","sha256":"%s"}}}\n' "$incarnation" "$digest"
      fi
    else
      [ "$BRIQYARD_TOKEN" = native-seal-test ] || return 22
      echo old >> "$events/queries"
      if [ "$scenario" = missingincarnation ]; then echo '{"observation":{}}'; else
        echo '{"observation":{"incarnation":"old"}}'
      fi
    fi
  fi
}
seal_api() { echo '{"eligible":true,"reason":"eligible","counts":{"desired_slots":0,"pool_claims":0,"warm_machines":0,"launch_holds":0,"launch_transitions":0,"warm_names":0,"pending_assignments":0,"run_authorities":0}}'; }
export seal_expected_token=$seal_original_token
export -f timeout sleep sudo systemctl briqyard
"""
        scenarios = {"success": None, "accepted_slow": None, "accepted_caps": None,
                     "accepted_expired": "pid_change_exhausted",
                     "accepted_slow_wrongconfig": "readiness_exhausted_identity_mismatch",
                     "accepted_slow_sameincarnation": "readiness_exhausted_identity_mismatch", "missingincarnation": "previous_incarnation_invalid",
                     "previous_incarnation": "previous_incarnation_query", "previous_incarnation_timeout": "previous_incarnation_timeout",
                     "copy": "config_restore", "copy_timeout": "config_restore_timeout",
                     "old_pid_invalid": "old_pid_invalid", "pid_change_exhausted": "pid_change_exhausted",
                     "sameincarnation": "readiness_exhausted_identity_mismatch", "emptyincarnation": "readiness_exhausted_identity_mismatch",
                     "wrongconfig": "readiness_exhausted_identity_mismatch", "recovery_fault": "readiness_exhausted_identity_mismatch", "malformed": "readiness_exhausted_identity_mismatch",
                     "readiness_query": "readiness_exhausted_query_failed",
                     "readiness_query_timeout": "readiness_exhausted_query_timeout", "overall_timeout": "overall_timeout"}
        for boundary in ["check_config", "old_pid_query", "new_pid_query", "kill", "start"]:
            category = "signal" if boundary == "kill" else boundary
            scenarios[boundary] = category
            scenarios[boundary + "_timeout"] = category + "_timeout"
        for scenario, category in scenarios.items():
            for original_token in ["original", ""]:
                with self.subTest(scenario=scenario, authenticated=bool(original_token)), tempfile.TemporaryDirectory() as directory:
                    # Guard against missing function exports invoking any host command.
                    guard = Path(directory) / "bin"
                    guard.mkdir()
                    for command in ["sudo", "systemctl", "briqyard", "briqyardd", "timeout"]:
                        fake = guard / command
                        fake.write_text("#!/bin/sh\necho offline_guard >&2\nexit 99\n")
                        fake.chmod(0o700)
                    script = 'export PATH="$1/bin:$PATH"\n' + prelude + functions + "\ntrap seal_cleanup EXIT\nexit 0"
                    result = subprocess.run(["bash", "-c", script, "fixture", directory, scenario, original_token],
                                            capture_output=True, text=True, timeout=5)
                    root = Path(directory)
                    self.assertEqual(result.returncode, 0 if category is None else 1, result.stderr)
                    self.assertEqual(result.stdout, "")
                    if category is None:
                        self.assertEqual(result.stderr, "")
                        self.assertEqual((root / "queries").read_text().splitlines(), ["old", "new"])
                    else:
                        expected = "sealed restoration: " + category
                        lines = [expected]
                        if scenario in ["copy", "copy_timeout"]:
                            lines.append("original configuration restore failed; private backup retained")
                        elif scenario not in ["previous_incarnation", "previous_incarnation_timeout", "missingincarnation", "overall_timeout"]:
                            if scenario not in ["check_config", "check_config_timeout", "old_pid_query", "old_pid_query_timeout", "old_pid_invalid"]:
                                lines.append("sealed restoration handover evidence: unknown")
                            lines.append("sealed restoration: handover_failed")
                        self.assertEqual(result.stderr.splitlines(), lines)
                    if scenario not in ["copy", "copy_timeout"]:
                        self.assertEqual((root / "restored").read_text(), "original")
                    self.assertTrue((root / "counts").exists())
                    if scenario in ["previous_incarnation", "previous_incarnation_timeout", "missingincarnation", "copy", "copy_timeout", "check_config", "check_config_timeout",
                                    "old_pid_query", "old_pid_query_timeout", "old_pid_invalid", "kill", "kill_timeout", "overall_timeout"]:
                        self.assertFalse((root / "signaled").exists())


    def test_failure_journal_projection_uses_recorded_signal_attempt_and_no_raw_output(self):
        source = (HACK / "e2e-seals.sh").read_text()
        function = "seal_restore_handover() {" + source.split("seal_restore_handover() {", 1)[1].split("\n}\n", 1)[0] + "\n}"
        function = next(line for line in source.splitlines() if line.startswith("seal_handover_seconds=")) + "\n" + function
        projection_path = HACK / "e2e-handover-evidence.py"
        spec = importlib.util.spec_from_file_location("handover_evidence", projection_path)
        projection = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(projection)
        daemon = (HACK.parent / "crates/briqyardd/src/main.rs").read_text()
        maintenance = (HACK.parent / "crates/briqyardd/src/machine/maintenance.rs").read_text()
        identity = (HACK.parent / "crates/briqyardd/src/machine/launch_identity.rs").read_text()
        compatibility = (HACK.parent / "crates/briqyardd/src/assignment_compatibility.rs").read_text()
        for message in ["handover refused; daemon remains serving", "shutting down", "handed over", "the shutdown ran past 60 s: ending without it"]:
            self.assertIn('"' + message + '"', daemon)
        for reason in projection.REFUSALS:
            if reason.startswith("warm catalog maintenance refused:"):
                self.assertIn('"warm catalog maintenance refused: {:?}"', identity)
                self.assertIn("R::" + reason.split(": ")[1], maintenance)
            else:
                self.assertIn('"' + reason + '"', maintenance + compatibility)

        def record(message, level="INFO", **fields):
            return {"_PID": "11", "_SYSTEMD_UNIT": "briqyardd.service", "_COMM": "briqyardd",
                    "_EXE": "/usr/local/bin/briqyardd", "_TRANSPORT": "stdout",
                    "__REALTIME_TIMESTAMP": "1700000000000001",
                    "MESSAGE": json.dumps({"level": level, "fields": {"message": message, **fields}})}

        def encoded(*entries):
            return "".join(json.dumps(entry) + "\n" for entry in entries)

        refusal = record("handover refused; daemon remains serving", "ERROR", err="synthetic-private-token/config/path")
        accepted = record("shutting down", hand_over=True)
        cases = [("absent", "", "unknown"), ("malformed", "synthetic-private-token/config/path", "unknown"),
                 ("unclassified_refusal", encoded(refusal), "refused_unknown"),
                 ("accepted", encoded(accepted), "accepted_shutdown"),
                 ("shutdown_timeout", encoded(accepted, record("the shutdown ran past 60 s: ending without it", "WARN", hand_over=True)), "accepted_shutdown_timeout"),
                 ("complete", encoded(accepted, record("handed over")), "accepted_complete"),
                 ("contradictory", encoded(accepted, refusal), "unknown"),
                 ("substring", encoded(record("CLI echo: handed over synthetic-private-token/config/path")), "unknown"),
                 ("stopping", encoded(record("shutting down", hand_over=False)), "unknown"),
                 ("wrong_level", encoded(record("handover refused; daemon remains serving", "INFO", err="synthetic-private-token/config/path")), "unknown"),
                 ("over_bytes", "x" * (projection.LIMIT_BYTES + 1), "unknown"),
                 ("over_count", encoded(*([accepted] * (projection.LIMIT_ENTRIES + 1))), "unknown"),
                 ("retrieval_failure", encoded(accepted), "unknown"),
                 ("retrieval_timeout", encoded(accepted), "unknown"),
                 ("outside_ci", encoded(accepted), "unknown"),
                 ("missing_timestamp", encoded(accepted), "unknown")]
        for error, category in projection.REFUSALS.items():
            cases.append((category, encoded(record("handover refused; daemon remains serving", "ERROR", err=error)), "refused_" + category))
        for key, value in {"_PID": "22", "_SYSTEMD_UNIT": "other.service", "_COMM": "bash", "_EXE": "/bin/bash", "_TRANSPORT": "journal", "__REALTIME_TIMESTAMP": "1700000000000000"}.items():
            wrong = dict(accepted, **{key: value})
            cases.append((key, encoded(wrong), "unknown"))
        wrong = dict(accepted, _PID=["11", "22"])
        cases.append(("ambiguous_metadata", encoded(wrong), "unknown"))
        cases.append(("duplicate_json", encoded(accepted).replace('"_PID": "11"', '"_PID": "11", "_PID": "11"'), "unknown"))
        prelude = r"""
set -euo pipefail
RUNNER_ENVIRONMENT=github-hosted
[ "$scenario" != outside_ci ] || RUNNER_ENVIRONMENT=offline-fixture
timeout() { shift; shift; "$@"; }
sleep() { SECONDS=$((SECONDS+30)); }
date() { [ "$scenario" != missing_timestamp ] || return 1; echo 1700000000.000001; }
sudo() {
  case "$1" in
    briqyardd) echo '{"source":"file","sha256":"original"}';;
    kill) [ "$2 $3" = '-USR2 11' ] || return 99; echo signal >> "$events";;
    journalctl) journalctl "${@:2}";;
    *) return 99;;
  esac
}
systemctl() { [ "$*" = 'show -p MainPID --value briqyardd' ] || return 99; echo 11; }
journalctl() {
  [ "$*" = '-b -u briqyardd --no-pager -o json -n 129 --since=@1700000000.000001 _PID=11' ] || return 99
  echo journal >> "$events"
  cat "$fixture"
  echo 'synthetic-private-token/config/path' >&2
  [ "$scenario" != retrieval_failure ] || return 1
  [ "$scenario" != retrieval_timeout ] || return 124
}
"""
        for scenario, fixture, category in cases:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "fixture").write_text(fixture)
                # A missing fake must never reach host journal/systemd or signal commands.
                guard = root / "bin"
                guard.mkdir()
                for command in ["sudo", "systemctl", "journalctl", "kill", "briqyard", "briqyardd", "timeout"]:
                    fake = guard / command
                    fake.write_text("#!/bin/sh\necho offline_guard >&2\nexit 99\n")
                    fake.chmod(0o700)
                setup = 'export PATH="$1/bin:$PATH"\nevents=$1/events; fixture=$1/fixture; scenario=$2; seal_handover_projection=$3\n'
                caller = "\nexport RUNNER_ENVIRONMENT events fixture scenario seal_handover_projection seal_handover_seconds\nexport -f timeout sleep date sudo systemctl journalctl seal_restore_handover\nbash -c 'seal_restore_handover old'"
                result = subprocess.run(["bash", "-c", setup + prelude + function + caller,
                                         "fixture", directory, scenario, str(projection_path.resolve())], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr.splitlines(), ["sealed restoration: pid_change_exhausted",
                                 "sealed restoration handover evidence: " + category])
                expected = ["signal"] if scenario in ["outside_ci", "missing_timestamp"] else ["signal", "journal"]
                self.assertEqual((root / "events").read_text().splitlines(), expected)

    def test_cleanup_refuses_handover_when_authority_is_outstanding(self):
        source = (HACK / "e2e-seals.sh").read_text()
        cleanup = "seal_cleanup() {" + source.split("seal_cleanup() {", 1)[1].split("\n}\n", 1)[0] + "\n}"
        cleanup = next(line for line in source.splitlines() if line.startswith("seal_handover_seconds=")) + "\n" + cleanup
        for eligible in [True, False, None]:
            with self.subTest(eligible=eligible), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                prelude = """
T=owned; pass=0; fail=0; seal_saved=1; seal_original_token=; seal_config=$1/config; seal_counts=$1/counts
printf original > "$seal_config"
sudo() { echo restore >> "$1"; }
# Replace only the host-copy invocation; no native command may run in this fake.
sleep() { SECONDS=$((SECONDS+10)); }
timeout() { shift; shift; if [ "$1" = bash ]; then handover; else "$@"; fi; }
briqyard() { if [ "$1 $2" = 'namespace ls' ]; then echo '[]'; elif [ "$1" = warm-maintenance ]; then echo '{"observation":{"incarnation":"old"}}'; fi; }
seal_api() { printf '%s' "$fixture_response"; }
ok() { pass=$((pass+1)); }
handover() { echo handover >> "$events"; }
"""
                cleanup = cleanup.replace('sudo cp "$seal_config" /etc/briqyard/config.yaml', 'echo restore >> "$events"')
                counts = {key: 0 for key in ["desired_slots", "pool_claims", "warm_machines", "launch_holds", "launch_transitions", "warm_names", "pending_assignments", "run_authorities"]}
                if not eligible:
                    counts["pending_assignments"] = 1
                maintenance = json.dumps({"eligible": eligible, "reason": "eligible" if eligible else "outstanding_warm_state", "counts": counts})
                if eligible is None:
                    # The first bounded CLI exhausts the shared drain budget. Restoration
                    # must still run, and no later CLI or handover may be attempted.
                    prelude = prelude.replace(
                        'timeout() { shift; shift; if [ "$1" = bash ]; then handover; else "$@"; fi; }',
                        'timeout() { shift; shift; if [ "$1" = briqyard ]; then SECONDS=$((SECONDS+91)); return 124; else "$@"; fi; }')
                script = prelude + "\nfixture_response=" + "'" + maintenance + "'\nevents=$1/events\n" + cleanup + "\nseal_cleanup"
                result = subprocess.run(["bash", "-c", script, "fixture", directory], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0 if eligible else 1, result.stderr)
                self.assertEqual((root / "events").read_text().splitlines(), ["restore", "handover"] if eligible else ["restore"])


if __name__ == "__main__":
    unittest.main()
