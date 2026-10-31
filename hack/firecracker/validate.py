"""Compile exact patched sources and record portable/kernel-dependent evidence."""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

from prepare import HERE, git, prepare

PREFIX = "device_manager::snapshot::tests::"
PORTABLE = [
    ("vmm", PREFIX + "block::checked_sync_errors_are_returned_and_inactive_is_no_io"),
    ("vmm", PREFIX + "block::checked_propagates_real_sync_syscall_failure"),
    ("vmm", PREFIX + "block::checked_refuses_unhandled_block_implementation"),
    ("firecracker", "api_server::parsed_request::checked_snapshot_response_tests::"
     "checked_preparation_failure_is_http_error_not_snapshot_success"),
]
URING = [
    ("vmm", PREFIX + "block::drain_failure_cannot_reach_sync_or_completion"),
    ("vmm", PREFIX + "block::checked_async_errors_are_returned_before_completion_can_succeed"),
    ("vmm", "devices::virtio::block::virtio::device::tests::test_prepare_snapshot_checked"),
]
KVM = [("vmm", PREFIX + name) for name in [
    "block::later_device_failure_precedes_every_transport_and_kvm_save",
    "api::checked_snapshot_refuses_unsupported_backend_on_both_buses",
]]
BOTH = [("vmm", PREFIX + name) for name in [
    "block::checked_inactive_has_no_io_and_preserves_serialized_state",
    "block::checked_prepares_once_without_unchecked_second_pass",
    "api::checked_snapshot_api_refuses_io_failure_before_output_publication",
]]

def negative_detected(returncode, output, name):
    # This exact source site is part of the pinned patched tree. Fixture panics,
    # unrelated assertions and setup/compilation failures are not mutation proof.
    site = r"panicked at [^\n]*device_manager/snapshot/block\.rs:151:9:"
    assertion = ("assertion failed: matches!(block.prepare_snapshot_checked(), "
                 "Err(BlockPrepareError::Io(_)))")
    return (returncode == 101
            and "test result: FAILED. 0 passed; 1 failed;" in output
            and re.search(r"test " + re.escape(name) + r" \.\.\.(?:\s|$)", output) is not None
            and re.search(site, output) is not None
            and assertion in " ".join(output.split()))


def capabilities():
    result = {}
    try:
        fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
        try:
            result["kvm"] = fcntl.ioctl(fd, 0xAE00, 0) == 12
        finally:
            os.close(fd)
    except OSError:
        result["kvm"] = False
    # io_uring_setup is syscall 425 on the two supported Linux architectures.
    if platform.machine() not in ("x86_64", "aarch64"):
        raise RuntimeError("unsupported validation architecture")
    libc = ctypes.CDLL(None, use_errno=True)
    params = ctypes.create_string_buffer(256)
    fd = libc.syscall(ctypes.c_long(425), ctypes.c_uint(8), ctypes.byref(params))
    result["io_uring"] = fd >= 0
    if fd >= 0:
        os.close(fd)
    else:
        result["io_uring_errno"] = ctypes.get_errno()
    return result

class Validation:
    def __init__(self, source, output):
        self.source = source.resolve()
        self.output = output.resolve()
        if self.output == self.source or self.source in self.output.parents:
            raise ValueError("output must be outside source checkout")
        self.output.mkdir(parents=True, exist_ok=False)
        self.receipt = {"status": "running", "architecture": platform.machine(), "tests": []}
        self.env = dict(os.environ, RUSTUP_TOOLCHAIN="1.97.0", CARGO_BUILD_JOBS="2")
        self.env["CARGO_TARGET_DIR"] = str(self.output / "target-positive")

    def command(self, args, name, source=None, env=None):
        print("Running:", name, flush=True)
        log = self.output / (name + ".log")
        with log.open("w") as stream:
            completed = subprocess.run(args, cwd=source or self.source,
                                       env=env or self.env, stdout=stream,
                                       stderr=subprocess.STDOUT, timeout=2400)
        if completed.returncode:
            print(log.read_text()[-24000:], flush=True)
            raise RuntimeError(f"{name} failed ({completed.returncode})")
        return log

    def build(self, source, env, label, packages):
        args = ["cargo", "test", "--lib", "--locked", "--no-run", "--message-format=json"]
        for package in packages:
            args += ["-p", package]
        log = self.command(args, label, source, env)
        binaries = {}
        for line in log.read_text().splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("profile", {}).get("test"):
                name, executable = item["target"]["name"], item.get("executable")
                if name in packages and executable:
                    if name in binaries and binaries[name] != executable:
                        raise RuntimeError("ambiguous library test executable")
                    binaries[name] = executable
        if set(binaries) != set(packages):
            raise RuntimeError("missing library test executable")
        return binaries

    def test(self, binaries, package, name, negative=False):
        executable = binaries[package]
        listed = subprocess.check_output([executable, name, "--exact", "--list"],
                                         cwd=self.source, env=self.env, text=True)
        if [line for line in listed.splitlines() if line.endswith(": test")] != [name + ": test"]:
            raise RuntimeError("exact test selection did not select one test")
        label = ("negative-" if negative else "positive-") + name.replace("::", "-")
        print("Running:", label, flush=True)
        completed = subprocess.run([executable, name, "--exact", "--nocapture", "--test-threads=1"],
                                   cwd=self.source, env=self.env, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        (self.output / (label + ".log")).write_text(completed.stdout)
        if negative:
            valid = negative_detected(completed.returncode, completed.stdout, name)
        else:
            valid = completed.returncode == 0 and "test result: ok. 1 passed; 0 failed;" in completed.stdout
        if not valid:
            print(completed.stdout[-24000:], flush=True)
            raise RuntimeError("unexpected test outcome")
        self.receipt["tests"].append({"name": name, "negative_control": negative, "status": "passed"})

    def export_test_binaries(self, binaries, pin):
        destination = self.output / "test-binaries"
        destination.mkdir()
        manifest = {"base": pin["base"], "tree": pin["tree"],
                    "series_sha256": pin["series_concatenated_sha256"],
                    "cargo_lock_sha256": hashlib.sha256((self.source / "Cargo.lock").read_bytes()).hexdigest(),
                    "toolchain": pin["toolchain"], "architecture": platform.machine(),
                    "kind": "debug-library-tests", "binaries": {}}
        for name, source in binaries.items():
            target = destination / name
            shutil.copyfile(source, target)
            target.chmod(0o500)
            digest = hashlib.sha256()
            with target.open("rb") as stream:
                for data in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(data)
            manifest["binaries"][name] = {"sha256": digest.hexdigest(), "bytes": target.stat().st_size}
        (destination / "provenance.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def run(self):
        pin = json.loads((HERE / "pin.json").read_text())
        if git(self.source, "rev-parse", "HEAD") != pin["base"] or git(self.source, "write-tree") != pin["tree"]:
            raise RuntimeError("source revision or staged tree mismatch")
        if git(self.source, "diff", "--name-only"):
            raise RuntimeError("unstaged source changes")
        self.receipt.update(base=pin["base"], tree=pin["tree"], toolchain=pin["toolchain"])
        self.receipt["capabilities"] = caps = capabilities()
        self.command(["rustc", "--version", "--verbose"], "toolchain")
        self.command(["cargo", "fmt", "--all", "--", "--check"], "format")
        binaries = self.build(self.source, self.env, "build-positive", ["vmm", "firecracker"])
        self.command(["cargo", "clippy", "--locked", "--lib", "--tests", "-p", "vmm", "-p", "firecracker",
                      "--", "-D", "warnings"], "clippy")
        for package, name in PORTABLE:
            self.test(binaries, package, name)
        for required, tests in [(["io_uring"], URING), (["kvm"], KVM), (["kvm", "io_uring"], BOTH)]:
            for package, name in tests:
                if all(caps[key] for key in required):
                    self.test(binaries, package, name)
                else:
                    self.receipt["tests"].append({"name": name, "status": "unverified", "requires": required})
        negative = self.output / "negative-source"
        self.command(["git", "clone", "--shared", "--no-checkout", str(self.source), str(negative)], "clone-negative")
        git(negative, "checkout", "--detach", pin["base"])
        prepare(negative)
        changed = negative / "src/vmm/src/devices/virtio/block/virtio/device.rs"
        source = changed.read_text()
        needle = "        self.disk.file_engine.drain_and_flush(false)?;"
        if source.count(needle) != 1:
            raise RuntimeError("negative-control mutation is not unique")
        changed.write_text(source.replace(needle, "        let _ = self.disk.file_engine.drain_and_flush(false);"))
        env = dict(self.env, CARGO_TARGET_DIR=str(self.output / "target-negative"))
        negative_binaries = self.build(negative, env, "build-negative", ["vmm"])
        self.test(negative_binaries, *PORTABLE[0], negative=True)
        self.export_test_binaries(binaries, pin)
        self.receipt["status"] = "portable-validation-passed"
        self.receipt["runtime_activation"] = "unverified; validation does not authorize deployment"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    validation = Validation(args.source, args.output)
    try:
        validation.run()
    except Exception:
        validation.receipt["status"] = "failed"
        raise
    finally:
        (validation.output / "receipt.json").write_text(json.dumps(validation.receipt, indent=2) + "\n")
