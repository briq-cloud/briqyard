"""Export static CLI candidates from the already verified, pinned source tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

from prepare import HERE, git

ARCHES = {"x86_64": "x86_64-linux-gnu", "aarch64": "aarch64-linux-gnu"}
FORBIDDEN = ("empty default seccomp", "No default seccomp policy")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def record(path):
    return {"sha256": digest(path), "bytes": path.stat().st_size}


def production_outputs(messages, target_root):
    """Bind executables and seccomp OUT_DIR to this Cargo invocation, not a glob."""
    if any(phrase.lower() in messages.lower() for phrase in FORBIDDEN):
        raise RuntimeError("release build used an empty seccomp policy")
    events = [json.loads(line) for line in messages.splitlines() if line.strip()]
    binaries = {}
    package = None
    for event in events:
        if event.get("reason") != "compiler-artifact":
            continue
        name = event.get("target", {}).get("name")
        if name not in ("firecracker", "jailer") or not event.get("executable"):
            continue
        if event.get("profile", {}).get("test") or "bin" not in event["target"]["kind"]:
            raise RuntimeError("unexpected CLI build profile")
        path = Path(event["executable"]).resolve()
        if path.parent != target_root.resolve() or name in binaries:
            raise RuntimeError("ambiguous or out-of-target CLI executable")
        binaries[name] = path
        if name == "firecracker":
            package = event["package_id"]
    if set(binaries) != {"firecracker", "jailer"}:
        raise RuntimeError("missing CLI executable")
    outputs = {Path(e["out_dir"]).resolve() for e in events
               if e.get("reason") == "build-script-executed" and e.get("package_id") == package}
    if len(outputs) != 1:
        raise RuntimeError("missing or ambiguous production seccomp output")
    output = outputs.pop()
    if output.parent.parent != (target_root / "build").resolve() or output.name != "out":
        raise RuntimeError("seccomp output is outside the release build directory")
    return binaries, output / "seccomp_filter.bpf"


def check_static(headers, program_headers, dynamic, arch):
    expected = {"aarch64": "AArch64", "x86_64": "Advanced Micro Devices X86-64"}[arch]
    if not re.search(r"Class:\s+ELF64", headers) or not re.search(r"Machine:\s+" + expected, headers):
        raise RuntimeError("ELF architecture mismatch")
    if re.search(r"\bINTERP\b", program_headers) or re.search(r"\(NEEDED\)", dynamic):
        raise RuntimeError("CLI executable is dynamically linked")


class Build:
    def __init__(self, source, validation, output, arch):
        self.source, self.validation, self.output = (p.resolve() for p in (source, validation, output))
        if arch not in ARCHES or platform.machine() != arch:
            raise RuntimeError("native runner architecture mismatch")
        if self.source == self.output or self.source in self.output.parents:
            raise RuntimeError("artifact output must be outside source")
        self.output.mkdir(parents=True, exist_ok=False)
        self.arch = arch
        self.target = arch + "-unknown-linux-musl"
        self.env = dict(os.environ, RUSTUP_TOOLCHAIN="1.97.0", CARGO_BUILD_JOBS="2",
                        CARGO_TARGET_DIR=str(self.validation / "target-positive"))
        self.manifest = {"status": "running", "kind": "static-cli-candidate",
                         "runtime_activation": "unverified; no deployment authorized"}

    def command(self, args, name):
        with (self.output / (name + ".log")).open("w") as stream:
            result = subprocess.run(args, cwd=self.source, env=self.env, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=2400)
        if result.returncode:
            raise RuntimeError(f"{name} failed ({result.returncode}); inspect its log")
        return (self.output / (name + ".log")).read_text()

    def uapi(self):
        destination = self.output / "uapi" / "include"
        files = {}
        for source in (Path("/usr/include/linux"), Path("/usr/include/asm-generic"),
                       Path("/usr/include") / ARCHES[self.arch] / "asm"):
            if not source.is_dir() or source.is_symlink():
                raise RuntimeError("missing native Linux UAPI directory")
            for path in sorted(source.rglob("*")):
                if path.is_symlink():
                    raise RuntimeError("unexpected symlink in Linux UAPI")
                if not path.is_file():
                    continue
                relative = Path(source.name) / path.relative_to(source)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                files[str(relative)] = record(target)
                if files[str(relative)] != record(path):
                    raise RuntimeError("UAPI copy hash mismatch")
        (self.output / "uapi-inputs.json").write_text(json.dumps(files, indent=2) + "\n")
        self.env["CFLAGS_" + self.target.replace("-", "_")] = "-idirafter " + str(destination)
        self.env["CC_" + self.target.replace("-", "_")] = "musl-gcc"
        self.env["CARGO_TARGET_" + self.target.upper().replace("-", "_") + "_LINKER"] = "musl-gcc"

    def run(self):
        pin = json.loads((HERE / "pin.json").read_text())
        if git(self.source, "rev-parse", "HEAD") != pin["base"] or git(self.source, "write-tree") != pin["tree"]:
            raise RuntimeError("prepared source does not match the exact pin")
        if git(self.source, "diff", "--name-only") or git(self.source, "ls-files", "--others", "--exclude-standard"):
            raise RuntimeError("unexpected source changes")
        receipt = json.loads((self.validation / "receipt.json").read_text())
        if receipt.get("status") != "portable-validation-passed" or receipt.get("tree") != pin["tree"]:
            raise RuntimeError("matching portable validation must pass first")
        workflow_commit = git(HERE, "rev-parse", "HEAD")
        if workflow_commit != os.environ["GITHUB_SHA"]:
            raise RuntimeError("workflow checkout revision mismatch")
        self.manifest.update(base=pin["base"], tree=pin["tree"], architecture=self.arch,
                             target=self.target, series_sha256=pin["series_concatenated_sha256"],
                             cargo_lock=record(self.source / "Cargo.lock"),
                             workflow={"repository": os.environ["GITHUB_REPOSITORY"],
                                       "commit": workflow_commit, "run_id": os.environ["GITHUB_RUN_ID"],
                                       "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"]})
        self.manifest["tools"] = {
            "rustc": self.command(["rustc", "--version", "--verbose"], "rustc").strip(),
            "gcc": self.command(["musl-gcc", "--version"], "musl-gcc").strip(),
            "packages": self.command(["dpkg-query", "-W", "-f=${Package} ${Version}\n",
                                      "linux-libc-dev", "musl", "musl-dev", "musl-tools", "libseccomp-dev"], "packages").strip()}
        self.manifest["host_seccomp_library"] = record(
            (Path("/usr/lib") / ARCHES[self.arch] / "libseccomp.so.2").resolve(strict=True))
        self.manifest["tool_binaries"] = {}
        for name, path in {
            "rustc": self.command(["rustup", "which", "rustc"], "rustc-path").strip(),
            "musl-gcc": shutil.which("musl-gcc"),
            "gcc": shutil.which("gcc"),
            "cc1": self.command(["musl-gcc", "-print-prog-name=cc1"], "cc1-path").strip(),
        }.items():
            self.manifest["tool_binaries"][name] = record(Path(path).resolve(strict=True))
        self.uapi()
        self.manifest["uapi_inputs"] = record(self.output / "uapi-inputs.json")
        args = ["cargo", "build", "--release", "--locked", "--target", self.target,
                "-p", "firecracker", "-p", "jailer", "--bin", "firecracker", "--bin", "jailer",
                "--message-format=json"]
        # Keep JSON and compiler diagnostics separate so both can be checked.
        with (self.output / "cargo.jsonl").open("w") as stdout, (self.output / "cargo.stderr.log").open("w") as stderr:
            result = subprocess.run(args, cwd=self.source, env=self.env, stdout=stdout, stderr=stderr, timeout=2400)
        if result.returncode:
            raise RuntimeError("release CLI build failed; inspect cargo logs")
        stderr = (self.output / "cargo.stderr.log").read_text()
        if any(phrase.lower() in stderr.lower() for phrase in FORBIDDEN):
            raise RuntimeError("release compiler emitted an empty seccomp warning")
        root = Path(self.env["CARGO_TARGET_DIR"]) / self.target / "release"
        binaries, policy = production_outputs((self.output / "cargo.jsonl").read_text(), root)
        if not policy.is_file() or policy.stat().st_size <= 0:
            raise RuntimeError("missing production seccomp bytecode")
        self.manifest["seccomp"] = {"compiled": record(policy),
                                    "source": record(self.source / "resources/seccomp" / (self.target + ".json"))}
        shutil.copyfile(policy, self.output / "seccomp_filter.bpf")
        self.manifest["binaries"] = {}
        for name, source in binaries.items():
            check_static(self.command(["readelf", "-h", str(source)], name + "-elf"),
                         self.command(["readelf", "-l", str(source)], name + "-program"),
                         self.command(["readelf", "-d", str(source)], name + "-dynamic"), self.arch)
            version = self.command([str(source), "--version"], name + "-version").strip()
            if not version.startswith(name.title() + " v") and not version.startswith(name + " v"):
                raise RuntimeError("unexpected executable version")
            target = self.output / name
            shutil.copyfile(source, target)
            target.chmod(0o500)
            self.manifest["binaries"][name] = dict(record(target), version=version)
        for name in ("LICENSE", "NOTICE", "THIRD-PARTY"):
            shutil.copyfile(self.source / name, self.output / name)
        self.manifest["status"] = "static-cli-candidate-built"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for arg in ("source", "validation", "output"):
        parser.add_argument(arg, type=Path)
    parser.add_argument("--arch", choices=ARCHES, required=True)
    args = parser.parse_args()
    build = Build(args.source, args.validation, args.output, args.arch)
    try:
        build.run()
    except Exception:
        build.manifest["status"] = "failed"
        raise
    finally:
        (build.output / "provenance.json").write_text(json.dumps(build.manifest, indent=2) + "\n")
