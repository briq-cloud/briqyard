"""Stage a local runtime release with the same checked bundle as bootstrap."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
BINARIES = ("briqyardd", "briqyard-init", "briqyard", "briqyard-fleet")


def verify_bundle(bundle, digest, arch):
    if arch not in ("aarch64", "x86_64"):
        raise ValueError("unsupported runtime architecture")
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("a trusted release bundle SHA256 is required")
    if bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("expected a bounded regular runtime bundle")
    if hashlib.sha256(bundle.read_bytes()).hexdigest() != digest:
        raise ValueError("runtime bundle differs from trusted release digest")
    with tarfile.open(bundle, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 64 or sum(m.size for m in members) > 32 * 1024 * 1024:
            raise ValueError("runtime bundle exceeds bounds")
        pin = json.load(archive.extractfile("pin.json"))
        if pin != json.loads((HERE / "firecracker/pin.json").read_text()):
            raise ValueError("runtime bundle differs from current source pin")
    # Reuse the installer's complete member, provenance, validation and digest checks.
    script = (HERE / "bootstrap-host.sh").read_text()
    helpers = script.split("# Runtime installation helpers.", 1)[1].split(
        "# End runtime installation helpers.", 1)[0]
    helpers = helpers[helpers.index("checked_bundle()") :]
    with tempfile.TemporaryDirectory() as destination:
        try:
            subprocess.run(["bash", "-c", "set -euo pipefail\n" + helpers + '\nchecked_bundle "$@"',
                            "checked-bundle", str(bundle.resolve()), arch, str(Path(destination) / "checked")],
                           check=True, capture_output=True, timeout=30)
        except subprocess.CalledProcessError:
            raise ValueError("bootstrap rejected runtime bundle evidence") from None


def stage_release(bundle, digest, arch, binaries, output):
    verify_bundle(bundle, digest, arch)
    # Validate and copy every input before changing an existing local release.
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        staging = Path(temporary)
        for name in BINARIES:
            shutil.copyfile(binaries / name, staging / f"{name}-linux-{arch}")
        copied_bundle = staging / f"firecracker-checked-linux-{arch}.tar.gz"
        shutil.copyfile(bundle, copied_bundle)
        if hashlib.sha256(copied_bundle.read_bytes()).hexdigest() != digest:
            raise ValueError("runtime bundle changed while staging")
        assets = sorted(staging.iterdir())
        sums = "".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n"
                       for p in assets)
        manifest = staging / f"SHA256SUMS-{arch}"
        manifest.write_text(sums)
        for asset in assets + [manifest]:
            asset.replace(output / asset.name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "stage"))
    parser.add_argument("bundle", type=Path)
    parser.add_argument("sha256", help="digest from a verified release manifest")
    parser.add_argument("--arch", required=True, choices=("aarch64", "x86_64"))
    parser.add_argument("--binaries", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.action == "verify":
        verify_bundle(args.bundle, args.sha256, args.arch)
    else:
        if args.binaries is None or args.output is None:
            parser.error("stage requires --binaries and --output")
        stage_release(args.bundle, args.sha256, args.arch, args.binaries, args.output)
