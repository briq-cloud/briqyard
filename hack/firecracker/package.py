"""Package the checked CLI build and its verified source/validation evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

from prepare import HERE


def record(path):
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size}


def package(source, validation, build, output, arch):
    pin = json.loads((HERE / "pin.json").read_text())
    provenance = json.loads((build / "provenance.json").read_text())
    receipt = json.loads((validation / "receipt.json").read_text())
    if (provenance.get("status") != "static-cli-candidate-built"
            or provenance.get("architecture") != arch
            or provenance.get("target") != arch + "-unknown-linux-musl"
            or provenance.get("base") != pin["base"]
            or provenance.get("tree") != pin["tree"]
            or provenance.get("series_sha256") != pin["series_concatenated_sha256"]
            or receipt.get("status") != "portable-validation-passed"
            or receipt.get("architecture") != arch
            or receipt.get("base") != pin["base"]
            or receipt.get("tree") != pin["tree"]
            or receipt.get("toolchain") != pin["toolchain"]):
        raise ValueError("release source or validation evidence mismatch")
    files = {name: build / name for name in ("firecracker", "jailer", "seccomp_filter.bpf",
                                             "provenance.json", "uapi-inputs.json",
                                             "LICENSE", "NOTICE", "THIRD-PARTY")}
    files.update({"receipt.json": validation / "receipt.json", "pin.json": HERE / "pin.json",
                  "series": HERE / "series", "seccomp-source.json": source / "resources/seccomp" / (provenance["target"] + ".json")})
    files.update({item["path"]: HERE / item["path"] for item in pin["series"]})
    expected = {name: provenance["binaries"][name] for name in ("firecracker", "jailer")}
    expected.update({"seccomp_filter.bpf": provenance["seccomp"]["compiled"],
                     "seccomp-source.json": provenance["seccomp"]["source"],
                     "uapi-inputs.json": provenance["uapi_inputs"],
                     "series": {"sha256": pin["series_file_sha256"]}})
    expected.update({item["path"]: item for item in pin["series"]})
    for name, path in files.items():
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise ValueError(f"missing release input: {name}")
        actual = record(path)
        if name in expected and any(actual[k] != expected[name][k] for k in actual if k in expected[name]):
            raise ValueError(f"release input digest mismatch: {name}")
    with tarfile.open(output, "w:gz") as archive:
        for name, path in sorted(files.items()):
            archive.add(path, arcname=name, recursive=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("source", "validation", "build", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--arch", choices=("x86_64", "aarch64"), required=True)
    args = parser.parse_args()
    package(args.source, args.validation, args.build, args.output, args.arch)
