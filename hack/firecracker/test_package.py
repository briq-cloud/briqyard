import json
from pathlib import Path
import tempfile
import unittest

from package import package, record
from prepare import HERE


def fixture(root, arch="x86_64"):
    source, validation, build = (root / name for name in ("source", "validation", "build"))
    for path in (source / "resources/seccomp", validation, build):
        path.mkdir(parents=True)
    pin = json.loads((HERE / "pin.json").read_text())
    for name in ("firecracker", "jailer"):
        (build / name).write_text("#!/bin/sh\necho '" + name.title() + " v1.17.0'\n# checked\n")
    for name in ("seccomp_filter.bpf", "uapi-inputs.json", "LICENSE", "NOTICE", "THIRD-PARTY"):
        (build / name).write_text(name + "\n")
    policy = source / "resources/seccomp" / (arch + "-unknown-linux-musl.json")
    policy.write_text('{"production": true}\n')
    provenance = dict(status="static-cli-candidate-built", architecture=arch,
                      target=arch + "-unknown-linux-musl", base=pin["base"], tree=pin["tree"],
                      series_sha256=pin["series_concatenated_sha256"],
                      binaries={name: record(build / name) for name in ("firecracker", "jailer")},
                      seccomp={"compiled": record(build / "seccomp_filter.bpf"), "source": record(policy)},
                      uapi_inputs=record(build / "uapi-inputs.json"))
    (build / "provenance.json").write_text(json.dumps(provenance))
    (validation / "receipt.json").write_text(json.dumps(dict(status="portable-validation-passed",
                 architecture=arch, base=pin["base"], tree=pin["tree"], toolchain=pin["toolchain"])))
    output = root / "firecracker-checked-linux-x86_64.tar.gz"
    package(source, validation, build, output, arch)
    return source, validation, build, output


class ReleasePackage(unittest.TestCase):
    def test_packaging_refuses_changed_executables_policy_and_evidence(self):
        for name in ("firecracker", "jailer", "seccomp_filter.bpf", "uapi-inputs.json", "NOTICE"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                source, validation, build, output = fixture(Path(directory))
                if name == "NOTICE":
                    (build / name).unlink()
                else:
                    (build / name).write_text("changed")
                with self.assertRaises(ValueError):
                    package(source, validation, build, output, "x86_64")
        with tempfile.TemporaryDirectory() as directory:
            source, validation, build, output = fixture(Path(directory))
            with self.assertRaises(ValueError):
                package(source, validation, build, output, "aarch64")
            receipt = json.loads((validation / "receipt.json").read_text())
            receipt["tree"] = "wrong"
            (validation / "receipt.json").write_text(json.dumps(receipt))
            with self.assertRaises(ValueError):
                package(source, validation, build, output, "x86_64")


if __name__ == "__main__":
    unittest.main()
