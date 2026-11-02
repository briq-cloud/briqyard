"""Local upgrade releases must satisfy the actual bootstrap bundle contract."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent / "firecracker"))
from test_package import fixture

spec = importlib.util.spec_from_file_location("dev_release", Path(__file__).with_name("dev-release.py"))
dev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dev)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rewrite(bundle, member, transform):
    with tarfile.open(bundle) as archive:
        contents = [(entry.name, archive.extractfile(entry).read()) for entry in archive.getmembers()]
    with tarfile.open(bundle, "w:gz") as archive:
        for name, value in contents:
            data = transform(value) if name == member else value
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))


class DevRelease(unittest.TestCase):
    def test_stages_complete_release_and_manifest_without_changing_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, _, binaries, bundle = fixture(root)
            for name in dev.BINARIES:
                (binaries / name).write_bytes(name.encode())
            output = root / "release"
            dev.stage_release(bundle, digest(bundle), "x86_64", binaries, output)
            expected = {f"{name}-linux-x86_64" for name in dev.BINARIES} | {bundle.name}
            self.assertEqual({p.name for p in output.iterdir()}, expected | {"SHA256SUMS-x86_64"})
            self.assertEqual((output / bundle.name).read_bytes(), bundle.read_bytes())
            self.assertEqual(set((output / "SHA256SUMS-x86_64").read_text().splitlines()),
                             {digest(output / name) + "  " + name for name in expected})
            dev.verify_bundle(output / bundle.name, digest(bundle), "x86_64")

    def test_missing_local_binary_preserves_previous_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, _, binaries, bundle = fixture(root)
            output = root / "release"
            output.mkdir()
            sentinel = output / "SHA256SUMS-x86_64"
            sentinel.write_text("previous release\n")
            with self.assertRaises(FileNotFoundError):
                dev.stage_release(bundle, digest(bundle), "x86_64", binaries, output)
            self.assertEqual(list(output.iterdir()), [sentinel])
            self.assertEqual(sentinel.read_text(), "previous release\n")

    def test_refuses_digest_arch_pin_validation_or_payload_mismatch_before_staging(self):
        for fault in ("digest", "arch", "pin", "receipt", "payload", "missing"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, _, binaries, bundle = fixture(root)
                trusted = digest(bundle)
                arch = "x86_64"
                if fault == "digest":
                    trusted = "0" * 64
                elif fault == "arch":
                    arch = "aarch64"
                elif fault in ("pin", "receipt"):
                    member = "pin.json" if fault == "pin" else "receipt.json"
                    rewrite(bundle, member, lambda b: json.dumps(json.loads(b) | {"tree": "wrong"}).encode())
                    trusted = digest(bundle)
                elif fault == "payload":
                    rewrite(bundle, "firecracker", lambda _: b"changed")
                    trusted = digest(bundle)
                else:
                    bundle.unlink()
                output = root / "release"
                output.mkdir()
                sentinel = output / "SHA256SUMS-x86_64"
                sentinel.write_text("previous release\n")
                with self.assertRaises(ValueError):
                    dev.stage_release(bundle, trusted, arch, binaries, output)
                self.assertEqual(list(output.iterdir()), [sentinel])
                self.assertEqual(sentinel.read_text(), "previous release\n")


if __name__ == "__main__":
    unittest.main()
