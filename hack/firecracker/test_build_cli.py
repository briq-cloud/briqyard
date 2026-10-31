import json
from pathlib import Path
import tempfile
import unittest

from build_cli import check_static, production_outputs


class ProductionEvidence(unittest.TestCase):
    def messages(self, root, out=None):
        return [
            {"reason": "build-script-executed", "package_id": "firecracker-id",
             "out_dir": str(out or root / "build/firecracker-current/out")},
            *[{"reason": "compiler-artifact", "package_id": name + "-id",
               "target": {"name": name, "kind": ["bin"]}, "profile": {"test": False},
               "executable": str(root / name)} for name in ("firecracker", "jailer")],
        ]

    def parse(self, messages, root):
        return production_outputs("\n".join(json.dumps(m) for m in messages), root)

    def test_seccomp_uses_current_package_event_not_other_build_scripts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "aarch64-unknown-linux-musl/release"
            messages = self.messages(root)
            messages.insert(0, {"reason": "build-script-executed", "package_id": "other-id",
                                "out_dir": "/old/build/out"})
            binaries, policy = self.parse(messages, root)
            self.assertEqual(set(binaries), {"firecracker", "jailer"})
            self.assertEqual(policy, (root / "build/firecracker-current/out/seccomp_filter.bpf").resolve())
            for invalid in (messages[:-1], messages + [dict(messages[1], out_dir=str(root / "build/firecracker-other/out"))],
                            self.messages(root, Path("/wrong/out"))):
                with self.assertRaises(RuntimeError):
                    self.parse(invalid, root)
            messages[-1]["executable"] = "/wrong/jailer"
            with self.assertRaises(RuntimeError):
                self.parse(messages, root)

    def test_empty_policy_warnings_are_terminal_even_in_json_diagnostics(self):
        for warning in ("Using empty default seccomp policy", "No default seccomp policy for target"):
            with self.assertRaisesRegex(RuntimeError, "empty seccomp"):
                production_outputs(json.dumps({"reason": "compiler-message", "message": warning}), Path("/release"))

    def test_static_elf_requires_architecture_and_no_loader_or_libraries(self):
        header = "Class: ELF64\nMachine: AArch64\n"
        check_static(header, "LOAD", "There is no dynamic section", "aarch64")
        for args in ((header, "INTERP", "", "aarch64"),
                     (header, "LOAD", "(NEEDED) libc.so", "aarch64"),
                     (header, "LOAD", "", "x86_64")):
            with self.assertRaises(RuntimeError):
                check_static(*args)


if __name__ == "__main__":
    unittest.main()
