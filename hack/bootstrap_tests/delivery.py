"""The generated script runs without the source tree, as a file or on SSH stdin."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HACK = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("assemble_bootstrap", HACK / "assemble-bootstrap.py")
assembler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assembler)


class BootstrapDelivery(unittest.TestCase):
    def test_checked_in_script_is_the_exact_assembly(self):
        self.assertEqual(assembler.assemble(), (HACK / "bootstrap-host.sh").read_bytes())
        subprocess.run(["python3", str(HACK / "assemble-bootstrap.py"), "--check"], check=True)

    def test_file_and_stdin_delivery_need_no_adjacent_files(self):
        script = assembler.assemble()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "bootstrap-host.sh"
            path.write_bytes(script)
            for args, stdin in ((["bash", str(path)], None), (["bash", "-s"], script)):
                with self.subTest(args=args):
                    result = subprocess.run(args, input=stdin, cwd=root,
                                            env={"PATH": os.defpath, "BRIQYARD_RUNTIME_CLASSES": "bogus"},
                                            capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, b"BRIQYARD_RUNTIME_CLASSES: bogus is not a class the release builds (nested)\n")
                    self.assertEqual(result.stderr, b"")
