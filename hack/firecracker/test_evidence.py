"""Refuse false mutation evidence before spending time on compilation."""
import unittest

from validate import PORTABLE, negative_detected

NAME = PORTABLE[0][1]
OUTPUT = f"""running 1 test
test {NAME} ...
thread '{NAME}' panicked at src/vmm/src/device_manager/snapshot/block.rs:151:9:
assertion failed: matches!(block.prepare_snapshot_checked(), Err(BlockPrepareError::Io(_)))
FAILED
failures:
    {NAME}
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 123 filtered out
"""

class NegativeEvidence(unittest.TestCase):
    def test_expected_mutation_assertion(self):
        self.assertTrue(negative_detected(101, OUTPUT, NAME))

    def test_fixture_panic_refused(self):
        output = OUTPUT.replace("block.rs:151:9:", "block.rs:17:9:")
        self.assertFalse(negative_detected(101, output, NAME))

    def test_unrelated_assertion_refused(self):
        output = OUTPUT.replace("assertion failed: matches!(block.prepare_snapshot_checked(), Err(BlockPrepareError::Io(_)))",
                                "assertion failed: unrelated_condition")
        self.assertFalse(negative_detected(101, output, NAME))

    def test_compile_failure_refused(self):
        self.assertFalse(negative_detected(101, "error: could not compile vmm", NAME))

    def test_zero_tests_refused(self):
        self.assertFalse(negative_detected(0, "test result: ok. 0 passed; 0 failed;", NAME))

    def test_signal_and_success_refused(self):
        for code in [-9, 0, 1]:
            self.assertFalse(negative_detected(code, OUTPUT, NAME))

    def test_wrong_test_refused(self):
        self.assertFalse(negative_detected(101, OUTPUT, NAME + "_other"))
