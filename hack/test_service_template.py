"""Offline tests of the pure parts of service_template.py qualify: verdicts, ok and exit status, MAC rule, clock bound, probe parsing."""
import os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import service_template as st


def probe(**kw):
    p = {'dmesg_ok': '1', 'vmgenid_dev': 'VMGENCTR:00 ', 'fork_msgs': '1', 'config': 'CONFIG_VMGENID=y;'}
    p.update(kw)
    return p


class Qualify(unittest.TestCase):
    def test_mac_follows_the_address(self):
        self.assertEqual(st.expected_mac('10.66.1.2/24'), '06:b1:0a:42:01:02')
        self.assertEqual(st.expected_mac('10.64.0.255'), '06:b1:0a:40:00:ff')

    def test_clock_skew_is_a_lower_bound(self):
        skew, est, precise = st.clock_skew('100.5', 100.0, 101.0)
        self.assertEqual((skew, precise), (0.0, True))
        self.assertAlmostEqual(est, 0.0)
        self.assertAlmostEqual(st.clock_skew('160.2', 100.0, 100.4)[0], 59.8)
        self.assertAlmostEqual(st.clock_skew('40.25', 100.0, 100.4)[0], 59.75)
        skew, _, precise = st.clock_skew('100', 100.2, 100.6)  # whole seconds: a second wide
        self.assertEqual((skew, precise), (0.0, False))
        self.assertEqual(st.clock_skew('100.%N', 100.2, 100.6)[::2], (0.0, False))
        self.assertIsNone(st.clock_skew('', 1, 2)[0])
        self.assertAlmostEqual(st.clock_skew('100', 99.0, 99.5)[0], 0.5)

    def test_verdict(self):
        self.assertEqual(st.verdict(['pass', 'pass']), 'pass')
        self.assertEqual(st.verdict(['pass', 'fail']), 'fail')
        self.assertEqual(st.verdict(['unsupported', 'unsupported']), 'unsupported')
        self.assertEqual(st.verdict(['pass', 'unsupported']), 'unsupported')
        self.assertEqual(st.verdict(['fail', 'unsupported']), 'fail')
        self.assertEqual(st.verdict([]), 'fail')

    def test_vmgenid(self):
        s, why, _ = st.vmgenid_status(probe())
        self.assertEqual(s, 'pass', why)
        self.assertEqual(st.vmgenid_status(probe(fork_msgs='0'))[0], 'fail')
        # a message that was already in the log before the seal is not evidence of the restore
        self.assertEqual(st.vmgenid_status(probe(fork_msgs='1', pre_fork='1'))[0], 'fail')
        self.assertEqual(st.vmgenid_status(probe(fork_msgs='2', pre_fork='1'))[0], 'pass')
        s, why, _ = st.vmgenid_status(probe(fork_msgs='0'))
        self.assertIn('no vmfork reseed logged', why)
        self.assertIn('possible causes', why)
        self.assertIn('CRNG was not ready', why)
        self.assertEqual(st.vmgenid_status(probe(vmgenid_dev=''))[0], 'fail')
        self.assertEqual(st.vmgenid_status(probe(dmesg_ok='0'))[0], 'fail')
        s, why, _ = st.vmgenid_status(probe(config='# CONFIG_VMGENID is not set;', vmgenid_dev='', fork_msgs='0'))
        self.assertEqual(s, 'unsupported')
        self.assertIn('# CONFIG_VMGENID is not set', why)

    def test_ok_needs_every_check_to_pass(self):
        allp = {n: 'pass' for n in st.CHECKS}
        self.assertEqual(st.evaluate(allp, {}, False), {'ok': True, 'failed': [], 'unsupported': []})
        r = st.evaluate({**allp, 'clock': 'fail'}, {}, True)
        self.assertEqual((r['ok'], r['failed']), (False, ['clock']))
        r = st.evaluate({**allp, 'vmgenid': 'unsupported'}, {}, False)
        self.assertEqual((r['ok'], r['failed'], r['unsupported']), (False, [], ['vmgenid']))
        self.assertTrue(st.evaluate({**allp, 'vmgenid': 'unsupported'}, {}, True)['ok'])
        self.assertFalse(st.evaluate({**allp, 'rng': 'unsupported'}, {}, False)['ok'])  # --clones 1
        r = st.evaluate(allp, {'2': 'TimeoutError'}, True)
        self.assertEqual((r['ok'], r['failed']), (False, ['clones']))
        self.assertFalse(st.evaluate({}, {}, True)['ok'])  # a check that never ran is a fail

    def test_exit_status(self):
        self.assertEqual(st.exit_status({'ok': True}), 0)
        self.assertEqual(st.exit_status({'ok': False, 'failed': ['mac']}), 1)
        self.assertEqual(st.exit_status({'error': 'boom'}), 1)
        self.assertEqual(st.exit_status(st.evaluate({**{n: 'pass' for n in st.CHECKS}, 'mac': 'fail'}, {}, False)), 1)

    def test_parse_probe_multi_line_with_equals(self):
        out = st.parse_probe('now=1700000000.5\ncmdline=console=ttyS0 root=/dev/vda ro quiet=1\nconfig=CONFIG_VMGENID=y;# CONFIG_X is not set;\nnoise line\ndraw=ab\n')
        self.assertEqual(out['cmdline'], 'console=ttyS0 root=/dev/vda ro quiet=1')
        self.assertEqual(out['config'], 'CONFIG_VMGENID=y;# CONFIG_X is not set;')
        self.assertEqual((out['now'], out['draw']), ('1700000000.5', 'ab'))
        self.assertNotIn('noise line', out)

    def test_pick_config_precedence(self):
        self.assertEqual(st.pick_config('CONFIG_VMGENID=y;', 'CONFIG_VMGENID'), ('CONFIG_VMGENID=y', 'guest /proc/config.gz'))
        # the guest's own line wins over the repo's, even when it says the option is off
        self.assertEqual(st.pick_config('# CONFIG_VMGENID is not set;', 'CONFIG_VMGENID'), ('# CONFIG_VMGENID is not set', 'guest /proc/config.gz'))
        # no guest line: the repo's copy of the pinned kernel config
        self.assertEqual(st.pick_config('CONFIG_OTHER=y;', 'CONFIG_VMGENID'), ('CONFIG_VMGENID=y', 'hack/kernel/base-x86_64.config'))
        self.assertEqual(st.pick_config('', 'CONFIG_NOT_IN_ANY_CONFIG_AT_ALL')[0], '')

    def test_neighbour_entry(self):
        self.assertEqual(st.parse_neigh('10.66.1.2 dev br0 lladdr 06:B1:0A:42:01:02 REACHABLE\n'), '06:b1:0a:42:01:02')
        self.assertIsNone(st.parse_neigh('10.66.1.2 dev br0  FAILED\n'))
        self.assertIsNone(st.parse_neigh('10.66.1.2 dev br0 lladdr 06:b1:0a:42:01:02 FAILED\n'))
        self.assertIsNone(st.parse_neigh(''))

    def test_nested_and_local_detection(self):
        self.assertTrue(st.detect_nested('processor\t: 0\nflags\t\t: fpu vme hypervisor lm\n', None))
        self.assertFalse(st.detect_nested('processor\t: 0\nflags\t\t: fpu vme lm\n', ''))
        self.assertTrue(st.detect_nested('flags : fpu\n', 'xen\n'))
        self.assertIsNone(st.detect_nested(None, None))
        self.assertTrue(st.is_local_host('127.0.0.1'))
        self.assertTrue(st.is_local_host('localhost'))
        self.assertFalse(st.is_local_host('192.0.2.7', can_bind=lambda a: False))
        self.assertTrue(st.is_local_host('192.0.2.7', can_bind=lambda a: True))

    def test_vmclock_across_clones(self):
        present = {'vmclock_node': 'vmclock0 '}
        self.assertEqual(st.vmclock_summary([present, present])['status'], 'present')
        s = st.vmclock_summary([{}, present])  # the first clone alone would say absent
        self.assertEqual((s['status'], s['per_clone']), ('mixed', ['absent', 'present']))
        self.assertEqual(st.vmclock_summary([])['status'], 'unknown')

    def test_config_lines(self):
        text = '# CONFIG_A is not set\nCONFIG_B=y\nCONFIG_BB=y\n'
        self.assertEqual(st.config_line(text, 'CONFIG_A'), '# CONFIG_A is not set')
        self.assertEqual(st.config_line(text, 'CONFIG_B'), 'CONFIG_B=y')
        self.assertEqual(st.config_line(text, 'CONFIG_C'), '')

    def test_pinned_kernel_config_has_the_devices(self):
        self.assertEqual(st.repo_config('CONFIG_VMGENID')[0], 'CONFIG_VMGENID=y')
        self.assertEqual(st.repo_config('CONFIG_PTP_1588_CLOCK_VMCLOCK')[0], 'CONFIG_PTP_1588_CLOCK_VMCLOCK=y')

    def test_vmclock_info(self):
        self.assertEqual(st.vmclock_info({'vmclock_node': 'vmclock0 '})['status'], 'present')
        self.assertEqual(st.vmclock_info({'config': '# CONFIG_PTP_1588_CLOCK_VMCLOCK is not set;'})['status'], 'unsupported')
        self.assertEqual(st.vmclock_info({})['status'], 'absent')


if __name__ == '__main__':
    unittest.main()
