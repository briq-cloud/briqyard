"""Offline tests of the pure parts of service_template.py qualify: verdicts, MAC rule, clock bound."""
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
        self.assertEqual(st.verdict(['pass', 'unsupported']), 'pass')
        self.assertEqual(st.verdict([]), 'fail')

    def test_vmgenid(self):
        s, why, _ = st.vmgenid_status(probe())
        self.assertEqual(s, 'pass', why)
        self.assertEqual(st.vmgenid_status(probe(fork_msgs='0'))[0], 'fail')
        self.assertEqual(st.vmgenid_status(probe(vmgenid_dev=''))[0], 'fail')
        self.assertEqual(st.vmgenid_status(probe(dmesg_ok='0'))[0], 'fail')
        s, why, _ = st.vmgenid_status(probe(config='# CONFIG_VMGENID is not set;', vmgenid_dev='', fork_msgs='0'))
        self.assertEqual(s, 'unsupported')
        self.assertIn('# CONFIG_VMGENID is not set', why)

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
