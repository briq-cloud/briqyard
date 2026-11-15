"""Run all standalone bootstrap suites through the existing CI entry point."""
import unittest

from bootstrap_tests.delivery import BootstrapDelivery
from bootstrap_tests.host import DroppedNestedClass, InstallerLock, PoolKeyRetry, UnknownClass
from bootstrap_tests.runtime import AssignmentCompatibility, BootstrapRelease
from bootstrap_tests.wireguard import WireguardPeers, WireguardRun


if __name__ == "__main__":
    unittest.main()
