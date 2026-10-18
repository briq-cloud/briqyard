//go:build !linux

package netw

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// The host network only exists on Linux. These stubs let the rest of the daemon compile and
// its unit tests run on a developer's machine.

var errLinuxOnly = errors.New("briqyard host networking needs Linux")

func BridgeName(index int) string { return fmt.Sprintf("by%d", index) }

func TapName(machineID string) string {
	id := strings.NewReplacer("-", "", "_", "").Replace(machineID)
	if len(id) > 12 {
		id = id[:12]
	}
	return "t" + id
}

func EnsureBridge(s Subnet) (string, error)              { return "", errLinuxOnly }
func DeleteBridge(index int) error                       { return errLinuxOnly }
func EnsureTap(machineID, bridge string) (string, error) { return "", errLinuxOnly }
func DeleteTap(machineID string) error                   { return errLinuxOnly }
func EnableForwarding() error                            { return errLinuxOnly }
func DefaultEgressInterface() (string, error)            { return "", errLinuxOnly }
func HostAddr(iface string) (netip.Addr, error)          { return netip.Addr{}, errLinuxOnly }

func MACFor(ip netip.Addr) string {
	b := ip.As4()
	return fmt.Sprintf("06:%02x:%02x:%02x:%02x:%02x", 0xb1, b[0], b[1], b[2], b[3])
}
