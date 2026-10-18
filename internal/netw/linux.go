//go:build linux

package netw

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// BridgeName is the bridge of tenant subnet index n: "by" + index, short enough for IFNAMSIZ.
func BridgeName(index int) string { return fmt.Sprintf("by%d", index) }

// TapName is the TAP of a machine: "t" + the first 12 characters of its id.
func TapName(machineID string) string {
	id := strings.NewReplacer("-", "", "_", "").Replace(machineID)
	if len(id) > 12 {
		id = id[:12]
	}
	return "t" + id
}

// EnsureBridge makes the tenant's bridge with the gateway address, up, and returns its name.
func EnsureBridge(s Subnet) (string, error) {
	name := BridgeName(s.Index)
	link, err := netlink.LinkByName(name)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: 1500}}
		if err := netlink.LinkAdd(br); err != nil {
			return "", fmt.Errorf("add bridge %s: %w", name, err)
		}
		link, err = netlink.LinkByName(name)
	}
	if err != nil {
		return "", fmt.Errorf("bridge %s: %w", name, err)
	}
	gw := netlink.Addr{IPNet: &net.IPNet{IP: s.Gateway().AsSlice(), Mask: net.CIDRMask(s.Prefix.Bits(), 32)}}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	have := false
	for _, a := range addrs {
		if a.IP.Equal(gw.IP) {
			have = true
		}
	}
	if !have {
		if err := netlink.AddrAdd(link, &gw); err != nil {
			return "", fmt.Errorf("address %s on %s: %w", gw.IPNet, name, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return "", fmt.Errorf("up %s: %w", name, err)
	}
	return name, nil
}

// DeleteBridge removes the tenant's bridge. Missing is success.
func DeleteBridge(index int) error {
	link, err := netlink.LinkByName(BridgeName(index))
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return nil
	}
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

// EnsureTap makes the machine's TAP, attached to the bridge and up. Firecracker opens it by name.
func EnsureTap(machineID, bridge string) (string, error) {
	name := TapName(machineID)
	link, err := netlink.LinkByName(name)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		tap := &netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: name, MTU: 1500},
			Mode:      netlink.TUNTAP_MODE_TAP,
			Flags:     netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_VNET_HDR,
		}
		if err := netlink.LinkAdd(tap); err != nil {
			return "", fmt.Errorf("add tap %s: %w", name, err)
		}
		link, err = netlink.LinkByName(name)
	}
	if err != nil {
		return "", fmt.Errorf("tap %s: %w", name, err)
	}
	br, err := netlink.LinkByName(bridge)
	if err != nil {
		return "", fmt.Errorf("bridge %s: %w", bridge, err)
	}
	if err := netlink.LinkSetMaster(link, br); err != nil {
		return "", fmt.Errorf("attach %s to %s: %w", name, bridge, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return "", fmt.Errorf("up %s: %w", name, err)
	}
	return name, nil
}

// DeleteTap removes the machine's TAP. Missing is success.
func DeleteTap(machineID string) error {
	link, err := netlink.LinkByName(TapName(machineID))
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return nil
	}
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

// EnableForwarding turns on IPv4 forwarding on the host.
func EnableForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
}

// DefaultEgressInterface is the interface of the host's default route.
func DefaultEgressInterface() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, r := range routes {
		if r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero) {
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				return "", err
			}
			return link.Attrs().Name, nil
		}
	}
	return "", errors.New("no default route")
}

// HostAddr returns a host address on the egress interface, for endpoints' addresses.
func HostAddr(iface string) (netip.Addr, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP.To4()); ok {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no IPv4 address on %s", iface)
}

// MACFor gives a machine a stable, locally administered MAC from its address.
func MACFor(ip netip.Addr) string {
	b := ip.As4()
	return fmt.Sprintf("06:%02x:%02x:%02x:%02x:%02x", 0xb1, b[0], b[1], b[2], b[3])
}

var _ = unix.AF_INET
