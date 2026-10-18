// Package netw is the host network: a bridge per tenant, a TAP per machine, addresses, nftables
// and the gateway's DNS.
package netw

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
)

// Subnet is a tenant's /24: index n in the range gives 10.64.n.0/24 when the range is 10.64.0.0/10.
type Subnet struct {
	Index  int
	Prefix netip.Prefix
}

// Gateway is the host's address on the subnet: .1.
func (s Subnet) Gateway() netip.Addr { return s.Prefix.Addr().Next() }

// Host returns the address of host number n (2..254).
func (s Subnet) Host(n int) (netip.Addr, error) {
	if n < 2 || n > 254 {
		return netip.Addr{}, fmt.Errorf("host number %d out of range 2..254", n)
	}
	b := s.Prefix.Addr().As4()
	b[3] = byte(n)
	return netip.AddrFrom4(b), nil
}

// SubnetAt gives subnet number index inside the range, as a /24.
func SubnetAt(rng netip.Prefix, index int) (Subnet, error) {
	if !rng.Addr().Is4() || rng.Bits() > 24 {
		return Subnet{}, fmt.Errorf("network range %s must be an IPv4 prefix of at most /24", rng)
	}
	count := 1 << (24 - rng.Bits())
	if index < 0 || index >= count {
		return Subnet{}, fmt.Errorf("subnet index %d out of range: %s holds %d /24s", index, rng, count)
	}
	base := rng.Masked().Addr().As4()
	n := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	n += uint32(index) << 8
	addr := netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	return Subnet{Index: index, Prefix: netip.PrefixFrom(addr, 24)}, nil
}

// ErrFull means no address or subnet is left.
var ErrFull = errors.New("no address left")

// FirstFree returns the smallest integer in [lo, hi] not in used.
func FirstFree(used []int, lo, hi int) (int, error) {
	sort.Ints(used)
	n := lo
	for _, u := range used {
		if u < n {
			continue
		}
		if u > n {
			break
		}
		n++
	}
	if n > hi {
		return 0, ErrFull
	}
	return n, nil
}

// MaskString gives "255.255.255.0" for a /24, what guests and nft want in places.
func MaskString(p netip.Prefix) string {
	m := net.CIDRMask(p.Bits(), 32)
	return net.IP(m).String()
}
