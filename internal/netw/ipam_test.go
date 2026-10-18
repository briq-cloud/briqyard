package netw

import (
	"net/netip"
	"testing"
)

func TestSubnetAt(t *testing.T) {
	rng := netip.MustParsePrefix("10.64.0.0/10")
	s, err := SubnetAt(rng, 0)
	if err != nil || s.Prefix.String() != "10.64.0.0/24" || s.Gateway().String() != "10.64.0.1" {
		t.Fatalf("subnet 0: %v %v", s, err)
	}
	s, err = SubnetAt(rng, 257)
	if err != nil || s.Prefix.String() != "10.65.1.0/24" {
		t.Fatalf("subnet 257: %v %v", s, err)
	}
	h, _ := s.Host(2)
	if h.String() != "10.65.1.2" {
		t.Fatalf("host 2: %s", h)
	}
	if _, err := SubnetAt(rng, 1<<14); err == nil {
		t.Fatal("index past the range should fail")
	}
	if _, err := s.Host(255); err == nil {
		t.Fatal("broadcast is not a host")
	}
}

func TestFirstFree(t *testing.T) {
	cases := []struct {
		used   []int
		lo, hi int
		want   int
		full   bool
	}{
		{nil, 2, 254, 2, false},
		{[]int{2, 3, 4}, 2, 254, 5, false},
		{[]int{3, 2, 5}, 2, 254, 4, false},
		{[]int{2, 3}, 2, 3, 0, true},
		{[]int{1, 7}, 2, 254, 2, false},
	}
	for _, c := range cases {
		got, err := FirstFree(c.used, c.lo, c.hi)
		if c.full {
			if err == nil {
				t.Errorf("%v: expected full, got %d", c.used, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%v: got %d %v, want %d", c.used, got, err, c.want)
		}
	}
}
