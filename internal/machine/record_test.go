package machine

import (
	"testing"
	"time"
)

func TestParseSleep(t *testing.T) {
	cases := map[string]time.Duration{"": 0, "never": 0, "30m": 30 * time.Minute, "2h": 2 * time.Hour, "7d": 7 * 24 * time.Hour}
	for in, want := range cases {
		got, err := ParseSleep(in)
		if err != nil || got != want {
			t.Errorf("%q: %v %v, want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"0", "-1h", "x", "1y"} {
		if _, err := ParseSleep(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"db", "my-app", "a1", "x"} {
		if !ValidName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "-a", "a-", "A", "a.b", "a_b"} {
		if ValidName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}
