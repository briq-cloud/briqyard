package netw

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Resolver answers the names of a tenant's machines on its gateway and forwards the rest.
// One Resolver serves every bridge: the answer depends on the address the query came in on.
type Resolver struct {
	Upstream []string
	Log      *slog.Logger

	mu sync.RWMutex
	// names: gateway address → name → address
	names   map[netip.Addr]map[string]netip.Addr
	servers []*dns.Server
}

// NewResolver makes a resolver with upstreams (default: the host's resolv.conf, then 1.1.1.1).
func NewResolver(upstream []string, log *slog.Logger) *Resolver {
	if len(upstream) == 0 {
		upstream = systemUpstreams()
	}
	for i, u := range upstream {
		if _, _, err := net.SplitHostPort(u); err != nil {
			upstream[i] = net.JoinHostPort(u, "53")
		}
	}
	return &Resolver{Upstream: upstream, Log: log, names: map[netip.Addr]map[string]netip.Addr{}}
}

func systemUpstreams() []string {
	var out []string
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				ip, err := netip.ParseAddr(f[1])
				// A local stub (systemd-resolved) is fine, a tenant subnet address is not.
				if err == nil && !ip.IsLoopback() || err == nil && ip.IsLoopback() {
					out = append(out, f[1])
				}
			}
		}
	}
	return append(out, "1.1.1.1")
}

// Set replaces the names served on a gateway.
func (r *Resolver) Set(gateway netip.Addr, names map[string]netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := make(map[string]netip.Addr, len(names))
	for k, v := range names {
		m[dns.Fqdn(strings.ToLower(k))] = v
	}
	r.names[gateway] = m
}

// Unset forgets a gateway's names.
func (r *Resolver) Unset(gateway netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.names, gateway)
}

// Listen serves DNS on the gateway address (UDP and TCP). Idempotent per address.
func (r *Resolver) Listen(gateway netip.Addr) error {
	addr := net.JoinHostPort(gateway.String(), "53")
	r.mu.Lock()
	for _, s := range r.servers {
		if s.Addr == addr {
			r.mu.Unlock()
			return nil
		}
	}
	r.mu.Unlock()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) { r.serve(gateway, w, q) })
	for _, netw := range []string{"udp", "tcp"} {
		s := &dns.Server{Addr: addr, Net: netw, Handler: handler, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
		started := make(chan error, 1)
		s.NotifyStartedFunc = func() { started <- nil }
		go func() {
			if err := s.ListenAndServe(); err != nil {
				started <- err
				r.Log.Warn("dns listener ended", "addr", addr, "net", netw, "err", err)
			}
		}()
		if err := <-started; err != nil {
			return err
		}
		r.mu.Lock()
		r.servers = append(r.servers, s)
		r.mu.Unlock()
	}
	return nil
}

// Shutdown stops every listener.
func (r *Resolver) Shutdown(ctx context.Context) {
	r.mu.Lock()
	servers := r.servers
	r.servers = nil
	r.mu.Unlock()
	for _, s := range servers {
		_ = s.ShutdownContext(ctx)
	}
}

func (r *Resolver) serve(gateway netip.Addr, w dns.ResponseWriter, q *dns.Msg) {
	if len(q.Question) == 0 {
		dns.HandleFailed(w, q)
		return
	}
	name := strings.ToLower(q.Question[0].Name)
	if strings.HasSuffix(name, ".internal.") {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Authoritative = true
		r.mu.RLock()
		ip, ok := r.names[gateway][name]
		r.mu.RUnlock()
		if !ok {
			m.Rcode = dns.RcodeNameError
		} else if q.Question[0].Qtype == dns.TypeA || q.Question[0].Qtype == dns.TypeANY {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
				A:   ip.AsSlice(),
			})
		}
		_ = w.WriteMsg(m)
		return
	}
	c := &dns.Client{Timeout: 4 * time.Second, Net: "udp"}
	for _, up := range r.Upstream {
		resp, _, err := c.ExchangeContext(context.Background(), q, up)
		if err == nil && resp != nil {
			if resp.Truncated {
				tc := &dns.Client{Timeout: 4 * time.Second, Net: "tcp"}
				if r2, _, err := tc.ExchangeContext(context.Background(), q, up); err == nil {
					resp = r2
				}
			}
			resp.Id = q.Id
			_ = w.WriteMsg(resp)
			return
		}
	}
	dns.HandleFailed(w, q)
}
