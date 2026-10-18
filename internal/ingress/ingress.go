// Package ingress is how the outside reaches a machine: a TCP port on the host per TCP
// endpoint, and one HTTP listener that routes by host name. A connection to a sleeping
// machine's endpoint wakes it.
package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/briq-cloud/briqyard/internal/machine"
)

// Backend is what the ingress needs from the machine manager.
type Backend interface {
	// MachineAddr gives the machine's address, starting it when wake is set and it sleeps.
	MachineAddr(ctx context.Context, id string, wake bool) (string, error)
	AllEndpoints() []machine.Endpoint
	OnEndpoint(fn func(ep machine.Endpoint, added bool))
}

// Ingress runs the listeners.
type Ingress struct {
	Backend Backend
	Bind    string
	HTTP    string
	Log     *slog.Logger
	// WakeTimeout bounds how long a connection waits for a sleeping machine.
	WakeTimeout time.Duration

	mu        sync.Mutex
	listeners map[string]net.Listener // endpoint id → TCP listener
	hosts     map[string]machine.Endpoint
	httpSrv   *http.Server
}

// Start opens the listeners for every endpoint and follows additions and removals.
func (in *Ingress) Start() error {
	if in.WakeTimeout == 0 {
		in.WakeTimeout = 90 * time.Second
	}
	in.listeners = map[string]net.Listener{}
	in.hosts = map[string]machine.Endpoint{}
	for _, ep := range in.Backend.AllEndpoints() {
		if err := in.add(ep); err != nil {
			in.Log.Error("endpoint listener", "endpoint", ep.ID, "err", err)
		}
	}
	in.Backend.OnEndpoint(func(ep machine.Endpoint, added bool) {
		if added {
			if err := in.add(ep); err != nil {
				in.Log.Error("endpoint listener", "endpoint", ep.ID, "err", err)
			}
		} else {
			in.remove(ep)
		}
	})
	if in.HTTP != "" {
		in.httpSrv = &http.Server{Addr: in.HTTP, Handler: http.HandlerFunc(in.serveHTTP), ReadHeaderTimeout: 30 * time.Second}
		ln, err := net.Listen("tcp", in.HTTP)
		if err != nil {
			return fmt.Errorf("http ingress on %s: %w", in.HTTP, err)
		}
		go func() {
			if err := in.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				in.Log.Error("http ingress", "err", err)
			}
		}()
	}
	return nil
}

// Stop closes every listener.
func (in *Ingress) Stop(ctx context.Context) {
	in.mu.Lock()
	for id, l := range in.listeners {
		l.Close()
		delete(in.listeners, id)
	}
	in.mu.Unlock()
	if in.httpSrv != nil {
		_ = in.httpSrv.Shutdown(ctx)
	}
}

func (in *Ingress) add(ep machine.Endpoint) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	switch ep.Protocol {
	case "http":
		in.hosts[strings.ToLower(ep.Host)] = ep
		return nil
	case "tcp":
		if _, ok := in.listeners[ep.ID]; ok {
			return nil
		}
		addr := net.JoinHostPort(in.Bind, fmt.Sprint(ep.HostPort))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		in.listeners[ep.ID] = ln
		go in.acceptLoop(ep, ln)
		in.Log.Info("tcp endpoint listening", "endpoint", ep.ID, "machine", ep.MachineID, "addr", addr, "port", ep.Port)
		return nil
	}
	return nil
}

func (in *Ingress) remove(ep machine.Endpoint) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if l, ok := in.listeners[ep.ID]; ok {
		l.Close()
		delete(in.listeners, ep.ID)
	}
	delete(in.hosts, strings.ToLower(ep.Host))
}

func (in *Ingress) acceptLoop(ep machine.Endpoint, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go in.proxyTCP(ep, conn)
	}
}

func (in *Ingress) proxyTCP(ep machine.Endpoint, conn net.Conn) {
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), in.WakeTimeout)
	defer cancel()
	target, err := in.dial(ctx, ep)
	if err != nil {
		in.Log.Warn("tcp endpoint: cannot reach machine", "endpoint", ep.ID, "machine", ep.MachineID, "err", err)
		return
	}
	defer target.Close()
	splice(conn, target)
}

// dial connects to the machine's port, waking it and waiting for the port to listen.
func (in *Ingress) dial(ctx context.Context, ep machine.Endpoint) (net.Conn, error) {
	ip, err := in.Backend.MachineAddr(ctx, ep.MachineID, true)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(ip, fmt.Sprint(ep.Port))
	var d net.Dialer
	for {
		dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		c, err := d.DialContext(dctx, "tcp", addr)
		cancel()
		if err == nil {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s did not answer: %w", addr, err)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if t, ok := dst.(*net.TCPConn); ok {
			_ = t.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

func (in *Ingress) serveHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	in.mu.Lock()
	ep, ok := in.hosts[host]
	in.mu.Unlock()
	if !ok {
		http.Error(w, "no endpoint for "+host, http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), in.WakeTimeout)
	defer cancel()
	// Wait for the port, so a request to a sleeping machine succeeds after its wake.
	c, err := in.dial(ctx, ep)
	if err != nil {
		http.Error(w, "the machine did not answer: "+err.Error(), http.StatusBadGateway)
		return
	}
	target := c.RemoteAddr().String()
	c.Close()
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: target})
			pr.Out.Host = r.Host
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}
