package machine

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/briq-cloud/briqyard/internal/api"
	"github.com/briq-cloud/briqyard/internal/guest"
	"github.com/briq-cloud/briqyard/internal/netw"
)

// writeConfigDrive renders the tar the init reads at boot.
func (m *Manager) writeConfigDrive(path string, r *Record, t *Tenant) error {
	s := m.subnet(t)
	cfg := guest.Config{
		Hostname:       r.Name,
		IP:             r.IP + "/24",
		Gateway:        s.Gateway().String(),
		DNS:            []string{s.Gateway().String()},
		Hosts:          map[string]string{r.Hostname(): r.IP, r.MachineHost(): r.IP},
		Entrypoint:     r.ImageConfig.Entrypoint,
		Cmd:            r.ImageConfig.Cmd,
		Env:            map[string]string{},
		WorkDir:        r.ImageConfig.WorkDir,
		User:           r.ImageConfig.User,
		StopTimeoutSec: 10,
	}
	for k, v := range r.ImageConfig.Env {
		cfg.Env[k] = v
	}
	for k, v := range r.Env {
		cfg.Env[k] = v
	}
	// Docker semantics: an entrypoint given replaces the image's and drops its cmd.
	if r.Entrypoint != nil {
		cfg.Entrypoint = r.Entrypoint
		cfg.Cmd = nil
	}
	if r.Cmd != nil {
		cfg.Cmd = r.Cmd
	}
	if r.Volume != nil {
		cfg.Mounts = []guest.Mount{{Device: "/dev/vdc", Path: r.Volume.Mount, FSType: "ext4"}}
	}
	type file struct {
		path string
		mode uint32
		data []byte
	}
	var files []file
	for _, f := range r.Files {
		data, err := base64.StdEncoding.DecodeString(f.Base64)
		if err != nil {
			return fmt.Errorf("file %s: %w", f.Path, err)
		}
		mode := uint32(0o644)
		if f.Mode != "" {
			n, err := strconv.ParseUint(f.Mode, 8, 32)
			if err != nil {
				return fmt.Errorf("file %s: mode %q", f.Path, f.Mode)
			}
			mode = uint32(n)
		}
		files = append(files, file{f.Path, mode, data})
		cfg.Files = append(cfg.Files, guest.FileMeta{Path: f.Path, Mode: mode})
	}
	tmp := path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(out)
	cfgJSON, err := jsonMarshal(cfg)
	if err != nil {
		return err
	}
	now := time.Now()
	if err := tw.WriteHeader(&tar.Header{Name: guest.ConfigName, Mode: 0o600, Size: int64(len(cfgJSON)), ModTime: now}); err != nil {
		return err
	}
	if _, err := tw.Write(cfgJSON); err != nil {
		return err
	}
	for _, f := range files {
		name := guest.FilesPrefix + strings.TrimPrefix(f.path, "/")
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: int64(f.mode), Size: int64(len(f.data)), ModTime: now}); err != nil {
			return err
		}
		if _, err := tw.Write(f.data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	// Firecracker wants the drive's size to be a multiple of 512 bytes.
	if fi, err := out.Stat(); err == nil {
		if pad := (512 - fi.Size()%512) % 512; pad > 0 {
			if _, err := out.Write(make([]byte, pad)); err != nil {
				return err
			}
		}
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// --- exec and files ---

// Exec runs a command in a running machine; with wake, a sleeping one is started first.
func (m *Manager) Exec(ctx context.Context, id string, req api.ExecRequest) (api.ExecResult, error) {
	sock, err := m.running(ctx, id, req.Wake)
	if err != nil {
		return api.ExecResult{}, err
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ectx, cancel := context.WithTimeout(ctx, timeout+10*time.Second)
	defer cancel()
	out, err := guest.Exec(ectx, sock, guest.Request{Cmd: req.Cmd, Env: req.Env, Cwd: req.Cwd, Stdin: []byte(req.Stdin), TimeoutMs: int(timeout / time.Millisecond)})
	if err != nil {
		if errors.Is(err, guest.ErrClosed) {
			return api.ExecResult{}, fmt.Errorf("%w: the machine went down during the command", ErrNotRunning)
		}
		return api.ExecResult{}, err
	}
	_ = m.Touch(id)
	return api.ExecResult{Stdout: string(out.Stdout), Stderr: string(out.Stderr), ExitCode: out.Code, TimedOut: out.TimedOut}, nil
}

// PutFile writes a file in a running machine.
func (m *Manager) PutFile(ctx context.Context, id string, req api.PutFileRequest) error {
	sock, err := m.running(ctx, id, false)
	if err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(req.Base64)
	if err != nil {
		return Invalid("base64: %v", err)
	}
	mode := uint32(0o644)
	if req.Mode != "" {
		n, err := strconv.ParseUint(req.Mode, 8, 32)
		if err != nil {
			return Invalid("mode %q", req.Mode)
		}
		mode = uint32(n)
	}
	pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := guest.Put(pctx, sock, req.Path, mode, data); err != nil {
		return err
	}
	_ = m.Touch(id)
	return nil
}

// GetFile reads a file from a running machine.
func (m *Manager) GetFile(ctx context.Context, id, path string) ([]byte, error) {
	sock, err := m.running(ctx, id, false)
	if err != nil {
		return nil, err
	}
	gctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	data, err := guest.Get(gctx, sock, path)
	if err != nil {
		return nil, err
	}
	_ = m.Touch(id)
	return data, nil
}

// running returns the vsock path of a running machine, waking it when asked.
func (m *Manager) running(ctx context.Context, id string, wake bool) (string, error) {
	e, err := m.entry(id)
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	if e.rec.State != api.StateRunning {
		if !wake {
			st := e.rec.State
			if e.rec.StoppedReason != "" {
				st += " (" + e.rec.StoppedReason + ")"
			}
			e.mu.Unlock()
			return "", fmt.Errorf("%w: %s", ErrNotRunning, st)
		}
		e.mu.Unlock()
		if _, err := m.Wake(ctx, id); err != nil {
			return "", err
		}
		e.mu.Lock()
	}
	proc := e.proc
	e.mu.Unlock()
	if proc == nil {
		return "", ErrNotRunning
	}
	return proc.VsockSock, nil
}

// --- logs ---

// Logs pages the machine's console. since is the byte offset to continue from ("" is the
// start); limit caps lines (default 500).
func (m *Manager) Logs(id, since string, limit int) (api.LogsResponse, error) {
	if _, err := m.entry(id); err != nil {
		return api.LogsResponse{}, err
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	console := filepath.Join(m.cfg.RunDir(), id, "console.log")
	f, err := os.Open(console)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return api.LogsResponse{}, nil
		}
		return api.LogsResponse{}, err
	}
	defer f.Close()
	offset := int64(0)
	if since != "" {
		if offset, err = strconv.ParseInt(since, 10, 64); err != nil {
			return api.LogsResponse{}, Invalid("since must be a cursor from a previous page")
		}
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return api.LogsResponse{}, err
	}
	br := bufio.NewReaderSize(f, 64<<10)
	var resp api.LogsResponse
	pos := offset
	for len(resp.Lines) < limit {
		line, err := br.ReadString('\n')
		if len(line) > 0 && strings.HasSuffix(line, "\n") {
			pos += int64(len(line))
			resp.Lines = append(resp.Lines, parseLogLine(line))
		}
		if err != nil {
			break
		}
	}
	if len(resp.Lines) == limit {
		resp.Next = strconv.FormatInt(pos, 10)
	} else if pos > offset || len(resp.Lines) == 0 {
		resp.Next = strconv.FormatInt(pos, 10)
	}
	return resp, nil
}

func parseLogLine(line string) api.LogLine {
	line = strings.TrimRight(line, "\r\n")
	ts, rest, ok := strings.Cut(line, " ")
	if ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			return api.LogLine{TS: t, Line: rest}
		}
	}
	return api.LogLine{Line: line}
}

// --- snapshots ---

// Snapshot takes a snapshot of both disks, named by the id returned.
func (m *Manager) Snapshot(ctx context.Context, id string) (api.Snapshot, error) {
	e, err := m.entry(id)
	if err != nil {
		return api.Snapshot{}, err
	}
	snap := NewID("s")
	if err := m.disks.Snapshot(ctx, e.rec.RootDataset(), snap); err != nil {
		return api.Snapshot{}, err
	}
	if e.rec.Volume != nil {
		if err := m.disks.Snapshot(ctx, e.rec.DataDataset(), snap); err != nil {
			return api.Snapshot{}, err
		}
	}
	return api.Snapshot{ID: snap, MachineID: id, CreatedAt: time.Now().UTC()}, nil
}

// Snapshots lists a machine's snapshots.
func (m *Manager) Snapshots(ctx context.Context, id string) ([]api.Snapshot, error) {
	e, err := m.entry(id)
	if err != nil {
		return nil, err
	}
	names, err := m.disks.Snapshots(ctx, e.rec.RootDataset())
	if err != nil {
		return nil, err
	}
	out := make([]api.Snapshot, 0, len(names))
	for _, n := range names {
		if strings.HasPrefix(n, "s_") {
			out = append(out, api.Snapshot{ID: n, MachineID: id})
		}
	}
	return out, nil
}

// --- endpoints ---

// OnEndpoint registers the ingress's hook for endpoints added and removed.
func (m *Manager) OnEndpoint(fn func(ep Endpoint, added bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onEndpoint = fn
}

// AllEndpoints lists every endpoint.
func (m *Manager) AllEndpoints() []Endpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Endpoint, 0, len(m.endpoints))
	for _, e := range m.endpoints {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (m *Manager) endpointsOf(machineID string) []api.Endpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []api.Endpoint
	for _, e := range m.endpoints {
		if e.MachineID == machineID {
			out = append(out, m.endpointView(e))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (m *Manager) endpointView(e *Endpoint) api.Endpoint {
	v := api.Endpoint{ID: e.ID, MachineID: e.MachineID, Port: e.Port, Protocol: e.Protocol, HostPort: e.HostPort, Host: e.Host, CreatedAt: e.CreatedAt}
	switch e.Protocol {
	case "http":
		v.Address = "http://" + e.Host
	default:
		addr := m.cfg.Ingress.Bind
		if addr == "" || addr == "0.0.0.0" {
			if ip, err := netw.HostAddr(m.egress); err == nil {
				addr = ip.String()
			}
		}
		v.Address = fmt.Sprintf("%s:%d", addr, e.HostPort)
	}
	return v
}

// EndpointView is the API view of an endpoint.
func (m *Manager) EndpointView(e Endpoint) api.Endpoint { return m.endpointView(&e) }

// CreateEndpoint opens a port of a machine to the outside.
func (m *Manager) CreateEndpoint(machineID string, req api.CreateEndpointRequest) (api.Endpoint, error) {
	e, err := m.entry(machineID)
	if err != nil {
		return api.Endpoint{}, err
	}
	if req.Port < 1 || req.Port > 65535 {
		return api.Endpoint{}, Invalid("port must be 1..65535")
	}
	proto := req.Protocol
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "http" {
		return api.Endpoint{}, Invalid("protocol must be tcp or http")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.endpoints {
		if ex.MachineID == machineID && ex.Port == req.Port && ex.Protocol == proto {
			return m.endpointView(ex), nil
		}
	}
	ep := &Endpoint{ID: NewID("ep"), MachineID: machineID, Tenant: e.rec.Tenant, Port: req.Port, Protocol: proto, CreatedAt: time.Now().UTC()}
	switch proto {
	case "tcp":
		lo, hi, err := portRange(m.cfg.Ingress.TCPPorts)
		if err != nil {
			return api.Endpoint{}, err
		}
		var used []int
		for _, ex := range m.endpoints {
			if ex.Protocol == "tcp" {
				used = append(used, ex.HostPort)
			}
		}
		port, err := netw.FirstFree(used, lo, hi)
		if err != nil {
			return api.Endpoint{}, fmt.Errorf("tcp endpoints: %w", err)
		}
		ep.HostPort = port
	case "http":
		if m.cfg.Ingress.HTTP == "" {
			return api.Endpoint{}, Invalid("http endpoints are not enabled on this host (ingress.http)")
		}
		label := req.Host
		if label == "" {
			label = e.rec.Name + "-" + NewID("")[1:5]
		}
		if !ValidName(label) {
			return api.Endpoint{}, Invalid("host must be a DNS label")
		}
		ep.Host = label + "." + m.cfg.Ingress.Domain
		for _, ex := range m.endpoints {
			if ex.Host == ep.Host {
				return api.Endpoint{}, Invalid("host %s is taken", ep.Host)
			}
		}
	}
	if err := m.store.PutEndpoint(ep.ID, ep); err != nil {
		return api.Endpoint{}, err
	}
	m.endpoints[ep.ID] = ep
	if m.onEndpoint != nil {
		m.onEndpoint(*ep, true)
	}
	return m.endpointView(ep), nil
}

// DeleteEndpoint removes an endpoint. Missing is success.
func (m *Manager) DeleteEndpoint(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ep, ok := m.endpoints[id]
	if !ok {
		return nil
	}
	if err := m.store.DeleteEndpoint(id); err != nil {
		return err
	}
	delete(m.endpoints, id)
	if m.onEndpoint != nil {
		m.onEndpoint(*ep, false)
	}
	return nil
}

// Endpoint returns one endpoint.
func (m *Manager) Endpoint(id string) (Endpoint, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ep, ok := m.endpoints[id]
	if !ok {
		return Endpoint{}, false
	}
	return *ep, true
}

func portRange(s string) (int, int, error) {
	lo, hi, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, fmt.Errorf("ingress.tcp_ports %q: want \"lo-hi\"", s)
	}
	l, err1 := strconv.Atoi(strings.TrimSpace(lo))
	h, err2 := strconv.Atoi(strings.TrimSpace(hi))
	if err1 != nil || err2 != nil || l < 1 || h > 65535 || l > h {
		return 0, 0, fmt.Errorf("ingress.tcp_ports %q: want \"lo-hi\"", s)
	}
	return l, h, nil
}

// MachineAddr gives the address a proxy connects to, waking the machine when asked.
func (m *Manager) MachineAddr(ctx context.Context, id string, wake bool) (string, error) {
	e, err := m.entry(id)
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	state, ip := e.rec.State, e.rec.IP
	e.mu.Unlock()
	if state == api.StateRunning {
		_ = m.Touch(id)
		return ip, nil
	}
	if !wake {
		return "", ErrNotRunning
	}
	if _, err := m.Wake(ctx, id); err != nil {
		return "", err
	}
	return ip, nil
}

var _ = io.EOF
