package machine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/briq-cloud/briqyard/internal/api"
	"github.com/briq-cloud/briqyard/internal/config"
	"github.com/briq-cloud/briqyard/internal/fc"
	"github.com/briq-cloud/briqyard/internal/guest"
	"github.com/briq-cloud/briqyard/internal/image"
	"github.com/briq-cloud/briqyard/internal/netw"
	"github.com/briq-cloud/briqyard/internal/storage"
	"github.com/briq-cloud/briqyard/internal/store"
)

// Errors the API maps to statuses.
var (
	ErrNotFound    = errors.New("machine not found")
	ErrNotRunning  = errors.New("machine is not running")
	ErrBadState    = errors.New("machine is busy")
	ErrConflict    = errors.New("a machine with that name exists in the tenant")
	ErrCapacity    = errors.New("the host is full")
	ErrInvalid     = errors.New("invalid request")
	ErrTenantInUse = errors.New("the tenant still has machines")
)

// Invalid wraps a validation message.
func Invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Manager owns every machine on the host.
type Manager struct {
	cfg    *config.Config
	store  *store.Store
	disks  storage.Backend
	images *image.Builder
	dns    *netw.Resolver
	log    *slog.Logger
	rng    netip.Prefix
	egress string
	HostID string

	mu         sync.Mutex
	machines   map[string]*entry
	tenants    map[string]*Tenant
	endpoints  map[string]*Endpoint
	onEndpoint func(ep Endpoint, added bool)

	stopCh chan struct{}
	wg     sync.WaitGroup
}

type entry struct {
	mu      sync.Mutex
	rec     Record
	proc    *fc.Process
	stopReq string // reason set before asking the guest to stop; empty when it ends on its own
	stopCh  chan struct{}
}

// New loads the state and prepares the host: forwarding, nftables, the tenants' bridges and
// DNS, and reaps machines left over from a previous daemon.
func New(ctx context.Context, cfg *config.Config, st *store.Store, disks storage.Backend, images *image.Builder, dns *netw.Resolver, log *slog.Logger) (*Manager, error) {
	rng, err := netip.ParsePrefix(cfg.Network.Range)
	if err != nil {
		return nil, fmt.Errorf("network.range: %w", err)
	}
	m := &Manager{cfg: cfg, store: st, disks: disks, images: images, dns: dns, log: log, rng: rng,
		machines: map[string]*entry{}, tenants: map[string]*Tenant{}, endpoints: map[string]*Endpoint{}, stopCh: make(chan struct{})}
	m.HostID, err = st.GetMeta("host_id")
	if errors.Is(err, store.ErrNotFound) {
		m.HostID = NewID("h")
		if err := st.PutMeta("host_id", m.HostID); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	m.egress = cfg.Network.Egress
	if m.egress == "" {
		if m.egress, err = netw.DefaultEgressInterface(); err != nil {
			return nil, fmt.Errorf("network.egress: %w", err)
		}
	}
	if err := os.MkdirAll(cfg.RunDir(), 0o750); err != nil {
		return nil, err
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	if err := netw.EnableForwarding(); err != nil {
		return nil, fmt.Errorf("ip_forward: %w", err)
	}
	for _, t := range m.tenants {
		if err := m.plumbTenant(t); err != nil {
			return nil, err
		}
	}
	if err := m.applyRules(ctx); err != nil {
		return nil, err
	}
	m.recover()
	m.wg.Add(1)
	go m.sleeper()
	return m, nil
}

func (m *Manager) load() error {
	err := m.store.EachTenant(func(_ string, data []byte) error {
		var t Tenant
		if err := json.Unmarshal(data, &t); err != nil {
			return err
		}
		m.tenants[t.ID] = &t
		return nil
	})
	if err != nil {
		return err
	}
	err = m.store.EachMachine(func(_ string, data []byte) error {
		var r Record
		if err := json.Unmarshal(data, &r); err != nil {
			return err
		}
		m.machines[r.ID] = &entry{rec: r}
		return nil
	})
	if err != nil {
		return err
	}
	return m.store.EachEndpoint(func(_ string, data []byte) error {
		var e Endpoint
		if err := json.Unmarshal(data, &e); err != nil {
			return err
		}
		m.endpoints[e.ID] = &e
		return nil
	})
}

// recover handles machines a previous daemon left: their Firecracker processes are ended and
// they are marked stopped (idle, so the next use wakes them). Adopting a live process is for later.
func (m *Manager) recover() {
	for _, e := range m.machines {
		r := &e.rec
		switch r.State {
		case api.StateRunning, api.StateStarting, api.StateStopping:
			if r.PID > 0 {
				_ = syscall.Kill(-r.PID, syscall.SIGKILL)
				_ = syscall.Kill(r.PID, syscall.SIGKILL)
			}
			_ = netw.DeleteTap(r.ID)
			now := time.Now().UTC()
			r.State, r.StoppedReason, r.PID, r.StoppedAt, r.UpdatedAt = api.StateStopped, api.StopIdle, 0, &now, now
			m.log.Warn("machine left running by a previous daemon, marked stopped", "machine", r.ID)
			_ = m.save(r)
		case api.StateDestroying:
			go func(id string) {
				if err := m.Destroy(context.Background(), id); err != nil {
					m.log.Error("resume destroy", "machine", id, "err", err)
				}
			}(r.ID)
		}
	}
}

func (m *Manager) save(r *Record) error {
	r.UpdatedAt = time.Now().UTC()
	return m.store.PutMachine(r.ID, r)
}

// Close stops the sleeper and every running machine (the daemon is going down).
func (m *Manager) Close(ctx context.Context) {
	close(m.stopCh)
	m.wg.Wait()
	m.mu.Lock()
	var running []*entry
	for _, e := range m.machines {
		if e.rec.State == api.StateRunning || e.rec.State == api.StateStarting {
			running = append(running, e)
		}
	}
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, e := range running {
		wg.Add(1)
		go func(e *entry) {
			defer wg.Done()
			if err := m.stopEntry(ctx, e, api.StopIdle, 10*time.Second); err != nil {
				m.log.Warn("stop on shutdown", "machine", e.rec.ID, "err", err)
			}
		}(e)
	}
	wg.Wait()
	m.dns.Shutdown(ctx)
}

// --- tenants ---

func (m *Manager) ensureTenant(id string) (*Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tenants[id]; ok {
		return t, nil
	}
	var used []int
	for _, t := range m.tenants {
		used = append(used, t.SubnetIndex)
	}
	count := 1 << (24 - m.rng.Bits())
	idx, err := netw.FirstFree(used, 0, count-1)
	if err != nil {
		return nil, fmt.Errorf("tenant networks: %w", err)
	}
	t := &Tenant{ID: id, SubnetIndex: idx, CreatedAt: time.Now().UTC()}
	if err := m.plumbTenant(t); err != nil {
		return nil, err
	}
	if err := m.store.PutTenant(id, t); err != nil {
		return nil, err
	}
	m.tenants[id] = t
	if err := m.applyRulesLocked(context.Background()); err != nil {
		return nil, err
	}
	return t, nil
}

func (m *Manager) subnet(t *Tenant) netw.Subnet {
	s, _ := netw.SubnetAt(m.rng, t.SubnetIndex)
	return s
}

// plumbTenant makes the bridge and the DNS listener. Called with or without m.mu; it touches
// only the host and the resolver.
func (m *Manager) plumbTenant(t *Tenant) error {
	s := m.subnet(t)
	if _, err := netw.EnsureBridge(s); err != nil {
		return err
	}
	if err := m.dns.Listen(s.Gateway()); err != nil {
		return fmt.Errorf("dns on %s: %w", s.Gateway(), err)
	}
	return nil
}

func (m *Manager) applyRules(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyRulesLocked(ctx)
}

func (m *Manager) applyRulesLocked(ctx context.Context) error {
	rs := netw.Ruleset{Egress: m.egress, Range: m.rng.String()}
	for _, t := range m.tenants {
		s := m.subnet(t)
		rs.Subnets = append(rs.Subnets, netw.RulesetSubnet{Bridge: netw.BridgeName(t.SubnetIndex), Prefix: s.Prefix.String()})
	}
	sort.Slice(rs.Subnets, func(i, j int) bool { return rs.Subnets[i].Bridge < rs.Subnets[j].Bridge })
	return rs.Apply(ctx)
}

// refreshDNS republishes a tenant's names. Called with m.mu held.
func (m *Manager) refreshDNSLocked(t *Tenant) {
	names := map[string]netip.Addr{}
	for _, e := range m.machines {
		r := &e.rec
		if r.Tenant != t.ID || r.IP == "" {
			continue
		}
		ip, err := netip.ParseAddr(r.IP)
		if err != nil {
			continue
		}
		names[r.Hostname()] = ip
		names[r.MachineHost()] = ip
	}
	m.dns.Set(m.subnet(t).Gateway(), names)
}

// Tenants lists the tenants on the host.
func (m *Manager) Tenants() []Tenant {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DeleteTenant removes an empty tenant's network. Missing is success.
func (m *Manager) DeleteTenant(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	if !ok {
		return nil
	}
	for _, e := range m.machines {
		if e.rec.Tenant == id {
			return ErrTenantInUse
		}
	}
	m.dns.Unset(m.subnet(t).Gateway())
	if err := netw.DeleteBridge(t.SubnetIndex); err != nil {
		return err
	}
	delete(m.tenants, id)
	if err := m.store.DeleteTenant(id); err != nil {
		return err
	}
	return m.applyRulesLocked(ctx)
}

// --- create ---

// Create makes a machine and, unless asked not to, starts it.
func (m *Manager) Create(ctx context.Context, req api.CreateMachineRequest) (api.Machine, error) {
	if req.Tenant == "" || len(req.Tenant) > 64 {
		return api.Machine{}, Invalid("tenant is required (at most 64 characters)")
	}
	if !ValidName(req.Name) {
		return api.Machine{}, Invalid("name must be a DNS label (a-z, 0-9, -)")
	}
	if req.Image == "" && req.Fork == nil {
		return api.Machine{}, Invalid("image is required")
	}
	if req.Size.VCPUs < 1 || req.Size.VCPUs > 32 {
		return api.Machine{}, Invalid("size.vcpus must be 1..32")
	}
	if req.Size.MemoryMB < 128 || req.Size.MemoryMB > 256*1024 {
		return api.Machine{}, Invalid("size.memory_mb must be 128..262144")
	}
	if req.Volume != nil {
		if req.Volume.SizeGB < 1 || !filepath.IsAbs(req.Volume.Mount) {
			return api.Machine{}, Invalid("volume needs size_gb >= 1 and an absolute mount")
		}
	}
	if _, err := ParseSleep(req.Sleep); err != nil {
		return api.Machine{}, Invalid("%v", err)
	}
	for _, f := range req.Files {
		if !filepath.IsAbs(f.Path) {
			return api.Machine{}, Invalid("file %q: path must be absolute", f.Path)
		}
	}
	restart := api.RestartPolicy{Policy: "on-failure", MaxRetries: 3}
	if req.Restart != nil {
		switch req.Restart.Policy {
		case "no", "on-failure", "always":
			restart = *req.Restart
		default:
			return api.Machine{}, Invalid("restart.policy must be no, on-failure or always")
		}
	}

	// Name uniqueness in the tenant, checked again when the record is added.
	if m.nameTaken(req.Tenant, req.Name) {
		return api.Machine{}, ErrConflict
	}

	var src *entry
	rec := Record{ID: NewID("m"), Tenant: req.Tenant, Name: req.Name, Entrypoint: req.Entrypoint, Cmd: req.Cmd, Env: req.Env, Files: req.Files,
		Size: req.Size, Volume: req.Volume, Ports: req.Ports, Sleep: req.Sleep, Restart: restart, Metadata: req.Metadata,
		State: api.StateCreated, CreatedAt: time.Now().UTC()}
	if rec.Sleep == "never" {
		rec.Sleep = ""
	}
	if req.Fork != nil {
		var err error
		src, err = m.entry(req.Fork.MachineID)
		if err != nil {
			return api.Machine{}, fmt.Errorf("fork source: %w", err)
		}
		if src.rec.Tenant != req.Tenant {
			return api.Machine{}, Invalid("fork source belongs to another tenant")
		}
		rec.Image, rec.ImageKey, rec.ImageDigest, rec.ImageConfig = src.rec.Image, src.rec.ImageKey, src.rec.ImageDigest, src.rec.ImageConfig
		if req.Image != "" && req.Image != src.rec.Image {
			return api.Machine{}, Invalid("a fork keeps its source's image")
		}
		if req.Volume == nil {
			rec.Volume = src.rec.Volume
		} else if src.rec.Volume != nil && req.Volume.Mount != src.rec.Volume.Mount {
			return api.Machine{}, Invalid("a fork keeps its source's volume mount")
		}
	} else {
		im, err := m.images.Ensure(ctx, req.Image)
		if err != nil {
			return api.Machine{}, err
		}
		rec.Image, rec.ImageKey, rec.ImageDigest, rec.ImageConfig = req.Image, im.Key, im.Digest, im.Config
	}

	t, err := m.ensureTenant(req.Tenant)
	if err != nil {
		return api.Machine{}, err
	}
	e := &entry{rec: rec}
	if err := m.addMachine(e, t); err != nil {
		return api.Machine{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := m.makeDisks(ctx, e, src, req.Fork); err != nil {
		m.removeMachine(e)
		_ = m.disks.Destroy(ctx, rec.Dataset())
		return api.Machine{}, err
	}
	if err := m.save(&e.rec); err != nil {
		return api.Machine{}, err
	}
	if req.Start == nil || *req.Start {
		if err := m.startEntry(ctx, e); err != nil {
			return m.view(e), err
		}
	}
	return m.view(e), nil
}

func (m *Manager) nameTaken(tenant, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.machines {
		if e.rec.Tenant == tenant && e.rec.Name == name && e.rec.State != api.StateDestroying {
			return true
		}
	}
	return false
}

// addMachine gives the machine an address and registers it. Nothing on disk yet.
func (m *Manager) addMachine(e *entry, t *Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.machines {
		if o.rec.Tenant == e.rec.Tenant && o.rec.Name == e.rec.Name && o.rec.State != api.StateDestroying {
			return ErrConflict
		}
	}
	var used []int
	for _, o := range m.machines {
		if o.rec.Tenant == t.ID {
			used = append(used, o.rec.HostNum)
		}
	}
	n, err := netw.FirstFree(used, 2, 254)
	if err != nil {
		return fmt.Errorf("tenant %s: %w", t.ID, err)
	}
	ip, err := m.subnet(t).Host(n)
	if err != nil {
		return err
	}
	e.rec.SubnetIndex, e.rec.HostNum, e.rec.IP = t.SubnetIndex, n, ip.String()
	m.machines[e.rec.ID] = e
	m.refreshDNSLocked(t)
	return nil
}

func (m *Manager) removeMachine(e *entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.machines, e.rec.ID)
	if t, ok := m.tenants[e.rec.Tenant]; ok {
		m.refreshDNSLocked(t)
	}
}

// makeDisks clones the root disk and makes the data volume; for a fork, both from snapshots
// of the source taken now.
func (m *Manager) makeDisks(ctx context.Context, e *entry, src *entry, fork *api.ForkSpec) error {
	r := &e.rec
	if src != nil && (fork.Copy == "" || fork.Copy == "disk") {
		snap := "fork-" + r.ID
		if err := m.disks.Snapshot(ctx, src.rec.RootDataset(), snap); err != nil {
			return err
		}
		if _, err := m.disks.Clone(ctx, src.rec.RootDataset(), snap, r.RootDataset()); err != nil {
			return err
		}
		if r.Volume != nil {
			if ok, _ := m.disks.Exists(ctx, src.rec.DataDataset()); ok {
				if err := m.disks.Snapshot(ctx, src.rec.DataDataset(), snap); err != nil {
					return err
				}
				if _, err := m.disks.Clone(ctx, src.rec.DataDataset(), snap, r.DataDataset()); err != nil {
					return err
				}
				return nil
			}
		}
	} else {
		if _, err := m.disks.Clone(ctx, "images/"+r.ImageKey, image.Snap, r.RootDataset()); err != nil {
			return err
		}
	}
	if r.Volume != nil {
		dev, err := m.disks.Create(ctx, r.DataDataset(), int64(r.Volume.SizeGB)<<30)
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, "mkfs.ext4", "-q", "-F", "-L", "data", "-E", "lazy_itable_init=0,lazy_journal_init=0", dev)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("mkfs.ext4 %s: %s", dev, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// --- lookup ---

func (m *Manager) entry(id string) (*entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.machines[id]
	if !ok {
		return nil, ErrNotFound
	}
	return e, nil
}

// view is the API view; it reads the record without the entry lock (fields are copied).
func (m *Manager) view(e *entry) api.Machine {
	r := e.rec
	var sleepsAt *time.Time
	if r.State == api.StateRunning && r.LastUsedAt != nil {
		if w := r.SleepWindow(); w > 0 {
			t := r.LastUsedAt.Add(w)
			sleepsAt = &t
		}
	}
	return r.ToAPI(m.endpointsOf(r.ID), sleepsAt)
}

// Get returns a machine.
func (m *Manager) Get(id string) (api.Machine, error) {
	e, err := m.entry(id)
	if err != nil {
		return api.Machine{}, err
	}
	return m.view(e), nil
}

// List returns the machines, of one tenant when tenant is set.
func (m *Manager) List(tenant string) []api.Machine {
	m.mu.Lock()
	entries := make([]*entry, 0, len(m.machines))
	for _, e := range m.machines {
		if tenant == "" || e.rec.Tenant == tenant {
			entries = append(entries, e)
		}
	}
	m.mu.Unlock()
	out := make([]api.Machine, 0, len(entries))
	for _, e := range entries {
		out = append(out, m.view(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Usage is what running machines take.
func (m *Manager) Usage() (used api.Capacity, running, total int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.machines {
		total++
		if e.rec.State == api.StateRunning || e.rec.State == api.StateStarting {
			running++
			used.MemoryMB += e.rec.Size.MemoryMB
			used.VCPUs += e.rec.Size.VCPUs
		}
	}
	return
}

// Capacity is what the host may hand out.
func (m *Manager) Capacity() api.Capacity {
	c := api.Capacity{MemoryMB: m.cfg.Capacity.MemoryMB, VCPUs: m.cfg.Capacity.VCPUs}
	if c.MemoryMB == 0 {
		c.MemoryMB = hostMemoryMB() - 2048
		if c.MemoryMB < 1024 {
			c.MemoryMB = 1024
		}
	}
	return c
}

func hostMemoryMB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 4096
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				kb, _ := strconv.Atoi(f[1])
				return kb / 1024
			}
		}
	}
	return 4096
}

// --- start ---

// Start boots a created or stopped machine.
func (m *Manager) Start(ctx context.Context, id string) (api.Machine, error) {
	e, err := m.entry(id)
	if err != nil {
		return api.Machine{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	switch e.rec.State {
	case api.StateRunning:
		return m.view(e), nil
	case api.StateCreated, api.StateStopped, api.StateError:
	default:
		return m.view(e), fmt.Errorf("%w: %s", ErrBadState, e.rec.State)
	}
	err = m.startEntry(ctx, e)
	return m.view(e), err
}

// Wake starts a machine that went to sleep (stopped for idleness or by its process ending
// cleanly); a machine stopped on purpose stays stopped. Returns the machine's address.
func (m *Manager) Wake(ctx context.Context, id string) (api.Machine, error) {
	e, err := m.entry(id)
	if err != nil {
		return api.Machine{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	switch e.rec.State {
	case api.StateRunning:
		m.touchLocked(e)
		return m.view(e), nil
	case api.StateStopped:
		if e.rec.StoppedReason == api.StopUser {
			return m.view(e), fmt.Errorf("%w: stopped on request", ErrNotRunning)
		}
	case api.StateCreated:
	default:
		return m.view(e), fmt.Errorf("%w: %s", ErrBadState, e.rec.State)
	}
	err = m.startEntry(ctx, e)
	return m.view(e), err
}

// startEntry boots the machine. Called with e.mu held.
func (m *Manager) startEntry(ctx context.Context, e *entry) error {
	r := &e.rec
	cap := m.Capacity()
	used, _, _ := m.Usage()
	if used.MemoryMB+r.Size.MemoryMB > cap.MemoryMB {
		return fmt.Errorf("%w: %d MB used of %d", ErrCapacity, used.MemoryMB, cap.MemoryMB)
	}
	r.State, r.Error, r.PID = api.StateStarting, "", 0
	_ = m.save(r)
	fail := func(err error) error {
		now := time.Now().UTC()
		r.State, r.Error, r.StoppedAt, r.PID = api.StateError, err.Error(), &now, 0
		_ = m.save(r)
		return err
	}
	t := m.tenantOf(r.Tenant)
	if t == nil {
		return fail(errors.New("tenant network is gone"))
	}
	tap, err := netw.EnsureTap(r.ID, netw.BridgeName(t.SubnetIndex))
	if err != nil {
		return fail(err)
	}
	dir := filepath.Join(m.cfg.RunDir(), r.ID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fail(err)
	}
	configDrive := filepath.Join(dir, "config.tar")
	if err := m.writeConfigDrive(configDrive, r, t); err != nil {
		return fail(fmt.Errorf("config drive: %w", err))
	}
	rootDev, err := m.disks.Device(ctx, r.RootDataset())
	if err != nil {
		return fail(fmt.Errorf("root disk: %w", err))
	}
	dataDev := ""
	if r.Volume != nil {
		if dataDev, err = m.disks.Device(ctx, r.DataDataset()); err != nil {
			return fail(fmt.Errorf("data volume: %w", err))
		}
	}
	// Where this boot's console output starts.
	if fi, err := os.Stat(filepath.Join(dir, "console.log")); err == nil {
		r.ConsoleOffset = fi.Size()
	} else {
		r.ConsoleOffset = 0
	}
	proc, err := fc.Start(ctx, m.cfg.Firecracker, r.ID, dir, m.cfg.PCI)
	if err != nil {
		return fail(err)
	}
	c := proc.Client
	ip, _ := netip.ParseAddr(r.IP)
	steps := []func() error{
		func() error {
			return c.PutMachineConfig(ctx, fc.MachineConfig{VCPUCount: r.Size.VCPUs, MemSizeMiB: r.Size.MemoryMB, SMT: false})
		},
		func() error {
			return c.PutBootSource(ctx, fc.BootSource{KernelImagePath: m.cfg.Kernel, BootArgs: m.bootArgs()})
		},
		func() error {
			return c.PutDrive(ctx, fc.Drive{DriveID: "rootfs", PathOnHost: rootDev, IsRootDevice: true, CacheType: "Writeback"})
		},
		func() error {
			return c.PutDrive(ctx, fc.Drive{DriveID: "config", PathOnHost: configDrive, IsReadOnly: true, CacheType: "Unsafe"})
		},
		func() error {
			return c.PutNetworkInterface(ctx, fc.NetworkInterface{IfaceID: "eth0", HostDevName: tap, GuestMAC: netw.MACFor(ip)})
		},
		func() error { return c.PutVsock(ctx, fc.Vsock{GuestCID: 3, UDSPath: proc.VsockSock}) },
	}
	if dataDev != "" {
		steps = append(steps[:4], append([]func() error{func() error {
			return c.PutDrive(ctx, fc.Drive{DriveID: "data", PathOnHost: dataDev, CacheType: "Writeback"})
		}}, steps[4:]...)...)
	}
	for _, step := range steps {
		if err := step(); err != nil {
			proc.Kill()
			return fail(fmt.Errorf("configure firecracker: %w", err))
		}
	}
	if err := c.InstanceStart(ctx); err != nil {
		proc.Kill()
		return fail(fmt.Errorf("start: %w", err))
	}
	e.proc, e.stopReq, e.stopCh = proc, "", make(chan struct{})
	r.PID, r.Boots = proc.PID(), r.Boots+1
	_ = m.save(r)
	m.wg.Add(1)
	go m.watch(e, proc)

	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ready := make(chan error, 1)
	go func() { ready <- guest.WaitReady(wctx, proc.VsockSock) }()
	select {
	case err := <-ready:
		if err != nil {
			if proc.Exited() {
				// The process ended during boot: watch recorded why.
				e.mu.Unlock()
				time.Sleep(200 * time.Millisecond)
				e.mu.Lock()
				return fmt.Errorf("the machine exited during boot: %s", m.lastConsoleLines(r, 5))
			}
			proc.Kill()
			return fail(fmt.Errorf("the guest did not come up: %w", err))
		}
	case <-proc.Done():
		e.mu.Unlock()
		time.Sleep(200 * time.Millisecond)
		e.mu.Lock()
		return fmt.Errorf("the machine exited during boot: %s", m.lastConsoleLines(r, 5))
	}
	now := time.Now().UTC()
	r.State, r.StartedAt, r.LastUsedAt, r.StoppedReason = api.StateRunning, &now, &now, ""
	_ = m.save(r)
	m.log.Info("machine running", "machine", r.ID, "tenant", r.Tenant, "name", r.Name, "ip", r.IP, "pid", r.PID)
	return nil
}

func (m *Manager) tenantOf(id string) *Tenant {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tenants[id]
}

func (m *Manager) bootArgs() string {
	args := "console=ttyS0 reboot=k panic=1 root=/dev/vda rw rootfstype=ext4 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd random.trust_cpu=on init=" + image.InitPath
	if !m.cfg.PCI {
		args += " pci=off"
	}
	if m.cfg.KernelArgs != "" {
		args += " " + m.cfg.KernelArgs
	}
	return args
}

var exitRe = regexp.MustCompile(`\[briqyard\] exit code=(\d+) oom=(true|false) requested=(true|false)`)

// watch waits for the Firecracker process and settles the machine's state.
func (m *Manager) watch(e *entry, proc *fc.Process) {
	defer m.wg.Done()
	_ = proc.Wait()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.proc != proc {
		return
	}
	r := &e.rec
	_ = netw.DeleteTap(r.ID)
	e.proc = nil
	now := time.Now().UTC()
	r.PID, r.StoppedAt = 0, &now
	code, oom, requested := m.exitFromConsole(r)
	switch {
	case e.stopReq != "":
		r.State, r.StoppedReason = api.StateStopped, e.stopReq
		m.log.Info("machine stopped", "machine", r.ID, "reason", e.stopReq)
	case requested:
		r.State, r.StoppedReason = api.StateStopped, api.StopUser
	default:
		r.Exit = &api.Exit{Code: code, OOMKilled: oom, At: now}
		again := false
		switch r.Restart.Policy {
		case "always":
			again = true
		case "on-failure":
			again = code != 0 && r.Restarts < r.Restart.MaxRetries
		}
		if again {
			r.Restarts++
			r.Exit.Restarting = true
			r.State, r.StoppedReason = api.StateStopped, api.StopExit
			_ = m.save(r)
			m.log.Warn("machine exited, restarting", "machine", r.ID, "code", code, "oom", oom, "restart", r.Restarts)
			go func() {
				time.Sleep(time.Duration(r.Restarts) * time.Second)
				e.mu.Lock()
				defer e.mu.Unlock()
				if e.rec.State != api.StateStopped || e.rec.StoppedReason != api.StopExit {
					return
				}
				if err := m.startEntry(context.Background(), e); err != nil {
					m.log.Error("restart", "machine", e.rec.ID, "err", err)
				}
			}()
			return
		}
		r.Restarts = 0
		r.State, r.StoppedReason = api.StateStopped, api.StopExit
		m.log.Info("machine exited", "machine", r.ID, "code", code, "oom", oom)
	}
	e.stopReq = ""
	close(e.stopCh)
	_ = m.save(r)
}

// exitFromConsole reads the init's exit line for this boot.
func (m *Manager) exitFromConsole(r *Record) (code int, oom, requested bool) {
	console := filepath.Join(m.cfg.RunDir(), r.ID, "console.log")
	f, err := os.Open(console)
	if err != nil {
		return 255, false, false
	}
	defer f.Close()
	if _, err := f.Seek(r.ConsoleOffset, 0); err != nil {
		return 255, false, false
	}
	data, _ := readAllBounded(f, 8<<20)
	match := exitRe.FindAllSubmatch(data, -1)
	if len(match) == 0 {
		return 255, false, false
	}
	last := match[len(match)-1]
	code, _ = strconv.Atoi(string(last[1]))
	return code, string(last[2]) == "true", string(last[3]) == "true"
}

func readAllBounded(f *os.File, max int64) ([]byte, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	pos, _ := f.Seek(0, 1)
	n := fi.Size() - pos
	if n > max {
		if _, err := f.Seek(fi.Size()-max, 0); err != nil {
			return nil, err
		}
		n = max
	}
	buf := make([]byte, n)
	_, err = f.Read(buf)
	return buf, err
}

func (m *Manager) lastConsoleLines(r *Record, n int) string {
	console := filepath.Join(m.cfg.RunDir(), r.ID, "console.log")
	f, err := os.Open(console)
	if err != nil {
		return ""
	}
	defer f.Close()
	_, _ = f.Seek(r.ConsoleOffset, 0)
	data, _ := readAllBounded(f, 64<<10)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// --- stop ---

// Stop stops a running machine on request.
func (m *Manager) Stop(ctx context.Context, id string, timeout time.Duration) (api.Machine, error) {
	e, err := m.entry(id)
	if err != nil {
		return api.Machine{}, err
	}
	err = m.stopEntry(ctx, e, api.StopUser, timeout)
	e.mu.Lock()
	defer e.mu.Unlock()
	return m.view(e), err
}

// stopEntry asks the guest to end its process, then waits for Firecracker to exit; after the
// grace, it kills. Takes e.mu itself so that watch can settle the state meanwhile.
func (m *Manager) stopEntry(ctx context.Context, e *entry, reason string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	e.mu.Lock()
	r := &e.rec
	switch r.State {
	case api.StateStopped, api.StateCreated, api.StateError:
		if r.State == api.StateStopped && reason == api.StopUser && r.StoppedReason != api.StopUser {
			r.StoppedReason = api.StopUser
			_ = m.save(r)
		}
		e.mu.Unlock()
		return nil
	case api.StateRunning:
	case api.StateStopping:
		stopCh := e.stopCh
		e.mu.Unlock()
		select {
		case <-stopCh:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	default:
		e.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrBadState, r.State)
	}
	proc := e.proc
	e.stopReq = reason
	r.State = api.StateStopping
	_ = m.save(r)
	stopCh := e.stopCh
	e.mu.Unlock()

	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err := guest.Shutdown(sctx, proc.VsockSock, timeout)
	cancel()
	if err != nil {
		m.log.Warn("guest shutdown request failed, killing", "machine", r.ID, "err", err)
		proc.Kill()
	}
	if !proc.WaitExit(timeout + 5*time.Second) {
		m.log.Warn("guest did not stop in time, killing", "machine", r.ID)
		proc.Kill()
		proc.WaitExit(5 * time.Second)
	}
	select {
	case <-stopCh:
	case <-time.After(5 * time.Second):
	}
	return nil
}

// --- destroy ---

// Destroy removes a machine, its endpoints and its disks.
func (m *Manager) Destroy(ctx context.Context, id string) error {
	e, err := m.entry(id)
	if err != nil {
		return nil
	}
	e.mu.Lock()
	if e.rec.State == api.StateRunning || e.rec.State == api.StateStopping {
		e.mu.Unlock()
		if err := m.stopEntry(ctx, e, api.StopUser, 5*time.Second); err != nil {
			return err
		}
		e.mu.Lock()
	}
	e.rec.State = api.StateDestroying
	_ = m.save(&e.rec)
	e.mu.Unlock()
	for _, ep := range m.endpointsOf(id) {
		_ = m.DeleteEndpoint(ep.ID)
	}
	_ = netw.DeleteTap(id)
	if err := m.disks.Destroy(ctx, e.rec.Dataset()); err != nil {
		return fmt.Errorf("disks: %w", err)
	}
	_ = os.RemoveAll(filepath.Join(m.cfg.RunDir(), id))
	if err := m.store.DeleteMachine(id); err != nil {
		return err
	}
	m.removeMachine(e)
	m.log.Info("machine destroyed", "machine", id)
	return nil
}

// --- use and sleep ---

// Touch records use of the machine, which postpones its sleep.
func (m *Manager) Touch(id string) error {
	e, err := m.entry(id)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	m.touchLocked(e)
	return nil
}

func (m *Manager) touchLocked(e *entry) {
	now := time.Now().UTC()
	e.rec.LastUsedAt = &now
	_ = m.save(&e.rec)
}

// sleeper stops machines whose window ran out.
func (m *Manager) sleeper() {
	defer m.wg.Done()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-t.C:
		}
		m.mu.Lock()
		var due []*entry
		for _, e := range m.machines {
			r := &e.rec
			if r.State != api.StateRunning || r.LastUsedAt == nil {
				continue
			}
			if w := r.SleepWindow(); w > 0 && time.Since(*r.LastUsedAt) > w {
				due = append(due, e)
			}
		}
		m.mu.Unlock()
		for _, e := range due {
			m.log.Info("machine idle, going to sleep", "machine", e.rec.ID)
			if err := m.stopEntry(context.Background(), e, api.StopIdle, 10*time.Second); err != nil {
				m.log.Warn("sleep", "machine", e.rec.ID, "err", err)
			}
		}
	}
}

// WaitRunning blocks until the machine is running, or the context ends.
func (m *Manager) WaitRunning(ctx context.Context, id string) error {
	for {
		mc, err := m.Get(id)
		if err != nil {
			return err
		}
		switch mc.State {
		case api.StateRunning:
			return nil
		case api.StateError:
			return fmt.Errorf("%w: %s", ErrNotRunning, mc.Error)
		case api.StateStopped:
			if mc.StoppedReason == api.StopExit && mc.Exit != nil && mc.Exit.Restarting {
				break
			}
			return fmt.Errorf("%w: stopped (%s)", ErrNotRunning, mc.StoppedReason)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
