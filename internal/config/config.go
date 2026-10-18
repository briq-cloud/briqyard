// Package config loads the daemon's configuration file.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Config is briqyardd's configuration: where things are on the host and what it may do.
type Config struct {
	// Listen is the HTTP API address. Default 127.0.0.1:7420; put it behind TLS or a private
	// network before listening on anything else.
	Listen string `yaml:"listen"`
	// Token, when set, is required as `Authorization: Bearer <token>` on every API request.
	Token string `yaml:"token"`
	// DataDir holds the state database, per-machine runtime files and the image cache.
	DataDir string `yaml:"data_dir"`
	// Firecracker is the path of the firecracker binary.
	Firecracker string `yaml:"firecracker"`
	// Jailer is the path of the jailer binary; empty runs Firecracker without it (development).
	Jailer string `yaml:"jailer"`
	// Kernel is the uncompressed guest kernel (vmlinux) every machine boots.
	Kernel string `yaml:"kernel"`
	// KernelArgs are appended to the default boot arguments.
	KernelArgs string `yaml:"kernel_args"`
	// PCI enables Firecracker's PCI transport (needs a guest kernel with PCI support).
	PCI bool `yaml:"pci"`
	// Init is the briqyard-init binary copied into every root disk at /.briqyard/init.
	Init    string  `yaml:"init"`
	Storage Storage `yaml:"storage"`
	Network Network `yaml:"network"`
	Ingress Ingress `yaml:"ingress"`
	// RootDiskGB is the size of every root disk (thin: only written blocks take space).
	RootDiskGB int `yaml:"root_disk_gb"`
	// Fleet, when set, makes the daemon register with a briqyard-fleet and send heartbeats.
	Fleet *FleetClient `yaml:"fleet"`
	// Capacity the daemon advertises: memory it may hand to machines (default: the host's
	// memory minus 2 GB) and vCPUs (default: hardware threads times 4).
	Capacity Capacity `yaml:"capacity"`
}

type Storage struct {
	// Backend is "zfs" (the only one today).
	Backend string `yaml:"backend"`
	// Pool is the ZFS pool (or dataset) that holds every disk.
	Pool string `yaml:"pool"`
}

type Network struct {
	// Range is the pool of tenant subnets, carved into /24s. Default 10.64.0.0/10.
	Range string `yaml:"range"`
	// Upstream DNS servers the gateway forwards to. Default: the host's resolv.conf, then 1.1.1.1.
	UpstreamDNS []string `yaml:"upstream_dns"`
	// Egress is the host interface machines reach the internet through (for masquerade).
	// Empty: the interface of the default route.
	Egress string `yaml:"egress"`
}

type Ingress struct {
	// TCPPorts is the range of host ports handed to TCP endpoints, "20000-29999".
	TCPPorts string `yaml:"tcp_ports"`
	// HTTP is the address of the shared HTTP listener that routes by host name; empty disables it.
	HTTP string `yaml:"http"`
	// Domain is the suffix of HTTP endpoint host names: `<endpoint>.<domain>`.
	Domain string `yaml:"domain"`
	// Bind is the address TCP endpoints listen on. Default 0.0.0.0.
	Bind string `yaml:"bind"`
}

type FleetClient struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
	// Advertise is the URL the fleet reaches this daemon at.
	Advertise string `yaml:"advertise"`
}

type Capacity struct {
	MemoryMB int `yaml:"memory_mb"`
	VCPUs    int `yaml:"vcpus"`
}

// Default is the configuration with every default applied; Load overlays a file on it.
func Default() *Config {
	return &Config{
		Listen:      "127.0.0.1:7420",
		DataDir:     "/var/lib/briqyard",
		Firecracker: "/usr/local/bin/firecracker",
		Kernel:      "/var/lib/briqyard/vmlinux",
		Init:        "/usr/local/bin/briqyard-init",
		Storage:     Storage{Backend: "zfs", Pool: "byard"},
		Network:     Network{Range: "10.64.0.0/10"},
		Ingress:     Ingress{TCPPorts: "20000-29999", Bind: "0.0.0.0", Domain: "byard.localhost"},
		RootDiskGB:  8,
		Capacity:    Capacity{VCPUs: runtime.NumCPU() * 4},
	}
}

// Load reads a YAML file over the defaults. A missing path is the defaults.
func Load(path string) (*Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks what can be checked without touching the host.
func (c *Config) Validate() error {
	if c.Storage.Backend != "zfs" {
		return fmt.Errorf("storage.backend: %q is not supported (zfs)", c.Storage.Backend)
	}
	if c.Storage.Pool == "" {
		return fmt.Errorf("storage.pool is required")
	}
	if c.RootDiskGB < 1 {
		return fmt.Errorf("root_disk_gb must be at least 1")
	}
	for _, p := range []struct{ name, path string }{{"firecracker", c.Firecracker}, {"kernel", c.Kernel}, {"init", c.Init}} {
		if !filepath.IsAbs(p.path) {
			return fmt.Errorf("%s must be an absolute path", p.name)
		}
	}
	return nil
}

// RunDir is where per-machine runtime files live (sockets, logs).
func (c *Config) RunDir() string { return filepath.Join(c.DataDir, "run") }

// ImageDir is where image extraction and metadata live.
func (c *Config) ImageDir() string { return filepath.Join(c.DataDir, "images") }

// StatePath is the state database.
func (c *Config) StatePath() string { return filepath.Join(c.DataDir, "state.db") }
