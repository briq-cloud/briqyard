// Package machine runs machines: it owns their records, disks, network and Firecracker
// processes, and every lifecycle transition.
package machine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/briq-cloud/briqyard/internal/api"
	"github.com/briq-cloud/briqyard/internal/image"
)

// Record is a machine as the daemon keeps it: the API view plus what running it needs.
type Record struct {
	ID            string            `json:"id"`
	Tenant        string            `json:"tenant"`
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	ImageKey      string            `json:"image_key"`
	ImageDigest   string            `json:"image_digest"`
	ImageConfig   image.Config      `json:"image_config"`
	Entrypoint    []string          `json:"entrypoint,omitempty"`
	Cmd           []string          `json:"cmd,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	Files         []api.File        `json:"files,omitempty"`
	Size          api.Size          `json:"size"`
	Volume        *api.VolumeSpec   `json:"volume,omitempty"`
	Ports         []int             `json:"ports,omitempty"`
	Sleep         string            `json:"sleep,omitempty"`
	Restart       api.RestartPolicy `json:"restart"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	State         string            `json:"state"`
	StoppedReason string            `json:"stopped_reason,omitempty"`
	Exit          *api.Exit         `json:"exit,omitempty"`
	Error         string            `json:"error,omitempty"`
	SubnetIndex   int               `json:"subnet_index"`
	HostNum       int               `json:"host_num"`
	IP            string            `json:"ip"`
	PID           int               `json:"pid,omitempty"`
	Restarts      int               `json:"restarts"`
	Boots         int               `json:"boots"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	StartedAt     *time.Time        `json:"started_at,omitempty"`
	StoppedAt     *time.Time        `json:"stopped_at,omitempty"`
	LastUsedAt    *time.Time        `json:"last_used_at,omitempty"`
	// ConsoleOffset is where the current boot's console output starts.
	ConsoleOffset int64 `json:"console_offset"`
}

// Tenant is a tenant's network on this host.
type Tenant struct {
	ID          string    `json:"id"`
	SubnetIndex int       `json:"subnet_index"`
	CreatedAt   time.Time `json:"created_at"`
}

// Endpoint is a persisted endpoint.
type Endpoint struct {
	ID        string    `json:"id"`
	MachineID string    `json:"machine_id"`
	Tenant    string    `json:"tenant"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	HostPort  int       `json:"host_port,omitempty"`
	Host      string    `json:"host,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Hostname of the machine's alias and of the machine itself.
func (r *Record) Hostname() string    { return r.Name + ".internal" }
func (r *Record) MachineHost() string { return r.ID + ".vm.internal" }

// RootDataset and DataDataset are the machine's disks.
func (r *Record) RootDataset() string { return "m/" + r.ID + "/root" }
func (r *Record) DataDataset() string { return "m/" + r.ID + "/data" }
func (r *Record) Dataset() string     { return "m/" + r.ID }

// SleepWindow parses the sleep setting; zero means never.
func (r *Record) SleepWindow() time.Duration {
	d, _ := ParseSleep(r.Sleep)
	return d
}

// ParseSleep reads "30m", "2h", "7d", "never" or "". Zero is never.
func ParseSleep(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "never" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("sleep %q: want a number of days", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("sleep %q: want \"30m\", \"2h\", \"7d\" or \"never\"", s)
	}
	return d, nil
}

// NewID makes an id: a prefix and 12 hex characters.
func NewID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidName is a DNS label.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ToAPI is the API view of a record.
func (r *Record) ToAPI(endpoints []api.Endpoint, sleepsAt *time.Time) api.Machine {
	m := api.Machine{
		ID: r.ID, Tenant: r.Tenant, Name: r.Name, Image: r.Image, ImageDigest: r.ImageDigest,
		State: r.State, StoppedReason: r.StoppedReason, Exit: r.Exit, Error: r.Error, IP: r.IP,
		Hostname: r.Hostname(), MachineHost: r.MachineHost(), Size: r.Size, Volume: r.Volume,
		Ports: r.Ports, Sleep: r.Sleep, Restart: r.Restart, Metadata: r.Metadata, Endpoints: endpoints,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, StartedAt: r.StartedAt, StoppedAt: r.StoppedAt,
		LastUsedAt: r.LastUsedAt, SleepsAt: sleepsAt,
	}
	if m.Sleep == "" {
		m.Sleep = "never"
	}
	return m
}
