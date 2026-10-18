// Package api is briqyardd's HTTP API: the JSON types every client uses, and the server.
package api

import "time"

// Size is a machine's compute.
type Size struct {
	VCPUs    int `json:"vcpus"`
	MemoryMB int `json:"memory_mb"`
}

// VolumeSpec asks for a data volume mounted in the machine.
type VolumeSpec struct {
	SizeGB int    `json:"size_gb"`
	Mount  string `json:"mount"`
}

// File is a boot file: written before the process starts, and again at every cold start.
type File struct {
	Path   string `json:"path"`
	Base64 string `json:"base64"`
	// Mode in octal digits ("0644"); empty is 0644.
	Mode string `json:"mode,omitempty"`
}

// RestartPolicy says what the daemon does when the main process ends on its own.
type RestartPolicy struct {
	// Policy is "no", "on-failure" or "always".
	Policy     string `json:"policy"`
	MaxRetries int    `json:"max_retries,omitempty"`
}

// CreateMachineRequest makes a machine. The image is pulled if the host has not seen it.
type CreateMachineRequest struct {
	// Tenant owns the machine and its network; any string, a team id for briq.
	Tenant string `json:"tenant"`
	// Name is a DNS label, unique in the tenant: `<name>.internal` resolves to the machine.
	Name       string            `json:"name"`
	Image      string            `json:"image"`
	Entrypoint []string          `json:"entrypoint,omitempty"`
	Cmd        []string          `json:"cmd,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Files      []File            `json:"files,omitempty"`
	Size       Size              `json:"size"`
	Volume     *VolumeSpec       `json:"volume,omitempty"`
	Ports      []int             `json:"ports,omitempty"`
	// Sleep is how long without use before the machine stops: "30m", "2h", or "never"/"" (never).
	Sleep   string         `json:"sleep,omitempty"`
	Restart *RestartPolicy `json:"restart,omitempty"`
	// Metadata is kept and returned as is (a briq id, a stack name).
	Metadata map[string]string `json:"metadata,omitempty"`
	// Start the machine right after creating it (default true).
	Start *bool `json:"start,omitempty"`
	// Fork makes the machine's disks from a snapshot of another machine, taken now.
	Fork *ForkSpec `json:"fork,omitempty"`
}

// ForkSpec names the source of a fork.
type ForkSpec struct {
	MachineID string `json:"machine_id"`
	// Copy is "disk" (both disks, the default) or "config" (nothing: a fresh image).
	Copy string `json:"copy,omitempty"`
}

// Exit is how the main process last ended on its own.
type Exit struct {
	Code       int       `json:"code"`
	OOMKilled  bool      `json:"oom_killed"`
	At         time.Time `json:"at"`
	Restarting bool      `json:"restarting"`
}

// Machine states.
const (
	StateCreated    = "created"
	StateStarting   = "starting"
	StateRunning    = "running"
	StateStopping   = "stopping"
	StateStopped    = "stopped"
	StateDestroying = "destroying"
	StateError      = "error"
)

// Why a machine is stopped.
const (
	StopUser = "user" // asked through the API
	StopIdle = "idle" // the sleep window ran out
	StopExit = "exit" // its process ended and the restart policy let it
)

// Machine is a machine as the API returns it.
type Machine struct {
	ID            string            `json:"id"`
	Tenant        string            `json:"tenant"`
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	ImageDigest   string            `json:"image_digest,omitempty"`
	State         string            `json:"state"`
	StoppedReason string            `json:"stopped_reason,omitempty"`
	Exit          *Exit             `json:"exit,omitempty"`
	Error         string            `json:"error,omitempty"`
	IP            string            `json:"ip,omitempty"`
	Hostname      string            `json:"hostname"`
	MachineHost   string            `json:"machine_host"`
	Size          Size              `json:"size"`
	Volume        *VolumeSpec       `json:"volume,omitempty"`
	Ports         []int             `json:"ports,omitempty"`
	Sleep         string            `json:"sleep,omitempty"`
	Restart       RestartPolicy     `json:"restart"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Endpoints     []Endpoint        `json:"endpoints,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	StartedAt     *time.Time        `json:"started_at,omitempty"`
	StoppedAt     *time.Time        `json:"stopped_at,omitempty"`
	LastUsedAt    *time.Time        `json:"last_used_at,omitempty"`
	// SleepsAt is when the machine stops if nothing uses it; nil when running with no window.
	SleepsAt *time.Time `json:"sleeps_at,omitempty"`
	// Host is the briqyardd that runs it (set by the fleet).
	Host string `json:"host,omitempty"`
}

// Endpoint is a way in from outside the tenant's network.
type Endpoint struct {
	ID        string `json:"id"`
	MachineID string `json:"machine_id"`
	// Port inside the machine.
	Port int `json:"port"`
	// Protocol is "tcp" or "http".
	Protocol string `json:"protocol"`
	// HostPort is the host port a TCP endpoint listens on.
	HostPort int `json:"host_port,omitempty"`
	// Host is the HTTP endpoint's host name.
	Host string `json:"host,omitempty"`
	// Address is where to connect: "<ip>:<host_port>" or "http://<host>".
	Address   string    `json:"address"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateEndpointRequest opens a port of a machine to the outside.
type CreateEndpointRequest struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	// Host, for http endpoints: the label before the domain; random when empty.
	Host string `json:"host,omitempty"`
}

// ExecRequest runs a command inside a machine.
type ExecRequest struct {
	Cmd       []string          `json:"cmd"`
	Env       map[string]string `json:"env,omitempty"`
	Cwd       string            `json:"cwd,omitempty"`
	Stdin     string            `json:"stdin,omitempty"`
	TimeoutMs int               `json:"timeout_ms,omitempty"`
	// Wake a sleeping machine for the command (default false: 409 when not running).
	Wake bool `json:"wake,omitempty"`
}

// ExecResult is the command's output.
type ExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	TimedOut bool   `json:"timed_out"`
}

// PutFileRequest writes a file into a running machine.
type PutFileRequest struct {
	Path   string `json:"path"`
	Base64 string `json:"base64"`
	Mode   string `json:"mode,omitempty"`
}

// LogLine is one line of the serial console.
type LogLine struct {
	TS   time.Time `json:"ts"`
	Line string    `json:"line"`
}

// LogsResponse pages the console log; Next continues after the last line returned.
type LogsResponse struct {
	Lines []LogLine `json:"lines"`
	Next  string    `json:"next,omitempty"`
}

// StopRequest stops a machine.
type StopRequest struct {
	// Suspend asks for a memory snapshot instead of a stop (falls back to a stop when unsupported).
	Suspend bool `json:"suspend,omitempty"`
	// TimeoutSec is how long the process gets after SIGTERM (default 10).
	TimeoutSec int `json:"timeout_sec,omitempty"`
}

// Snapshot is a point-in-time copy of a machine's disks.
type Snapshot struct {
	ID        string    `json:"id"`
	MachineID string    `json:"machine_id"`
	CreatedAt time.Time `json:"created_at"`
}

// Host is a briqyardd as the fleet sees it.
type Host struct {
	ID       string    `json:"id"`
	URL      string    `json:"url"`
	Region   string    `json:"region,omitempty"`
	Provider string    `json:"provider,omitempty"`
	State    string    `json:"state"` // ready, draining, down, provisioning
	Capacity Capacity  `json:"capacity"`
	Used     Capacity  `json:"used"`
	Machines int       `json:"machines"`
	Tenants  []string  `json:"tenants,omitempty"`
	LastSeen time.Time `json:"last_seen"`
	Version  string    `json:"version,omitempty"`
}

// Capacity is compute the host has or uses.
type Capacity struct {
	MemoryMB int `json:"memory_mb"`
	VCPUs    int `json:"vcpus"`
}

// RegisterHostRequest is what a daemon sends the fleet on start and as heartbeats.
type RegisterHostRequest struct {
	ID       string   `json:"id"`
	URL      string   `json:"url"`
	Region   string   `json:"region,omitempty"`
	Capacity Capacity `json:"capacity"`
	Used     Capacity `json:"used"`
	Machines int      `json:"machines"`
	Tenants  []string `json:"tenants,omitempty"`
	Version  string   `json:"version,omitempty"`
}

// Status is what GET /v1/status returns.
type Status struct {
	Version  string   `json:"version"`
	HostID   string   `json:"host_id"`
	Capacity Capacity `json:"capacity"`
	Used     Capacity `json:"used"`
	Machines int      `json:"machines"`
	Running  int      `json:"running"`
}

// Error is every error response's body.
type Error struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"request_id,omitempty"`
}
