// Package guest is what the host and briqyard-init agree on: the config drive the init reads at
// boot, and the vsock protocol the host uses to run commands and move files.
package guest

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Port is the vsock port briqyard-init listens on.
const Port = 7421

// MaxFrame bounds one frame; bigger payloads are sent as several frames.
const MaxFrame = 4 << 20

// ConfigName is the entry of the config drive that holds Config.
const ConfigName = "config.json"

// FilesPrefix is the directory of the config drive that holds boot files, under their guest path.
const FilesPrefix = "files/"

// Config is what the init reads from the config drive at every boot.
type Config struct {
	Hostname string `json:"hostname"`
	// IP in CIDR notation, on eth0.
	IP      string   `json:"ip"`
	Gateway string   `json:"gateway"`
	DNS     []string `json:"dns"`
	// Hosts are extra /etc/hosts lines (name → address), for the machine's own names.
	Hosts map[string]string `json:"hosts,omitempty"`
	// Entrypoint and Cmd, already resolved against the image's config.
	Entrypoint []string          `json:"entrypoint"`
	Cmd        []string          `json:"cmd"`
	Env        map[string]string `json:"env"`
	WorkDir    string            `json:"workdir"`
	// User is "name", "uid", "name:group" or "uid:gid", as in an OCI config; empty is root.
	User   string  `json:"user"`
	Mounts []Mount `json:"mounts"`
	// Files lists the boot files present under FilesPrefix, with their modes.
	Files []FileMeta `json:"files"`
	// StopTimeoutSec is how long the main process gets after SIGTERM before SIGKILL.
	StopTimeoutSec int `json:"stop_timeout_sec"`
}

type Mount struct {
	Device string `json:"device"`
	Path   string `json:"path"`
	FSType string `json:"fstype"`
}

type FileMeta struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
}

// Request is one operation over one vsock connection.
type Request struct {
	Op string `json:"op"` // exec, put, get, ping, shutdown
	// exec
	Cmd       []string          `json:"cmd,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Cwd       string            `json:"cwd,omitempty"`
	Stdin     []byte            `json:"stdin,omitempty"`
	TimeoutMs int               `json:"timeout_ms,omitempty"`
	// put, get
	Path string `json:"path,omitempty"`
	Mode uint32 `json:"mode,omitempty"`
	Data []byte `json:"data,omitempty"`
	// shutdown
	GraceSec int `json:"grace_sec,omitempty"`
}

// Response frames stream back: stdout and stderr chunks, then exit; or ok, file, pong, error.
type Response struct {
	Type     string `json:"type"` // stdout, stderr, exit, ok, file, pong, error
	Data     []byte `json:"data,omitempty"`
	Code     int    `json:"code,omitempty"`
	TimedOut bool   `json:"timed_out,omitempty"`
	Message  string `json:"message,omitempty"`
	// pong
	Uptime float64 `json:"uptime,omitempty"`
	Main   int     `json:"main_pid,omitempty"`
}

// WriteFrame writes one length-prefixed JSON frame.
func WriteFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		return fmt.Errorf("frame of %d bytes exceeds %d", len(b), MaxFrame)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ReadFrame reads one frame into v.
func ReadFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return fmt.Errorf("frame of %d bytes exceeds %d", n, MaxFrame)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ErrClosed is returned by a stream reader when the connection ended before an exit frame.
var ErrClosed = errors.New("guest connection closed before the command ended")
