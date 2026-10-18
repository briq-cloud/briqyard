// Package fc drives Firecracker: one process per machine, configured over its Unix socket API.
package fc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client talks to one Firecracker process over its API socket.
type Client struct {
	http *http.Client
}

// NewClient makes a client for the API socket at path.
func NewClient(path string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		DisableKeepAlives: true,
	}
	return &Client{http: &http.Client{Transport: tr, Timeout: 60 * time.Second}}
}

// APIError is a non-2xx answer from Firecracker.
type APIError struct {
	Status int
	Fault  string
}

func (e *APIError) Error() string { return fmt.Sprintf("firecracker: %d %s", e.Status, e.Fault) }

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://firecracker"+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var fault struct {
			Fault string `json:"fault_message"`
		}
		_ = json.Unmarshal(data, &fault)
		if fault.Fault == "" {
			fault.Fault = string(data)
		}
		return &APIError{Status: resp.StatusCode, Fault: fault.Fault}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// BootSource is PUT /boot-source.
type BootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args,omitempty"`
	InitrdPath      string `json:"initrd_path,omitempty"`
}

// Drive is PUT /drives/{id}.
type Drive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
	// CacheType is "Unsafe" (no flush) or "Writeback" (a guest flush is a host fsync).
	CacheType string `json:"cache_type,omitempty"`
	IOEngine  string `json:"io_engine,omitempty"`
}

// NetworkInterface is PUT /network-interfaces/{id}.
type NetworkInterface struct {
	IfaceID     string `json:"iface_id"`
	HostDevName string `json:"host_dev_name"`
	GuestMAC    string `json:"guest_mac,omitempty"`
}

// Vsock is PUT /vsock.
type Vsock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

// MachineConfig is PUT /machine-config.
type MachineConfig struct {
	VCPUCount  int  `json:"vcpu_count"`
	MemSizeMiB int  `json:"mem_size_mib"`
	SMT        bool `json:"smt"`
}

// InstanceInfo is GET /.
type InstanceInfo struct {
	ID          string `json:"id"`
	State       string `json:"state"` // "Not started", "Running", "Paused"
	VMMVersion  string `json:"vmm_version"`
	AppName     string `json:"app_name"`
	Description string `json:"description,omitempty"`
}

func (c *Client) PutBootSource(ctx context.Context, b BootSource) error {
	return c.do(ctx, http.MethodPut, "/boot-source", b, nil)
}

func (c *Client) PutDrive(ctx context.Context, d Drive) error {
	return c.do(ctx, http.MethodPut, "/drives/"+d.DriveID, d, nil)
}

func (c *Client) PutNetworkInterface(ctx context.Context, n NetworkInterface) error {
	return c.do(ctx, http.MethodPut, "/network-interfaces/"+n.IfaceID, n, nil)
}

func (c *Client) PutVsock(ctx context.Context, v Vsock) error {
	return c.do(ctx, http.MethodPut, "/vsock", v, nil)
}

func (c *Client) PutMachineConfig(ctx context.Context, m MachineConfig) error {
	return c.do(ctx, http.MethodPut, "/machine-config", m, nil)
}

func (c *Client) action(ctx context.Context, t string) error {
	return c.do(ctx, http.MethodPut, "/actions", map[string]string{"action_type": t}, nil)
}

func (c *Client) InstanceStart(ctx context.Context) error { return c.action(ctx, "InstanceStart") }

// SendCtrlAltDel asks the guest to reboot (x86: through the i8042; aarch64: a power button on
// newer versions). Firecracker then exits. Unsupported combinations answer 400.
func (c *Client) SendCtrlAltDel(ctx context.Context) error { return c.action(ctx, "SendCtrlAltDel") }

func (c *Client) Pause(ctx context.Context) error {
	return c.do(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Paused"}, nil)
}

func (c *Client) Resume(ctx context.Context) error {
	return c.do(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Resumed"}, nil)
}

// SnapshotCreate writes a full snapshot (VM state and memory) of a paused machine.
func (c *Client) SnapshotCreate(ctx context.Context, statePath, memPath string) error {
	return c.do(ctx, http.MethodPut, "/snapshot/create", map[string]any{
		"snapshot_type": "Full",
		"snapshot_path": statePath,
		"mem_file_path": memPath,
	}, nil)
}

// SnapshotLoad restores a snapshot into a fresh process and resumes it. The TAP is reopened by
// name through the override, so it may have been recreated meanwhile.
func (c *Client) SnapshotLoad(ctx context.Context, statePath, memPath string, ifaceID, tap string) error {
	return c.do(ctx, http.MethodPut, "/snapshot/load", map[string]any{
		"snapshot_path": statePath,
		"mem_backend":   map[string]string{"backend_type": "File", "backend_path": memPath},
		"resume_vm":     true,
		"network_overrides": []map[string]string{
			{"iface_id": ifaceID, "host_dev_name": tap},
		},
	}, nil)
}

func (c *Client) Info(ctx context.Context) (InstanceInfo, error) {
	var i InstanceInfo
	err := c.do(ctx, http.MethodGet, "/", nil, &i)
	return i, err
}

// WaitAPI waits until the socket answers.
func (c *Client) WaitAPI(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		rctx, cancel := context.WithTimeout(ctx, time.Second)
		_, err := c.Info(rctx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("firecracker API did not answer within %s: %w", timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
