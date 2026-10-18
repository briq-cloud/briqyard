// Package fleet is briqyard across several hosts: the registry of hosts, placement of tenants,
// the proxying API, and the provisioners that add and release hosts.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/briq-cloud/briqyard/internal/api"
	"github.com/briq-cloud/briqyard/internal/machine"
	"github.com/briq-cloud/briqyard/internal/version"
)

// HostReporter is what a daemon tells the fleet about itself.
type HostReporter interface {
	Usage() (used api.Capacity, running, total int)
	Capacity() api.Capacity
	Tenants() []machine.Tenant
}

// Heartbeat registers a daemon with the fleet and keeps the registration fresh.
type Heartbeat struct {
	URL       string
	Token     string
	Advertise string
	HostID    string
	Region    string
	Machines  HostReporter
	Log       *slog.Logger
	Interval  time.Duration
}

// Run sends heartbeats until ctx ends.
func (h *Heartbeat) Run(ctx context.Context) {
	if h.Interval == 0 {
		h.Interval = 15 * time.Second
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for {
		if err := h.send(ctx, client); err != nil {
			h.Log.Warn("fleet heartbeat", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(h.Interval):
		}
	}
}

func (h *Heartbeat) send(ctx context.Context, client *http.Client) error {
	used, _, total := h.Machines.Usage()
	var tenants []string
	for _, t := range h.Machines.Tenants() {
		tenants = append(tenants, t.ID)
	}
	req := api.RegisterHostRequest{ID: h.HostID, URL: h.Advertise, Region: h.Region, Capacity: h.Machines.Capacity(), Used: used, Machines: total, Tenants: tenants, Version: version.Version}
	body, _ := json.Marshal(req)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL+"/v1/hosts/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	if h.Token != "" {
		r.Header.Set("Authorization", "Bearer "+h.Token)
	}
	resp, err := client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("fleet answered %d", resp.StatusCode)
	}
	return nil
}
