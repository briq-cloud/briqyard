// Package apiserver is briqyardd's HTTP API server over the machine manager.
package apiserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/briq-cloud/briqyard/internal/api"
	"github.com/briq-cloud/briqyard/internal/machine"
	"github.com/briq-cloud/briqyard/internal/version"
)

// Machines is what the server needs from the machine manager.
type Machines interface {
	Create(ctx context.Context, req api.CreateMachineRequest) (api.Machine, error)
	Get(id string) (api.Machine, error)
	List(tenant string) []api.Machine
	Start(ctx context.Context, id string) (api.Machine, error)
	Wake(ctx context.Context, id string) (api.Machine, error)
	Stop(ctx context.Context, id string, timeout time.Duration) (api.Machine, error)
	Destroy(ctx context.Context, id string) error
	Touch(id string) error
	WaitRunning(ctx context.Context, id string) error
	Exec(ctx context.Context, id string, req api.ExecRequest) (api.ExecResult, error)
	PutFile(ctx context.Context, id string, req api.PutFileRequest) error
	GetFile(ctx context.Context, id, path string) ([]byte, error)
	Logs(id, since string, limit int) (api.LogsResponse, error)
	Snapshot(ctx context.Context, id string) (api.Snapshot, error)
	Snapshots(ctx context.Context, id string) ([]api.Snapshot, error)
	CreateEndpoint(machineID string, req api.CreateEndpointRequest) (api.Endpoint, error)
	DeleteEndpoint(id string) error
	Endpoint(id string) (machine.Endpoint, bool)
	EndpointView(e machine.Endpoint) api.Endpoint
	AllEndpoints() []machine.Endpoint
	Tenants() []machine.Tenant
	DeleteTenant(ctx context.Context, id string) error
	Usage() (used api.Capacity, running, total int)
	Capacity() api.Capacity
}

// Server is the HTTP API.
type Server struct {
	Machines Machines
	Token    string
	HostID   string
	Log      *slog.Logger
	// OpenAPI is served at /v1/openapi.yaml.
	OpenAPI []byte
}

// Handler builds the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /v1/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(s.OpenAPI)
	})
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("GET /v1/machines", s.listMachines)
	mux.HandleFunc("POST /v1/machines", s.createMachine)
	mux.HandleFunc("GET /v1/machines/{id}", s.getMachine)
	mux.HandleFunc("DELETE /v1/machines/{id}", s.destroyMachine)
	mux.HandleFunc("POST /v1/machines/{id}/start", s.startMachine)
	mux.HandleFunc("POST /v1/machines/{id}/wake", s.wakeMachine)
	mux.HandleFunc("POST /v1/machines/{id}/stop", s.stopMachine)
	mux.HandleFunc("POST /v1/machines/{id}/touch", s.touchMachine)
	mux.HandleFunc("POST /v1/machines/{id}/wait", s.waitMachine)
	mux.HandleFunc("POST /v1/machines/{id}/exec", s.exec)
	mux.HandleFunc("PUT /v1/machines/{id}/files", s.putFile)
	mux.HandleFunc("GET /v1/machines/{id}/files", s.getFile)
	mux.HandleFunc("GET /v1/machines/{id}/logs", s.logs)
	mux.HandleFunc("POST /v1/machines/{id}/snapshots", s.snapshot)
	mux.HandleFunc("GET /v1/machines/{id}/snapshots", s.snapshots)
	mux.HandleFunc("POST /v1/machines/{id}/endpoints", s.createEndpoint)
	mux.HandleFunc("GET /v1/endpoints", s.listEndpoints)
	mux.HandleFunc("GET /v1/endpoints/{id}", s.getEndpoint)
	mux.HandleFunc("DELETE /v1/endpoints/{id}", s.deleteEndpoint)
	mux.HandleFunc("GET /v1/tenants", s.listTenants)
	mux.HandleFunc("DELETE /v1/tenants/{id}", s.deleteTenant)
	return s.middleware(mux)
}

type ctxKey int

const requestIDKey ctxKey = 1

// RequestID of the request, for logs and error bodies.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			var b [8]byte
			_, _ = rand.Read(b[:])
			id = hex.EncodeToString(b[:])
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		r = r.WithContext(ctx)
		if s.Token != "" && r.URL.Path != "/healthz" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
				writeError(w, r, http.StatusUnauthorized, "unauthorized", "a bearer token is required")
				return
			}
		}
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		if r.URL.Path != "/healthz" {
			s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rw.status, "ms", time.Since(start).Milliseconds(), "request_id", id)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeJSON(w, status, api.Error{Error: msg, Code: code, RequestID: RequestID(r.Context())})
}

// fail maps the manager's errors to statuses.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, machine.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, machine.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "invalid", err.Error())
	case errors.Is(err, machine.ErrConflict):
		writeError(w, r, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, machine.ErrNotRunning):
		writeError(w, r, http.StatusConflict, "not_running", err.Error())
	case errors.Is(err, machine.ErrBadState):
		writeError(w, r, http.StatusConflict, "bad_state", err.Error())
	case errors.Is(err, machine.ErrCapacity):
		writeError(w, r, http.StatusServiceUnavailable, "capacity", err.Error())
	case errors.Is(err, machine.ErrTenantInUse):
		writeError(w, r, http.StatusConflict, "tenant_in_use", err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, r, http.StatusGatewayTimeout, "timeout", err.Error())
	default:
		s.Log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err, "request_id", RequestID(r.Context()))
		writeError(w, r, http.StatusInternalServerError, "internal", err.Error())
	}
}

func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: body: %v", machine.ErrInvalid, err)
	}
	return nil
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	used, running, total := s.Machines.Usage()
	writeJSON(w, 200, api.Status{Version: version.Version, HostID: s.HostID, Capacity: s.Machines.Capacity(), Used: used, Machines: total, Running: running})
}

func (s *Server) listMachines(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.Machines.List(r.URL.Query().Get("tenant")))
}

func (s *Server) createMachine(w http.ResponseWriter, r *http.Request) {
	var req api.CreateMachineRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.Machines.Create(r.Context(), req)
	if err != nil {
		if m.ID != "" {
			// Created but did not start: the caller gets the machine with its error.
			writeJSON(w, http.StatusCreated, m)
			return
		}
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (s *Server) getMachine(w http.ResponseWriter, r *http.Request) {
	m, err := s.Machines.Get(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, m)
}

func (s *Server) destroyMachine(w http.ResponseWriter, r *http.Request) {
	if err := s.Machines.Destroy(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) startMachine(w http.ResponseWriter, r *http.Request) {
	m, err := s.Machines.Start(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, m)
}

func (s *Server) wakeMachine(w http.ResponseWriter, r *http.Request) {
	m, err := s.Machines.Wake(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, m)
}

func (s *Server) stopMachine(w http.ResponseWriter, r *http.Request) {
	var req api.StopRequest
	if r.ContentLength != 0 {
		if err := decode(r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	m, err := s.Machines.Stop(r.Context(), r.PathValue("id"), time.Duration(req.TimeoutSec)*time.Second)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, m)
}

func (s *Server) touchMachine(w http.ResponseWriter, r *http.Request) {
	if err := s.Machines.Touch(r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) waitMachine(w http.ResponseWriter, r *http.Request) {
	timeout := 60 * time.Second
	if t := r.URL.Query().Get("timeout"); t != "" {
		if n, err := strconv.Atoi(t); err == nil && n > 0 && n <= 600 {
			timeout = time.Duration(n) * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	if err := s.Machines.WaitRunning(ctx, r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	m, _ := s.Machines.Get(r.PathValue("id"))
	writeJSON(w, 200, m)
}

func (s *Server) exec(w http.ResponseWriter, r *http.Request) {
	var req api.ExecRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.Cmd) == 0 {
		s.fail(w, r, machine.Invalid("cmd is required"))
		return
	}
	res, err := s.Machines.Exec(r.Context(), r.PathValue("id"), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) putFile(w http.ResponseWriter, r *http.Request) {
	var req api.PutFileRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Machines.PutFile(r.Context(), r.PathValue("id"), req); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		s.fail(w, r, machine.Invalid("path is required"))
		return
	}
	data, err := s.Machines.GetFile(r.Context(), r.PathValue("id"), path)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"path": path, "base64": base64.StdEncoding.EncodeToString(data)})
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	res, err := s.Machines.Logs(r.PathValue("id"), r.URL.Query().Get("since"), limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if res.Lines == nil {
		res.Lines = []api.LogLine{}
	}
	writeJSON(w, 200, res)
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Machines.Snapshot(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, snap)
}

func (s *Server) snapshots(w http.ResponseWriter, r *http.Request) {
	snaps, err := s.Machines.Snapshots(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if snaps == nil {
		snaps = []api.Snapshot{}
	}
	writeJSON(w, 200, snaps)
}

func (s *Server) createEndpoint(w http.ResponseWriter, r *http.Request) {
	var req api.CreateEndpointRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ep, err := s.Machines.CreateEndpoint(r.PathValue("id"), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, ep)
}

func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) {
	all := s.Machines.AllEndpoints()
	out := make([]api.Endpoint, 0, len(all))
	for _, e := range all {
		out = append(out, s.Machines.EndpointView(e))
	}
	writeJSON(w, 200, out)
}

func (s *Server) getEndpoint(w http.ResponseWriter, r *http.Request) {
	ep, ok := s.Machines.Endpoint(r.PathValue("id"))
	if !ok {
		writeError(w, r, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	writeJSON(w, 200, s.Machines.EndpointView(ep))
}

func (s *Server) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	if err := s.Machines.DeleteEndpoint(r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	ts := s.Machines.Tenants()
	if ts == nil {
		ts = []machine.Tenant{}
	}
	writeJSON(w, 200, ts)
}

func (s *Server) deleteTenant(w http.ResponseWriter, r *http.Request) {
	if err := s.Machines.DeleteTenant(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
