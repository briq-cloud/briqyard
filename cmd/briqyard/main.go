// briqyard is the CLI: it talks to a briqyardd or a briqyard-fleet over HTTP.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/briq-cloud/briqyard/internal/api"
	"github.com/briq-cloud/briqyard/internal/version"
)

func usage() {
	fmt.Fprint(os.Stderr, `briqyard: machines in Firecracker microVMs

  briqyard status
  briqyard machine ls [--tenant T]
  briqyard machine run --image IMG [--name N] [--tenant T] [--env K=V]... [--volume 10G:/data] [--port P]... [--vcpus 1] [--memory 512] [--sleep 30m] [--file /guest/path=local] [-- cmd...]
  briqyard machine get ID
  briqyard machine start|stop|wake|touch|rm ID
  briqyard machine exec [--wake] [--timeout 60s] ID -- cmd...
  briqyard machine logs ID [--since CURSOR] [--limit N]
  briqyard machine fork ID --name N
  briqyard machine put ID LOCAL /guest/path
  briqyard machine get-file ID /guest/path
  briqyard machine snapshot ID
  briqyard endpoint add ID PORT [--http [--host LABEL]]
  briqyard endpoint ls | rm ID
  briqyard tenant ls | rm ID
  briqyard host ls            (fleet)
  briqyard openapi

Environment: BRIQYARD_URL (default http://127.0.0.1:7420), BRIQYARD_TOKEN.
`)
}

type client struct {
	base  string
	token string
	http  *http.Client
}

func (c *client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var e api.Error
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s (%s, request %s)", e.Error, e.Code, e.RequestID)
		}
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	base := os.Getenv("BRIQYARD_URL")
	if base == "" {
		base = "http://127.0.0.1:7420"
	}
	c := &client{base: strings.TrimRight(base, "/"), token: os.Getenv("BRIQYARD_TOKEN"), http: &http.Client{Timeout: 15 * time.Minute}}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Println(version.Version)
	case "status":
		var st api.Status
		if err = c.do("GET", "/v1/status", nil, &st); err == nil {
			printJSON(st)
		}
	case "openapi":
		resp, e := http.Get(c.base + "/v1/openapi.yaml")
		if e != nil {
			err = e
			break
		}
		defer resp.Body.Close()
		_, _ = io.Copy(os.Stdout, resp.Body)
	case "machine", "m":
		err = machineCmd(c, os.Args[2:])
	case "endpoint", "ep":
		err = endpointCmd(c, os.Args[2:])
	case "tenant":
		err = tenantCmd(c, os.Args[2:])
	case "host":
		err = hostCmd(c, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func splitArgs(args []string) (flags, rest []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func machineCmd(c *client, args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("machine: missing subcommand")
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "ls":
		fs := flag.NewFlagSet("ls", flag.ExitOnError)
		tenant := fs.String("tenant", "", "tenant")
		_ = fs.Parse(args)
		var ms []api.Machine
		path := "/v1/machines"
		if *tenant != "" {
			path += "?tenant=" + *tenant
		}
		if err := c.do("GET", path, nil, &ms); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTENANT\tNAME\tIMAGE\tSTATE\tIP\tSIZE\tSLEEP\tHOST")
		for _, m := range ms {
			state := m.State
			if m.StoppedReason != "" {
				state += " (" + m.StoppedReason + ")"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%dc/%dM\t%s\t%s\n", m.ID, m.Tenant, m.Name, m.Image, state, m.IP, m.Size.VCPUs, m.Size.MemoryMB, m.Sleep, m.Host)
		}
		return tw.Flush()
	case "run":
		flags, cmd := splitArgs(args)
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		image := fs.String("image", "", "OCI image")
		name := fs.String("name", "", "name (DNS label)")
		tenant := fs.String("tenant", "default", "tenant")
		vcpus := fs.Int("vcpus", 1, "vCPUs")
		memory := fs.Int("memory", 512, "memory in MB")
		sleep := fs.String("sleep", "", "sleep window (30m, 2h, never)")
		volume := fs.String("volume", "", "data volume, SIZE:MOUNT (10G:/data)")
		noStart := fs.Bool("no-start", false, "create without starting")
		var envs, ports, files, entrypoint multi
		fs.Var(&envs, "env", "K=V")
		fs.Var(&ports, "port", "port the image listens on")
		fs.Var(&files, "file", "/guest/path=local/path")
		fs.Var(&entrypoint, "entrypoint", "entrypoint argv (repeat)")
		_ = fs.Parse(flags)
		if *image == "" {
			return errors.New("--image is required")
		}
		req := api.CreateMachineRequest{Tenant: *tenant, Name: *name, Image: *image, Size: api.Size{VCPUs: *vcpus, MemoryMB: *memory}, Sleep: *sleep, Env: map[string]string{}, Cmd: cmd}
		if *name == "" {
			base := (*image)[strings.LastIndex(*image, "/")+1:]
			base, _, _ = strings.Cut(base, ":")
			base, _, _ = strings.Cut(base, "@")
			req.Name = base + "-" + strconv.FormatInt(time.Now().UnixNano()%10000, 10)
		}
		if len(entrypoint) > 0 {
			req.Entrypoint = entrypoint
		}
		for _, kv := range envs {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("--env %q: want K=V", kv)
			}
			req.Env[k] = v
		}
		for _, p := range ports {
			n, err := strconv.Atoi(p)
			if err != nil {
				return fmt.Errorf("--port %q", p)
			}
			req.Ports = append(req.Ports, n)
		}
		for _, f := range files {
			guestPath, local, ok := strings.Cut(f, "=")
			if !ok {
				return fmt.Errorf("--file %q: want /guest/path=local/path", f)
			}
			data, err := os.ReadFile(local)
			if err != nil {
				return err
			}
			req.Files = append(req.Files, api.File{Path: guestPath, Base64: base64.StdEncoding.EncodeToString(data)})
		}
		if *volume != "" {
			size, mount, ok := strings.Cut(*volume, ":")
			gb, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSuffix(size, "G"), "GB"))
			if !ok || err != nil {
				return fmt.Errorf("--volume %q: want SIZE:MOUNT, like 10G:/data", *volume)
			}
			req.Volume = &api.VolumeSpec{SizeGB: gb, Mount: mount}
		}
		if *noStart {
			f := false
			req.Start = &f
		}
		var m api.Machine
		if err := c.do("POST", "/v1/machines", req, &m); err != nil {
			return err
		}
		printJSON(m)
		if m.State == api.StateError {
			return errors.New(m.Error)
		}
		return nil
	case "get":
		var m api.Machine
		if err := c.do("GET", "/v1/machines/"+need(args, 0), nil, &m); err != nil {
			return err
		}
		printJSON(m)
		return nil
	case "start", "stop", "wake", "touch":
		var m api.Machine
		if err := c.do("POST", "/v1/machines/"+need(args, 0)+"/"+sub, nil, &m); err != nil {
			return err
		}
		if sub != "touch" {
			printJSON(m)
		}
		return nil
	case "rm", "destroy":
		return c.do("DELETE", "/v1/machines/"+need(args, 0), nil, nil)
	case "exec":
		flags, cmd := splitArgs(args)
		fs := flag.NewFlagSet("exec", flag.ExitOnError)
		wake := fs.Bool("wake", false, "wake a sleeping machine")
		timeout := fs.Duration("timeout", 5*time.Minute, "timeout")
		stdin := fs.Bool("stdin", false, "send stdin")
		_ = fs.Parse(flags)
		id := need(fs.Args(), 0)
		if len(cmd) == 0 {
			return errors.New("exec: give the command after --")
		}
		req := api.ExecRequest{Cmd: cmd, Wake: *wake, TimeoutMs: int(timeout.Milliseconds())}
		if *stdin {
			data, _ := io.ReadAll(os.Stdin)
			req.Stdin = string(data)
		}
		var res api.ExecResult
		if err := c.do("POST", "/v1/machines/"+id+"/exec", req, &res); err != nil {
			return err
		}
		os.Stdout.WriteString(res.Stdout)
		os.Stderr.WriteString(res.Stderr)
		if res.TimedOut {
			fmt.Fprintln(os.Stderr, "(timed out)")
		}
		if res.ExitCode != 0 {
			os.Exit(res.ExitCode)
		}
		return nil
	case "logs":
		fs := flag.NewFlagSet("logs", flag.ExitOnError)
		since := fs.String("since", "", "cursor")
		limit := fs.Int("limit", 500, "lines")
		follow := fs.Bool("f", false, "follow")
		_ = fs.Parse(args)
		id := need(fs.Args(), 0)
		cursor := *since
		for {
			var res api.LogsResponse
			if err := c.do("GET", fmt.Sprintf("/v1/machines/%s/logs?since=%s&limit=%d", id, cursor, *limit), nil, &res); err != nil {
				return err
			}
			for _, l := range res.Lines {
				fmt.Printf("%s %s\n", l.TS.Local().Format("15:04:05.000"), l.Line)
			}
			if !*follow {
				if res.Next != "" {
					fmt.Fprintf(os.Stderr, "(next: --since %s)\n", res.Next)
				}
				return nil
			}
			if res.Next != "" {
				cursor = res.Next
			}
			time.Sleep(time.Second)
		}
	case "fork":
		fs := flag.NewFlagSet("fork", flag.ExitOnError)
		name := fs.String("name", "", "name of the fork")
		_ = fs.Parse(args)
		id := need(fs.Args(), 0)
		var src api.Machine
		if err := c.do("GET", "/v1/machines/"+id, nil, &src); err != nil {
			return err
		}
		if *name == "" {
			*name = src.Name + "-fork"
		}
		req := api.CreateMachineRequest{Tenant: src.Tenant, Name: *name, Size: src.Size, Ports: src.Ports, Sleep: src.Sleep, Metadata: src.Metadata, Fork: &api.ForkSpec{MachineID: id}}
		var m api.Machine
		if err := c.do("POST", "/v1/machines", req, &m); err != nil {
			return err
		}
		printJSON(m)
		return nil
	case "put":
		id, local, guestPath := need(args, 0), need(args, 1), need(args, 2)
		data, err := os.ReadFile(local)
		if err != nil {
			return err
		}
		return c.do("PUT", "/v1/machines/"+id+"/files", api.PutFileRequest{Path: guestPath, Base64: base64.StdEncoding.EncodeToString(data)}, nil)
	case "get-file":
		id, guestPath := need(args, 0), need(args, 1)
		var res struct {
			Base64 string `json:"base64"`
		}
		if err := c.do("GET", "/v1/machines/"+id+"/files?path="+guestPath, nil, &res); err != nil {
			return err
		}
		data, err := base64.StdEncoding.DecodeString(res.Base64)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
		return err
	case "snapshot":
		var s api.Snapshot
		if err := c.do("POST", "/v1/machines/"+need(args, 0)+"/snapshots", nil, &s); err != nil {
			return err
		}
		printJSON(s)
		return nil
	case "wait":
		var m api.Machine
		if err := c.do("POST", "/v1/machines/"+need(args, 0)+"/wait?timeout=120", nil, &m); err != nil {
			return err
		}
		printJSON(m)
		return nil
	}
	usage()
	return fmt.Errorf("machine: unknown subcommand %q", sub)
}

func endpointCmd(c *client, args []string) error {
	if len(args) == 0 {
		return errors.New("endpoint: missing subcommand")
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("add", flag.ExitOnError)
		httpEp := fs.Bool("http", false, "an HTTP endpoint on the shared listener")
		host := fs.String("host", "", "host label for an HTTP endpoint")
		_ = fs.Parse(args[1:])
		id := need(fs.Args(), 0)
		port, err := strconv.Atoi(need(fs.Args(), 1))
		if err != nil {
			return errors.New("endpoint add: PORT must be a number")
		}
		req := api.CreateEndpointRequest{Port: port, Host: *host}
		if *httpEp {
			req.Protocol = "http"
		}
		var ep api.Endpoint
		if err := c.do("POST", "/v1/machines/"+id+"/endpoints", req, &ep); err != nil {
			return err
		}
		printJSON(ep)
		return nil
	case "ls":
		var eps []api.Endpoint
		if err := c.do("GET", "/v1/endpoints", nil, &eps); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tMACHINE\tPORT\tPROTOCOL\tADDRESS")
		for _, e := range eps {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", e.ID, e.MachineID, e.Port, e.Protocol, e.Address)
		}
		return tw.Flush()
	case "rm":
		return c.do("DELETE", "/v1/endpoints/"+need(args, 1), nil, nil)
	}
	return fmt.Errorf("endpoint: unknown subcommand %q", args[0])
}

func tenantCmd(c *client, args []string) error {
	if len(args) == 0 {
		return errors.New("tenant: missing subcommand")
	}
	switch args[0] {
	case "ls":
		var ts []map[string]any
		if err := c.do("GET", "/v1/tenants", nil, &ts); err != nil {
			return err
		}
		printJSON(ts)
		return nil
	case "rm":
		return c.do("DELETE", "/v1/tenants/"+need(args, 1), nil, nil)
	}
	return fmt.Errorf("tenant: unknown subcommand %q", args[0])
}

func hostCmd(c *client, args []string) error {
	if len(args) == 0 || args[0] != "ls" {
		return errors.New("host: ls")
	}
	var hs []api.Host
	if err := c.do("GET", "/v1/hosts", nil, &hs); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tURL\tSTATE\tMEMORY (used/MB)\tVCPUS\tMACHINES\tTENANTS\tLAST SEEN")
	for _, h := range hs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d/%d\t%d/%d\t%d\t%d\t%s\n", h.ID, h.URL, h.State, h.Used.MemoryMB, h.Capacity.MemoryMB, h.Used.VCPUs, h.Capacity.VCPUs, h.Machines, len(h.Tenants), h.LastSeen.Local().Format(time.RFC3339))
	}
	return tw.Flush()
}

func need(args []string, i int) string {
	if i >= len(args) {
		usage()
		fmt.Fprintln(os.Stderr, "error: missing argument")
		os.Exit(2)
	}
	return args[i]
}

var _ = context.Background
