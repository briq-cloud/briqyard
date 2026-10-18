//go:build linux

// briqyard-init is PID 1 inside every machine. It prepares the guest from the config drive,
// runs the image's command, serves the host over vsock, and halts when the command ends.
package main

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/briq-cloud/briqyard/internal/guest"
)

const (
	configDevice = "/dev/vdb"
	logPrefix    = "[briqyard] "
)

var console *os.File

func logf(format string, args ...any) {
	msg := logPrefix + fmt.Sprintf(format, args...) + "\n"
	if console != nil {
		_, _ = console.WriteString(msg)
	} else {
		_, _ = os.Stderr.WriteString(msg)
	}
}

type state struct {
	cfg       guest.Config
	env       []string
	mu        sync.Mutex
	main      *os.Process
	mainDone  chan struct{}
	exitCode  int
	oom       bool
	requested bool
}

func main() {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "briqyard-init must run as PID 1")
		os.Exit(2)
	}
	mountBase()
	console, _ = os.OpenFile("/dev/console", os.O_WRONLY, 0)
	st := &state{mainDone: make(chan struct{})}
	code := run(st)
	logf("exit code=%d oom=%v requested=%v", code, st.oom, st.requested)
	halt()
}

func run(st *state) int {
	cfg, files, err := readConfigDrive()
	if err != nil {
		logf("config drive: %v", err)
		return 125
	}
	st.cfg = cfg
	if err := setupMounts(cfg); err != nil {
		logf("mounts: %v", err)
		return 125
	}
	if err := writeFiles(cfg, files); err != nil {
		logf("boot files: %v", err)
		return 125
	}
	setupNames(cfg)
	if err := setupNetwork(cfg); err != nil {
		logf("network: %v", err)
	}
	st.env = buildEnv(cfg.Env)
	go serve(st)
	cmd, err := mainCommand(cfg, st.env)
	if err != nil {
		logf("command: %v", err)
		return 126
	}
	if err := cmd.Start(); err != nil {
		logf("start %v: %v", cmd.Args, err)
		return 127
	}
	st.mu.Lock()
	st.main = cmd.Process
	st.mu.Unlock()
	logf("started pid=%d %s", cmd.Process.Pid, strings.Join(cmd.Args, " "))
	code := reap(cmd.Process.Pid)
	st.mu.Lock()
	st.main = nil
	st.exitCode = code
	st.oom = code == 137 && sawOOM()
	st.mu.Unlock()
	close(st.mainDone)
	return code
}

// mountBase mounts the pseudo filesystems PID 1 needs before anything else.
func mountBase() {
	mounts := []struct {
		src, dst, fstype, data string
		flags                  uintptr
	}{
		{"proc", "/proc", "proc", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
		{"sysfs", "/sys", "sysfs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
		{"devtmpfs", "/dev", "devtmpfs", "mode=0755", unix.MS_NOSUID},
		{"tmpfs", "/run", "tmpfs", "mode=0755", unix.MS_NOSUID | unix.MS_NODEV},
		{"tmpfs", "/tmp", "tmpfs", "mode=1777", unix.MS_NOSUID | unix.MS_NODEV},
	}
	for _, m := range mounts {
		_ = os.MkdirAll(m.dst, 0o755)
		_ = unix.Mount(m.src, m.dst, m.fstype, m.flags, m.data)
	}
	_ = os.MkdirAll("/dev/pts", 0o755)
	_ = unix.Mount("devpts", "/dev/pts", "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=0620,gid=5,ptmxmode=666")
	_ = os.MkdirAll("/dev/shm", 0o1777)
	_ = unix.Mount("tmpfs", "/dev/shm", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=1777")
	_ = os.MkdirAll("/sys/fs/cgroup", 0o755)
	_ = unix.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, "")
	_ = os.MkdirAll("/dev/mqueue", 0o755)
	_ = unix.Mount("mqueue", "/dev/mqueue", "mqueue", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, "")
	// Linux wants PID 1 to be the subreaper of everything; it is, by being PID 1.
	_ = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}

type bootFile struct {
	meta guest.FileMeta
	data []byte
}

// readConfigDrive reads the raw tar on the config device.
func readConfigDrive() (guest.Config, []bootFile, error) {
	var cfg guest.Config
	f, err := os.Open(configDevice)
	if err != nil {
		return cfg, nil, err
	}
	defer f.Close()
	tr := tar.NewReader(bufio.NewReaderSize(f, 1<<20))
	var files []bootFile
	modes := map[string]uint32{}
	haveConfig := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return cfg, nil, err
		}
		switch {
		case hdr.Name == guest.ConfigName:
			if err := json.NewDecoder(tr).Decode(&cfg); err != nil {
				return cfg, nil, fmt.Errorf("config.json: %w", err)
			}
			haveConfig = true
			for _, fm := range cfg.Files {
				modes[fm.Path] = fm.Mode
			}
		case strings.HasPrefix(hdr.Name, guest.FilesPrefix) && hdr.Typeflag == tar.TypeReg:
			data, err := io.ReadAll(tr)
			if err != nil {
				return cfg, nil, err
			}
			p := "/" + strings.TrimPrefix(hdr.Name, guest.FilesPrefix)
			files = append(files, bootFile{meta: guest.FileMeta{Path: p, Mode: uint32(hdr.Mode)}, data: data})
		}
	}
	if !haveConfig {
		return cfg, nil, errors.New("no config.json on the config drive")
	}
	for i := range files {
		if m, ok := modes[files[i].meta.Path]; ok && m != 0 {
			files[i].meta.Mode = m
		}
	}
	return cfg, files, nil
}

// setupMounts mounts the data volumes, giving a fresh one the image directory's owner and
// content, as Docker does for a named volume.
func setupMounts(cfg guest.Config) error {
	for _, m := range cfg.Mounts {
		var st unix.Stat_t
		had := unix.Stat(m.Path, &st) == nil
		if err := os.MkdirAll(m.Path, 0o755); err != nil {
			return err
		}
		staging := ""
		if had {
			// Keep the image's content to seed an empty volume.
			staging = m.Path + ".briqyard-seed"
			_ = os.Rename(m.Path, staging)
			if err := os.MkdirAll(m.Path, 0o755); err != nil {
				return err
			}
		}
		fstype := m.FSType
		if fstype == "" {
			fstype = "ext4"
		}
		if err := unix.Mount(m.Device, m.Path, fstype, unix.MS_NOATIME, ""); err != nil {
			return fmt.Errorf("mount %s on %s: %w", m.Device, m.Path, err)
		}
		if isEmptyVolume(m.Path) {
			if had {
				_ = os.Chown(m.Path, int(st.Uid), int(st.Gid))
				_ = os.Chmod(m.Path, os.FileMode(st.Mode)&os.ModePerm)
				if staging != "" {
					_ = copyTree(staging, m.Path)
				}
			}
		}
		if staging != "" {
			_ = os.RemoveAll(staging)
		}
	}
	return nil
}

func isEmptyVolume(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() != "lost+found" {
			return false
		}
	}
	return true
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		var st unix.Stat_t
		_ = unix.Lstat(p, &st)
		switch {
		case d.IsDir():
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return err
			}
			_ = os.Lchown(target, int(st.Uid), int(st.Gid))
		case info.Mode()&os.ModeSymlink != 0:
			l, err := os.Readlink(p)
			if err != nil {
				return err
			}
			_ = os.Symlink(l, target)
			_ = os.Lchown(target, int(st.Uid), int(st.Gid))
		case info.Mode().IsRegular():
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
			if err != nil {
				return err
			}
			_, err = io.Copy(out, in)
			out.Close()
			_ = os.Lchown(target, int(st.Uid), int(st.Gid))
			return err
		}
		return nil
	})
}

func writeFiles(cfg guest.Config, files []bootFile) error {
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.meta.Path), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(f.meta.Mode) & os.ModePerm
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(f.meta.Path, f.data, mode); err != nil {
			return fmt.Errorf("%s: %w", f.meta.Path, err)
		}
		_ = os.Chmod(f.meta.Path, mode)
	}
	return nil
}

func setupNames(cfg guest.Config) {
	if cfg.Hostname != "" {
		_ = unix.Sethostname([]byte(cfg.Hostname))
		_ = os.WriteFile("/etc/hostname", []byte(cfg.Hostname+"\n"), 0o644)
	}
	var hosts strings.Builder
	hosts.WriteString("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n")
	if ip, _, ok := strings.Cut(cfg.IP, "/"); ok && cfg.Hostname != "" {
		fmt.Fprintf(&hosts, "%s\t%s\n", ip, cfg.Hostname)
	}
	for name, addr := range cfg.Hosts {
		fmt.Fprintf(&hosts, "%s\t%s\n", addr, name)
	}
	_ = os.WriteFile("/etc/hosts", []byte(hosts.String()), 0o644)
	var resolv strings.Builder
	for _, d := range cfg.DNS {
		fmt.Fprintf(&resolv, "nameserver %s\n", d)
	}
	resolv.WriteString("search internal\noptions ndots:1\n")
	_ = os.WriteFile("/etc/resolv.conf", []byte(resolv.String()), 0o644)
}

func setupNetwork(cfg guest.Config) error {
	if lo, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(lo)
	}
	if cfg.IP == "" {
		return nil
	}
	var eth netlink.Link
	var err error
	for i := 0; i < 50; i++ {
		eth, err = netlink.LinkByName("eth0")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("eth0: %w", err)
	}
	addr, err := netlink.ParseAddr(cfg.IP)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(eth, addr); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("address: %w", err)
	}
	if err := netlink.LinkSetUp(eth); err != nil {
		return err
	}
	if cfg.Gateway != "" {
		gw := net.ParseIP(cfg.Gateway)
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: gw}); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("default route: %w", err)
		}
	}
	return nil
}

func buildEnv(env map[string]string) []string {
	if _, ok := env["PATH"]; !ok {
		env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	if _, ok := env["HOME"]; !ok {
		env["HOME"] = "/root"
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func mainCommand(cfg guest.Config, env []string) (*exec.Cmd, error) {
	argv := append(append([]string{}, cfg.Entrypoint...), cfg.Cmd...)
	if len(argv) == 0 {
		return nil, errors.New("the image has no entrypoint or command")
	}
	path, err := lookPath(argv[0], env)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Env = env
	cmd.Dir = cfg.WorkDir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.Stdin = nil
	cmd.Stdout = console
	cmd.Stderr = console
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if cfg.User != "" {
		uid, gid, home, err := lookupUser(cfg.User)
		if err != nil {
			return nil, err
		}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid, Groups: supplementaryGroups(uid)}
		if home != "" {
			cmd.Env = append(cmd.Env, "HOME="+home)
		}
	}
	return cmd, nil
}

func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	path := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			path = kv[5:]
		}
	}
	for _, dir := range strings.Split(path, ":") {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in PATH", name)
}

// lookupUser resolves "name", "uid", "name:group" or "uid:gid" through /etc/passwd and /etc/group.
func lookupUser(spec string) (uid, gid uint32, home string, err error) {
	userPart, groupPart, _ := strings.Cut(spec, ":")
	passwd := readTable("/etc/passwd")
	groups := readTable("/etc/group")
	found := false
	for _, row := range passwd {
		if len(row) < 7 {
			continue
		}
		if row[0] == userPart || row[2] == userPart {
			u, _ := strconv.Atoi(row[2])
			g, _ := strconv.Atoi(row[3])
			uid, gid, home, found = uint32(u), uint32(g), row[5], true
			break
		}
	}
	if !found {
		n, convErr := strconv.Atoi(userPart)
		if convErr != nil {
			return 0, 0, "", fmt.Errorf("user %q not found", userPart)
		}
		uid, gid = uint32(n), uint32(n)
	}
	if groupPart != "" {
		gfound := false
		for _, row := range groups {
			if len(row) >= 3 && (row[0] == groupPart || row[2] == groupPart) {
				g, _ := strconv.Atoi(row[2])
				gid, gfound = uint32(g), true
				break
			}
		}
		if !gfound {
			n, convErr := strconv.Atoi(groupPart)
			if convErr != nil {
				return 0, 0, "", fmt.Errorf("group %q not found", groupPart)
			}
			gid = uint32(n)
		}
	}
	return uid, gid, home, nil
}

func supplementaryGroups(uid uint32) []uint32 {
	name := ""
	for _, row := range readTable("/etc/passwd") {
		if len(row) >= 3 && row[2] == strconv.Itoa(int(uid)) {
			name = row[0]
		}
	}
	if name == "" {
		return nil
	}
	var out []uint32
	for _, row := range readTable("/etc/group") {
		if len(row) < 4 {
			continue
		}
		for _, m := range strings.Split(row[3], ",") {
			if m == name {
				g, _ := strconv.Atoi(row[2])
				out = append(out, uint32(g))
			}
		}
	}
	return out
}

func readTable(path string) [][]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var rows [][]string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rows = append(rows, strings.Split(line, ":"))
	}
	return rows
}

// reap waits for children as PID 1 must, and returns the main process's exit code when it ends.
func reap(mainPID int) int {
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, 0, nil)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.ECHILD) {
				return 0
			}
			continue
		}
		if pid == mainPID {
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
	}
}

func sawOOM() bool {
	buf := make([]byte, 1<<16)
	n, err := unix.Klogctl(unix.SYSLOG_ACTION_READ_ALL, buf)
	if err != nil {
		return false
	}
	return strings.Contains(string(buf[:n]), "Out of memory")
}

func halt() {
	if console != nil {
		console.Sync()
	}
	unix.Sync()
	time.Sleep(50 * time.Millisecond)
	// Firecracker exits when the guest resets.
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
	select {}
}

// serve answers the host on vsock, one request per connection.
func serve(st *state) {
	var l net.Listener
	var err error
	for i := 0; i < 50; i++ {
		l, err = vsock.Listen(guest.Port, nil)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		logf("vsock listen: %v", err)
		return
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go handle(st, conn)
	}
}

func handle(st *state, conn net.Conn) {
	defer conn.Close()
	var req guest.Request
	if err := guest.ReadFrame(conn, &req); err != nil {
		return
	}
	switch req.Op {
	case "ping":
		var si unix.Sysinfo_t
		_ = unix.Sysinfo(&si)
		st.mu.Lock()
		pid := 0
		if st.main != nil {
			pid = st.main.Pid
		}
		st.mu.Unlock()
		_ = guest.WriteFrame(conn, guest.Response{Type: "pong", Uptime: float64(si.Uptime), Main: pid})
	case "exec":
		execOp(st, conn, req)
	case "put":
		if err := os.MkdirAll(filepath.Dir(req.Path), 0o755); err != nil {
			_ = guest.WriteFrame(conn, guest.Response{Type: "error", Message: err.Error()})
			return
		}
		mode := os.FileMode(req.Mode) & os.ModePerm
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(req.Path, req.Data, mode); err != nil {
			_ = guest.WriteFrame(conn, guest.Response{Type: "error", Message: err.Error()})
			return
		}
		_ = os.Chmod(req.Path, mode)
		_ = guest.WriteFrame(conn, guest.Response{Type: "ok"})
	case "get":
		data, err := os.ReadFile(req.Path)
		if err != nil {
			_ = guest.WriteFrame(conn, guest.Response{Type: "error", Message: err.Error()})
			return
		}
		_ = guest.WriteFrame(conn, guest.Response{Type: "file", Data: data})
	case "shutdown":
		st.mu.Lock()
		st.requested = true
		p := st.main
		st.mu.Unlock()
		_ = guest.WriteFrame(conn, guest.Response{Type: "ok"})
		if p == nil {
			return
		}
		grace := time.Duration(req.GraceSec) * time.Second
		if grace <= 0 {
			grace = 10 * time.Second
		}
		logf("stopping pid=%d grace=%s", p.Pid, grace)
		_ = p.Signal(unix.SIGTERM)
		select {
		case <-st.mainDone:
		case <-time.After(grace):
			logf("killing pid=%d", p.Pid)
			_ = p.Signal(unix.SIGKILL)
		}
	default:
		_ = guest.WriteFrame(conn, guest.Response{Type: "error", Message: "unknown op " + req.Op})
	}
}

type frameWriter struct {
	mu   *sync.Mutex
	conn net.Conn
	typ  string
}

func (w frameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(p) > 0 {
		n := len(p)
		if n > 1<<20 {
			n = 1 << 20
		}
		if err := guest.WriteFrame(w.conn, guest.Response{Type: w.typ, Data: p[:n]}); err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return len(p), nil
}

func execOp(st *state, conn net.Conn, req guest.Request) {
	if len(req.Cmd) == 0 {
		_ = guest.WriteFrame(conn, guest.Response{Type: "error", Message: "empty command"})
		return
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	env := append([]string{}, st.env...)
	for k, v := range req.Env {
		env = append(env, k+"="+v)
	}
	path, err := lookPath(req.Cmd[0], env)
	if err != nil {
		_ = guest.WriteFrame(conn, guest.Response{Type: "stderr", Data: []byte(err.Error() + "\n")})
		_ = guest.WriteFrame(conn, guest.Response{Type: "exit", Code: 127})
		return
	}
	cmd := exec.CommandContext(ctx, path, req.Cmd[1:]...)
	cmd.Env = env
	cmd.Dir = req.Cwd
	if cmd.Dir == "" {
		cmd.Dir = st.cfg.WorkDir
	}
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	if len(req.Stdin) > 0 {
		cmd.Stdin = strings.NewReader(string(req.Stdin))
	}
	var mu sync.Mutex
	cmd.Stdout = frameWriter{&mu, conn, "stdout"}
	cmd.Stderr = frameWriter{&mu, conn, "stderr"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	err = cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
		if code < 0 {
			code = 137
		}
	default:
		mu.Lock()
		_ = guest.WriteFrame(conn, guest.Response{Type: "stderr", Data: []byte(err.Error() + "\n")})
		mu.Unlock()
		code = 126
	}
	mu.Lock()
	_ = guest.WriteFrame(conn, guest.Response{Type: "exit", Code: code, TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded)})
	mu.Unlock()
}
