package fc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Process is one running Firecracker.
type Process struct {
	ID        string
	Dir       string // runtime dir: API socket, vsock socket, logs
	API       string // API socket path
	VsockSock string
	Console   string // the guest's serial console, one timestamped line per guest line
	cmd       *exec.Cmd
	done      chan struct{}
	err       error
	Client    *Client
	logDone   sync.WaitGroup
}

// Paths of a machine's runtime files inside its run dir.
func Paths(dir string) (api, vsock, console, fclog string) {
	return filepath.Join(dir, "api.sock"), filepath.Join(dir, "vsock.sock"), filepath.Join(dir, "console.log"), filepath.Join(dir, "firecracker.log")
}

// Start launches Firecracker for machine id with its runtime files under dir, and waits for
// its API. Nothing is configured yet: the caller PUTs the boot source, drives, interfaces and
// then InstanceStart (or loads a snapshot).
func Start(ctx context.Context, binary, id, dir string, pci bool) (*Process, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	api, vsock, console, fclog := Paths(dir)
	_ = os.Remove(api)
	_ = os.Remove(vsock)
	out, err := os.OpenFile(console, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	if f, err := os.OpenFile(fclog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
		f.Close()
	}
	args := []string{"--api-sock", api, "--id", id, "--log-path", fclog, "--level", "Warn"}
	if pci {
		args = append(args, "--enable-pci")
	}
	cmd := exec.Command(binary, args...)
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		out.Close()
		pw.Close()
		return nil, fmt.Errorf("start firecracker: %w", err)
	}
	p := &Process{ID: id, Dir: dir, API: api, VsockSock: vsock, Console: console, cmd: cmd, done: make(chan struct{}), Client: NewClient(api)}
	p.logDone.Add(1)
	go func() {
		defer p.logDone.Done()
		defer out.Close()
		stamp(pr, out)
	}()
	go func() {
		err := cmd.Wait()
		pw.Close()
		p.logDone.Wait()
		p.err = err
		close(p.done)
	}()
	if err := p.Client.WaitAPI(ctx, 10*time.Second); err != nil {
		p.Kill()
		return nil, err
	}
	return p, nil
}

// stamp copies lines from the guest console with a timestamp in front of each.
func stamp(r io.Reader, w io.Writer) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			ts := time.Now().UTC().Format(time.RFC3339Nano)
			_, _ = fmt.Fprintf(w, "%s %s", ts, line)
			if line[len(line)-1] != '\n' {
				_, _ = w.Write([]byte{'\n'})
			}
		}
		if err != nil {
			return
		}
	}
}

// Done is closed when the process has exited.
func (p *Process) Done() <-chan struct{} { return p.done }

// Wait blocks until the process exits and returns its error (nil for exit 0).
func (p *Process) Wait() error {
	<-p.done
	return p.err
}

// Exited says whether the process is gone.
func (p *Process) Exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// Kill ends the process now.
func (p *Process) Kill() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
}

// PID of the Firecracker process.
func (p *Process) PID() int {
	if p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// WaitExit waits up to d for the process to exit on its own.
func (p *Process) WaitExit(d time.Duration) bool {
	select {
	case <-p.done:
		return true
	case <-time.After(d):
		return false
	}
}

// ErrNotRunning is returned by operations on a process that has exited.
var ErrNotRunning = errors.New("firecracker is not running")
