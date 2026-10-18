package guest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Dial opens one connection to the init through Firecracker's vsock Unix socket: connect to
// the socket, ask for the guest port, wait for Firecracker's OK.
func Dial(ctx context.Context, udsPath string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", udsPath)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", Port); err != nil {
		conn.Close()
		return nil, err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("vsock connect: %w", err)
	}
	if !strings.HasPrefix(line, "OK ") {
		conn.Close()
		return nil, fmt.Errorf("vsock connect refused: %s", strings.TrimSpace(line))
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// ExecOutput is a finished command.
type ExecOutput struct {
	Stdout   []byte
	Stderr   []byte
	Code     int
	TimedOut bool
}

// MaxOutput bounds what Exec keeps of each stream.
const MaxOutput = 4 << 20

// Exec runs a command in the guest and collects its output. The timeout in req is enforced by
// the guest; ctx bounds the whole call on the host side.
func Exec(ctx context.Context, udsPath string, req Request) (ExecOutput, error) {
	req.Op = "exec"
	conn, err := Dial(ctx, udsPath)
	if err != nil {
		return ExecOutput{}, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := WriteFrame(conn, req); err != nil {
		return ExecOutput{}, err
	}
	var out ExecOutput
	var stdout, stderr bytes.Buffer
	for {
		var r Response
		if err := ReadFrame(conn, &r); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return out, ErrClosed
			}
			return out, err
		}
		switch r.Type {
		case "stdout":
			appendBounded(&stdout, r.Data)
		case "stderr":
			appendBounded(&stderr, r.Data)
		case "exit":
			out.Stdout, out.Stderr, out.Code, out.TimedOut = stdout.Bytes(), stderr.Bytes(), r.Code, r.TimedOut
			return out, nil
		case "error":
			return out, errors.New(r.Message)
		}
	}
}

func appendBounded(b *bytes.Buffer, data []byte) {
	if b.Len() >= MaxOutput {
		return
	}
	if room := MaxOutput - b.Len(); len(data) > room {
		data = data[:room]
	}
	b.Write(data)
}

// Put writes a file in the guest.
func Put(ctx context.Context, udsPath, path string, mode uint32, data []byte) error {
	return simple(ctx, udsPath, Request{Op: "put", Path: path, Mode: mode, Data: data}, "ok")
}

// Get reads a file from the guest.
func Get(ctx context.Context, udsPath, path string) ([]byte, error) {
	r, err := roundTrip(ctx, udsPath, Request{Op: "get", Path: path})
	if err != nil {
		return nil, err
	}
	if r.Type != "file" {
		return nil, fmt.Errorf("guest answered %s: %s", r.Type, r.Message)
	}
	return r.Data, nil
}

// Ping checks the init answers; the response carries the guest uptime.
func Ping(ctx context.Context, udsPath string) (Response, error) {
	r, err := roundTrip(ctx, udsPath, Request{Op: "ping"})
	if err != nil {
		return r, err
	}
	if r.Type != "pong" {
		return r, fmt.Errorf("guest answered %s: %s", r.Type, r.Message)
	}
	return r, nil
}

// Shutdown asks the init to end the main process (SIGTERM, then SIGKILL after grace) and halt.
func Shutdown(ctx context.Context, udsPath string, grace time.Duration) error {
	return simple(ctx, udsPath, Request{Op: "shutdown", GraceSec: int(grace.Seconds())}, "ok")
}

func simple(ctx context.Context, udsPath string, req Request, want string) error {
	r, err := roundTrip(ctx, udsPath, req)
	if err != nil {
		return err
	}
	if r.Type != want {
		return fmt.Errorf("guest answered %s: %s", r.Type, r.Message)
	}
	return nil
}

func roundTrip(ctx context.Context, udsPath string, req Request) (Response, error) {
	conn, err := Dial(ctx, udsPath)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := WriteFrame(conn, req); err != nil {
		return Response{}, err
	}
	var r Response
	if err := ReadFrame(conn, &r); err != nil {
		return Response{}, err
	}
	if r.Type == "error" {
		return r, errors.New(r.Message)
	}
	return r, nil
}

// WaitReady polls Ping until the init answers or the context ends.
func WaitReady(ctx context.Context, udsPath string) error {
	for {
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := Ping(pctx, udsPath)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("guest init did not answer: %w (last: %v)", ctx.Err(), err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
