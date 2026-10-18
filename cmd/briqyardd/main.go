//go:build linux

// briqyardd runs machines on one server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	spec "github.com/briq-cloud/briqyard/api"
	"github.com/briq-cloud/briqyard/internal/apiserver"
	"github.com/briq-cloud/briqyard/internal/config"
	"github.com/briq-cloud/briqyard/internal/fleet"
	"github.com/briq-cloud/briqyard/internal/image"
	"github.com/briq-cloud/briqyard/internal/ingress"
	"github.com/briq-cloud/briqyard/internal/machine"
	"github.com/briq-cloud/briqyard/internal/netw"
	"github.com/briq-cloud/briqyard/internal/storage/zfs"
	"github.com/briq-cloud/briqyard/internal/store"
	"github.com/briq-cloud/briqyard/internal/version"
)

func main() {
	configPath := flag.String("config", "/etc/briqyard/config.yaml", "configuration file")
	showVersion := flag.Bool("version", false, "print the version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.Version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()}))
	if err := run(*configPath, log); err != nil {
		log.Error("briqyardd failed", "err", err)
		os.Exit(1)
	}
}

func logLevel() slog.Level {
	switch os.Getenv("BRIQYARD_LOG") {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

func run(configPath string, log *slog.Logger) error {
	if _, err := os.Stat(configPath); err != nil && configPath == "/etc/briqyard/config.yaml" {
		configPath = ""
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("briqyardd must run as root (ZFS, TAP devices, nftables)")
	}
	for _, p := range []string{cfg.Firecracker, cfg.Kernel, cfg.Init} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	st, err := store.Open(cfg.StatePath())
	if err != nil {
		return err
	}
	defer st.Close()
	disks, err := zfs.New(ctx, cfg.Storage.Pool)
	if err != nil {
		return err
	}
	images := &image.Builder{Store: disks, Dir: cfg.ImageDir(), Init: cfg.Init, RootGB: cfg.RootDiskGB, Log: log}
	dns := netw.NewResolver(cfg.Network.UpstreamDNS, log)
	mgr, err := machine.New(ctx, cfg, st, disks, images, dns, log)
	if err != nil {
		return err
	}
	in := &ingress.Ingress{Backend: mgr, Bind: cfg.Ingress.Bind, HTTP: cfg.Ingress.HTTP, Log: log}
	if err := in.Start(); err != nil {
		return err
	}
	srv := &apiserver.Server{Machines: mgr, Token: cfg.Token, HostID: mgr.HostID, Log: log, OpenAPI: spec.OpenAPI}
	httpSrv := &http.Server{Addr: cfg.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 30 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		log.Info("briqyardd listening", "addr", cfg.Listen, "version", version.Version, "host_id", mgr.HostID, "pool", cfg.Storage.Pool)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	var hb *fleet.Heartbeat
	if cfg.Fleet != nil && cfg.Fleet.URL != "" {
		hb = &fleet.Heartbeat{URL: cfg.Fleet.URL, Token: cfg.Fleet.Token, Advertise: cfg.Fleet.Advertise, HostID: mgr.HostID, Machines: mgr, Log: log}
		go hb.Run(ctx)
	}
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		log.Error("api server", "err", err)
	}
	sctx, scancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer scancel()
	_ = httpSrv.Shutdown(sctx)
	in.Stop(sctx)
	mgr.Close(sctx)
	return nil
}
