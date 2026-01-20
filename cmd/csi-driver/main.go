package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/kernel/ebpf"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/pkg/csi/driver"
)

var (
	driverName = flag.String("driver-name", "csi.bpfman.io", "CSI driver name")
	endpoint   = flag.String("endpoint", "unix:///csi/csi.sock", "CSI endpoint")
	nodeID     = flag.String("node-id", "", "Node ID (defaults to hostname)")
	version    = flag.String("version", "0.1.0", "Driver version")
	logFormat  = flag.String("log-format", "text", "Log format: text or json")

	// bpfman integration flags
	dbPath     = flag.String("db", "", "SQLite database path for bpfman integration (enables bpfman-aware mode)")
	csiFsRoot  = flag.String("csi-fs-root", driver.DefaultCSIFsRoot, "Root directory for per-pod bpffs mounts")
)

func main() {
	flag.Parse()

	// Configure slog
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	if *logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Default nodeID to hostname if not provided
	if *nodeID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			logger.Error("failed to get hostname", "error", err)
			os.Exit(1)
		}
		*nodeID = hostname
	}

	// Build driver options
	var driverOpts []driver.Option

	// Configure bpfman integration if database path is provided
	if *dbPath != "" {
		store, err := sqlite.New(*dbPath)
		if err != nil {
			logger.Error("failed to open database", "path", *dbPath, "error", err)
			os.Exit(1)
		}
		defer store.Close()

		kernel := ebpf.New()

		driverOpts = append(driverOpts,
			driver.WithStore(store),
			driver.WithKernel(kernel),
		)

		logger.Info("bpfman integration enabled",
			"db", *dbPath,
		)
	}

	if *csiFsRoot != driver.DefaultCSIFsRoot {
		driverOpts = append(driverOpts, driver.WithCSIFsRoot(*csiFsRoot))
	}

	logger.Info("starting CSI driver",
		"name", *driverName,
		"version", *version,
		"nodeID", *nodeID,
		"endpoint", *endpoint,
		"bpfman-mode", *dbPath != "",
	)

	d := driver.New(*driverName, *version, *nodeID, *endpoint, logger, driverOpts...)

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		logger.Info("received signal, shutting down", "signal", sig)
		d.Stop()
	}()

	if err := d.Run(); err != nil {
		logger.Error("driver failed", "error", err)
		os.Exit(1)
	}
}
