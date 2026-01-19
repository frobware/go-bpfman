package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/frobware/bpffs-csi-driver/pkg/driver"
)

var (
	driverName = flag.String("driver-name", "bpffs.csi.frobware.io", "CSI driver name")
	endpoint   = flag.String("endpoint", "unix:///csi/csi.sock", "CSI endpoint")
	nodeID     = flag.String("node-id", "", "Node ID (defaults to hostname)")
	version    = flag.String("version", "0.1.0", "Driver version")
	logFormat  = flag.String("log-format", "text", "Log format: text or json")
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

	logger.Info("starting CSI driver",
		"name", *driverName,
		"version", *version,
		"nodeID", *nodeID,
		"endpoint", *endpoint,
	)

	d := driver.New(*driverName, *version, *nodeID, *endpoint, logger)

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
