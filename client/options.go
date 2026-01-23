package client

import (
	"io"
	"log/slog"

	"github.com/frobware/go-bpfman/config"
)

// DefaultSocketPath returns the default Unix socket path for connecting to a bpfman daemon.
// This is derived from the default runtime directories.
func DefaultSocketPath() string {
	return config.DefaultRuntimeDirs().SocketPath()
}

// Option configures client behaviour.
type Option interface {
	applyDial(*dialOptions)
	applyOpen(*openOptions)
}

// dialOptions holds configuration for Dial.
type dialOptions struct {
	logger *slog.Logger
}

// openOptions holds configuration for Open.
type openOptions struct {
	logger *slog.Logger
	path   string
	config config.Config
}

// funcOption implements Option using functions.
type funcOption struct {
	dial func(*dialOptions)
	open func(*openOptions)
}

func (f *funcOption) applyDial(o *dialOptions) {
	if f.dial != nil {
		f.dial(o)
	}
}

func (f *funcOption) applyOpen(o *openOptions) {
	if f.open != nil {
		f.open(o)
	}
}

// WithLogger sets the logger for client operations.
// If not specified, a no-op logger is used.
func WithLogger(l *slog.Logger) Option {
	return &funcOption{
		dial: func(o *dialOptions) { o.logger = l },
		open: func(o *openOptions) { o.logger = l },
	}
}

// WithRuntimeDir sets the base runtime directory for Open.
// If not specified, defaults to /run/bpfman.
// This option has no effect on Dial.
func WithRuntimeDir(path string) Option {
	return &funcOption{
		open: func(o *openOptions) { o.path = path },
	}
}

// WithConfig sets the configuration for Open.
// If not specified, defaults are loaded from /etc/bpfman/bpfman.toml
// or embedded defaults if that file doesn't exist.
// This option has no effect on Dial.
func WithConfig(cfg config.Config) Option {
	return &funcOption{
		open: func(o *openOptions) { o.config = cfg },
	}
}

// discardLogger returns a logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Dial connects to a bpfman daemon at the specified address.
// The address can be:
//   - "host:port" for TCP connections
//   - "unix:///path/to/socket" for Unix socket connections
//   - "/path/to/socket" for Unix socket connections (shorthand)
//
// Example:
//
//	c, err := client.Dial("localhost:50051")
//	c, err := client.Dial("/run/bpfman-sock/bpfman.sock")
//	c, err := client.Dial("unix:///run/bpfman-sock/bpfman.sock")
//
// The returned client must be closed when no longer needed.
func Dial(address string, opts ...Option) (Client, error) {
	o := &dialOptions{
		logger: discardLogger(),
	}
	for _, opt := range opts {
		opt.applyDial(o)
	}
	return newRemote(address, o.logger)
}

// Open creates a client for local BPF program management.
//
// Example:
//
//	// Use defaults (/run/bpfman, default config)
//	c, err := client.Open()
//
//	// Use custom runtime directory
//	c, err := client.Open(client.WithRuntimeDir("/tmp/mybpfman"))
//
//	// Use custom logger
//	c, err := client.Open(client.WithLogger(myLogger))
//
// The returned client must be closed when no longer needed.
func Open(opts ...Option) (Client, error) {
	o := &openOptions{
		logger: discardLogger(),
		path:   "", // empty means use default
		config: config.DefaultConfig(),
	}
	for _, opt := range opts {
		opt.applyOpen(o)
	}

	// Determine runtime directories
	var dirs config.RuntimeDirs
	if o.path != "" {
		dirs = config.NewRuntimeDirs(o.path)
	} else {
		dirs = config.DefaultRuntimeDirs()
	}

	return newEphemeral(dirs, o.config, o.logger)
}
