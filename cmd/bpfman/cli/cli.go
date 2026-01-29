// Package cli provides the command-line interface for bpfman.
// It uses Kong for argument parsing and delegates to the client package
// for BPF operations.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/alecthomas/kong"

	"github.com/frobware/go-bpfman/client"
	"github.com/frobware/go-bpfman/config"
	"github.com/frobware/go-bpfman/lock"
	"github.com/frobware/go-bpfman/logging"
	"github.com/frobware/go-bpfman/nsenter"
)

// CLI is the root command structure for bpfman.
type CLI struct {
	RuntimeDir  string        `name:"runtime-dir" help:"Runtime directory base path." default:"${default_runtime_dir}"`
	Config      string        `name:"config" help:"Config file path." default:"${default_config_path}"`
	Log         string        `name:"log" help:"Log spec (e.g., 'info,manager=debug')." env:"BPFMAN_LOG"`
	Remote      string        `name:"remote" short:"r" help:"Remote endpoint (unix:///path or host:port). Connects via gRPC instead of local manager."`
	LockTimeout time.Duration `name:"lock-timeout" help:"Timeout for acquiring the global writer lock (0 for indefinite)." default:"30s"`

	Serve  ServeCmd  `cmd:"" help:"Start the gRPC daemon."`
	Load   LoadCmd   `cmd:"" help:"Load a BPF program from an object file."`
	Unload UnloadCmd `cmd:"" help:"Unload a managed BPF program."`
	Attach AttachCmd `cmd:"" help:"Attach a loaded program to a hook."`
	Detach DetachCmd `cmd:"" help:"Detach a link."`
	List   ListCmd   `cmd:"" help:"List managed programs or links."`
	Get    GetCmd    `cmd:"" help:"Get a loaded eBPF program or program attachment link."`
	GC     GCCmd     `cmd:"" help:"Garbage collect stale resources."`
	Doctor DoctorCmd `cmd:"" help:"Check coherency of database, kernel, and filesystem state."`
	Image  ImageCmd  `cmd:"" help:"Image operations (verify signatures)."`
}

// RuntimeDirs returns the runtime directories configuration.
func (c *CLI) RuntimeDirs() config.RuntimeDirs {
	return config.NewRuntimeDirs(c.RuntimeDir)
}

// resolveMode returns the effective mode name by checking the
// BPFMAN_MODE environment variable first, falling back to argv[0].
func resolveMode() string {
	if mode := os.Getenv(nsenter.ModeEnvVar); mode != "" {
		return mode
	}
	return filepath.Base(os.Args[0])
}

// Run parses command-line arguments and executes the selected command.
// If invoked as "bpfman-rpc" (via argv[0] or BPFMAN_MODE), automatically
// runs the serve command for compatibility with the bpfman-operator which
// expects the Rust daemon's binary layout.
// If invoked as "bpfman-ns" (via argv[0], argv[1], or BPFMAN_MODE), runs
// the namespace helper for container uprobes.
func Run(ctx context.Context) {
	// Check for bpfman-ns mode first - needs special early handling
	if runAsNS() {
		return
	}

	if resolveMode() == "bpfman-rpc" {
		os.Args = append([]string{os.Args[0], "serve"}, os.Args[1:]...)
	}

	var c CLI
	kctx := kong.Parse(&c, KongOptions()...)
	kctx.BindTo(ctx, (*context.Context)(nil))
	kctx.FatalIfErrorf(kctx.Run(&c))
}

// KongOptions returns the Kong configuration options for the CLI.
func KongOptions() []kong.Option {
	return []kong.Option{
		kong.Name("bpfman"),
		kong.Description("BPF program manager with integrated CSI driver."),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.ShortUsageOnError(),
		kong.TypeMapper(reflect.TypeOf(ProgramID{}), programIDMapper()),
		kong.TypeMapper(reflect.TypeOf(LinkID{}), linkIDMapper()),
		kong.TypeMapper(reflect.TypeOf(KeyValue{}), keyValueMapper()),
		kong.TypeMapper(reflect.TypeOf(GlobalData{}), globalDataMapper()),
		kong.TypeMapper(reflect.TypeOf(ObjectPath{}), objectPathMapper()),
		kong.TypeMapper(reflect.TypeOf(ProgramSpec{}), programSpecMapper()),
		kong.TypeMapper(reflect.TypeOf(ImagePullPolicy{}), imagePullPolicyMapper()),
		kong.Vars{
			"default_runtime_dir": "/run/bpfman",
			"default_config_path": "/etc/bpfman/bpfman.toml",
		},
	}
}

// LoadConfig loads the configuration from the config file path.
func (c *CLI) LoadConfig() (config.Config, error) {
	return config.Load(c.Config)
}

// Logger creates a logger for CLI commands.
// CLI commands default to WARN level for quieter output.
// Use LoggerFromConfig for long-running services like serve.
func (c *CLI) Logger() (*slog.Logger, error) {
	cfg, err := c.LoadConfig()
	if err != nil {
		return nil, err
	}

	format, err := logging.ParseFormat(cfg.Logging.Format)
	if err != nil {
		return nil, err
	}

	// CLI commands default to warn unless --log is specified
	spec := c.Log
	if spec == "" {
		spec = "warn"
	}

	opts := logging.Options{
		CLISpec:    spec,
		ConfigSpec: cfg.Logging.ToSpec(),
		Format:     format,
		Output:     os.Stderr,
	}

	return logging.New(opts)
}

// LoggerFromConfig creates a logger using config file settings.
// Used by long-running services (serve) where INFO level is appropriate.
// Output goes to stdout for daemon/container log collection.
func (c *CLI) LoggerFromConfig() (*slog.Logger, error) {
	cfg, err := c.LoadConfig()
	if err != nil {
		return nil, err
	}

	format, err := logging.ParseFormat(cfg.Logging.Format)
	if err != nil {
		return nil, err
	}

	opts := logging.Options{
		CLISpec:    c.Log,
		ConfigSpec: cfg.Logging.ToSpec(),
		Format:     format,
		Output:     os.Stdout,
	}

	return logging.New(opts)
}

// Client returns a client appropriate for the configured transport.
// If --remote is set, returns a client connected via gRPC to the remote daemon.
// Otherwise, returns a client that spawns an in-process gRPC server,
// ensuring all operations use the same code path as remote clients.
// The returned client must be closed when no longer needed.
func (c *CLI) Client(ctx context.Context) (client.Client, error) {
	logger, err := c.Logger()
	if err != nil {
		return nil, err
	}

	if c.Remote != "" {
		return client.Dial(c.Remote, client.WithLogger(logger))
	}

	cfg, err := c.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return client.Open(ctx,
		client.WithLogger(logger),
		client.WithRuntimeDir(c.RuntimeDir),
		client.WithConfig(cfg),
	)
}

// RunWithLock wraps mutating CLI operations with the global writer lock when
// running in local (ephemeral) mode. Remote mode relies on the server's lock
// interceptor, so the client must avoid taking the same lock to prevent
// deadlock.
func (c *CLI) RunWithLock(ctx context.Context, fn func(context.Context) error) error {
	if c.Remote != "" {
		return fn(ctx)
	}

	// Apply lock timeout if set (0 means indefinite)
	if c.LockTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.LockTimeout)
		defer cancel()
	}

	dirs := c.RuntimeDirs()
	if err := lock.Run(ctx, dirs.Lock, func(ctx context.Context, _ lock.WriterScope) error {
		return fn(ctx)
	}); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("timed out waiting for lock %s (--lock-timeout=%v)", dirs.Lock, c.LockTimeout)
		}
		return err
	}
	return nil
}
