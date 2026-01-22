package cli

import (
	"log/slog"
	"os"
	"reflect"

	"github.com/alecthomas/kong"

	"github.com/frobware/go-bpfman/pkg/bpfman/client"
	"github.com/frobware/go-bpfman/pkg/bpfman/config"
	"github.com/frobware/go-bpfman/pkg/logging"
)

// CLI is the root command structure for bpfman.
type CLI struct {
	DB     DBPath `name:"db" help:"SQLite database path." default:"${default_db_path}"`
	Config string `name:"config" help:"Config file path." default:"${default_config_path}"`
	Log    string `name:"log" help:"Log spec (e.g., 'info,manager=debug')." env:"BPFMAN_LOG"`
	Remote string `name:"remote" short:"r" help:"Remote endpoint (unix:///path or host:port). Connects via gRPC instead of local manager."`

	Serve  ServeCmd  `cmd:"" help:"Start the gRPC daemon."`
	Load   LoadCmd   `cmd:"" help:"Load a BPF program from an object file."`
	Unload UnloadCmd `cmd:"" help:"Unload a managed BPF program."`
	Attach AttachCmd `cmd:"" help:"Attach a loaded program to a hook."`
	Detach DetachCmd `cmd:"" help:"Detach a link."`
	List   ListCmd   `cmd:"" help:"List managed programs or links."`
	Get    GetCmd    `cmd:"" help:"Get details of a program or link."`
	GC     GCCmd     `cmd:"" help:"Garbage collect stale resources."`
	Image  ImageCmd  `cmd:"" help:"Image operations (verify signatures)."`
}

// KongOptions returns the Kong configuration options for the CLI.
func KongOptions() []kong.Option {
	return []kong.Option{
		kong.Name("bpfman"),
		kong.Description("BPF program manager with integrated CSI driver."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.TypeMapper(reflect.TypeOf(ProgramID{}), programIDMapper()),
		kong.TypeMapper(reflect.TypeOf(LinkID{}), linkIDMapper()),
		kong.TypeMapper(reflect.TypeOf(LinkUUID{}), linkUUIDMapper()),
		kong.TypeMapper(reflect.TypeOf(KeyValue{}), keyValueMapper()),
		kong.TypeMapper(reflect.TypeOf(GlobalData{}), globalDataMapper()),
		kong.TypeMapper(reflect.TypeOf(ObjectPath{}), objectPathMapper()),
		kong.TypeMapper(reflect.TypeOf(DBPath{}), dbPathMapper()),
		kong.TypeMapper(reflect.TypeOf(ProgramSpec{}), programSpecMapper()),
		kong.TypeMapper(reflect.TypeOf(ImagePullPolicy{}), imagePullPolicyMapper()),
		kong.Vars{
			"default_db_path":     "/run/bpfman/state.db",
			"default_socket_path": "/run/bpfman-sock/bpfman.sock",
			"default_csi_socket":  "/run/bpfman/csi/csi.sock",
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
// If --remote is set, returns a RemoteClient connected via gRPC.
// Otherwise, returns a LocalClient with direct manager access.
// The returned client must be closed when no longer needed.
func (c *CLI) Client() (client.Client, error) {
	logger, err := c.Logger()
	if err != nil {
		return nil, err
	}

	if c.Remote != "" {
		return client.NewRemote(c.Remote, logger)
	}

	return client.NewLocal(c.DB.Path, logger)
}
