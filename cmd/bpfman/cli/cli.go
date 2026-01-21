package cli

import (
	"reflect"

	"github.com/alecthomas/kong"
)

// CLI is the root command structure for bpfman.
type CLI struct {
	DB DBPath `name:"db" help:"SQLite database path." default:"${default_db_path}"`

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
