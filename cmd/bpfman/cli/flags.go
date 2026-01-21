package cli

import "time"

// DryRunFlag provides a --dry-run flag for commands that support it.
type DryRunFlag struct {
	DryRun bool `help:"Show what would be done without making changes."`
}

// MetadataFlags provides metadata-related flags.
type MetadataFlags struct {
	Metadata []KeyValue `short:"m" name:"metadata" help:"KEY=VALUE metadata to attach (can be repeated)."`
}

// GlobalDataFlags provides global data flags.
type GlobalDataFlags struct {
	GlobalData []GlobalData `short:"g" name:"global" help:"NAME=HEX global data (can be repeated)."`
}

// OutputFormat represents the output format type.
type OutputFormat string

const (
	OutputFormatTable OutputFormat = "table"
	OutputFormatTree  OutputFormat = "tree"
	OutputFormatJSON  OutputFormat = "json"
)

// OutputFlags provides output formatting flags.
type OutputFlags struct {
	Output OutputFormat `short:"o" help:"Output format (table, tree, json)." default:"table" enum:"table,tree,json"`
}

// TTLFlag provides a TTL duration flag.
type TTLFlag struct {
	TTL time.Duration `help:"Time-to-live duration." default:"5m"`
}
