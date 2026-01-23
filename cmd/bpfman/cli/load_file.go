package cli

import (
	"context"
	"fmt"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/manager"
)

// LoadCmd loads a BPF program from an object file or OCI image.
type LoadCmd struct {
	File  LoadFileCmd  `cmd:"" default:"withargs" help:"Load from a local object file."`
	Image LoadImageCmd `cmd:"" help:"Load from an OCI container image."`
}

// LoadFileCmd loads a BPF program from a local object file.
type LoadFileCmd struct {
	OutputFlags
	MetadataFlags
	GlobalDataFlags

	Path        string        `short:"p" name:"path" help:"Path to the BPF object file (.o)." required:""`
	Programs    []ProgramSpec `name:"programs" help:"TYPE:NAME or TYPE:NAME:ATTACH_FUNC program to load (can be repeated). For fentry/fexit, ATTACH_FUNC is required." required:""`
	Application string        `short:"a" name:"application" help:"Application name to group programs (stored as bpfman.io/application metadata)."`
	MapOwnerID  uint32        `name:"map-owner-id" help:"Program ID of another program to share maps with."`
}

// Run executes the load file command.
func (c *LoadFileCmd) Run(cli *CLI) error {
	// Validate object file exists
	objPath, err := ParseObjectPath(c.Path)
	if err != nil {
		return err
	}

	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	// Convert global data
	var globalData map[string][]byte
	if len(c.GlobalData) > 0 {
		globalData = GlobalDataMap(c.GlobalData)
	}

	// Build metadata map, adding application if specified
	metadata := MetadataMap(c.Metadata)
	if c.Application != "" {
		if metadata == nil {
			metadata = make(map[string]string)
		}
		metadata["bpfman.io/application"] = c.Application
	}

	ctx := context.Background()
	results := make([]bpfman.ManagedProgram, 0, len(c.Programs))

	for _, prog := range c.Programs {
		// Build load spec and options
		// PinPath is the bpffs root; actual paths are computed from kernel ID
		spec := bpfman.LoadSpec{
			ObjectPath:  objPath.Path,
			ProgramName: prog.Name,
			ProgramType: prog.Type, // Already validated at parse time
			PinPath:     cli.RuntimeDirs().FS,
			GlobalData:  globalData,
			AttachFunc:  prog.AttachFunc, // For fentry/fexit
			MapOwnerID:  c.MapOwnerID,
		}
		opts := manager.LoadOpts{
			UserMetadata: metadata,
		}

		// Load through client
		loaded, err := b.Load(ctx, spec, opts)
		if err != nil {
			return fmt.Errorf("failed to load program %q: %w", prog.Name, err)
		}
		results = append(results, loaded)
	}

	output, err := FormatLoadedPrograms(results, &c.OutputFlags)
	if err != nil {
		return err
	}

	fmt.Print(output)
	return nil
}
