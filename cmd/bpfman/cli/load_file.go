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
func (c *LoadFileCmd) Run(cli *CLI, ctx context.Context) error {
	// Validate object file exists
	objPath, err := ParseObjectPath(c.Path)
	if err != nil {
		return err
	}

	b, err := cli.Client(ctx)
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

	results := make([]bpfman.ManagedProgram, 0, len(c.Programs))

	for _, prog := range c.Programs {
		// Build load spec using the appropriate constructor
		var spec bpfman.LoadSpec
		var err error
		if prog.Type.RequiresAttachFunc() {
			spec, err = bpfman.NewAttachLoadSpec(objPath.Path, prog.Name, prog.Type, prog.AttachFunc)
		} else {
			spec, err = bpfman.NewLoadSpec(objPath.Path, prog.Name, prog.Type)
		}
		if err != nil {
			return fmt.Errorf("invalid load spec for %q: %w", prog.Name, err)
		}

		// Apply optional fields
		// PinPath is the bpffs root; actual paths are computed from kernel ID
		spec = spec.WithPinPath(cli.RuntimeDirs().FS)
		if globalData != nil {
			spec = spec.WithGlobalData(globalData)
		}
		if c.MapOwnerID != 0 {
			spec = spec.WithMapOwnerID(c.MapOwnerID)
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
