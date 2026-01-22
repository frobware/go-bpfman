package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

// LoadCmd loads a BPF program from an object file or OCI image.
type LoadCmd struct {
	File  LoadFileCmd  `cmd:"" default:"withargs" help:"Load from a local object file."`
	Image LoadImageCmd `cmd:"" help:"Load from an OCI container image."`
}

// LoadFileCmd loads a BPF program from a local object file.
type LoadFileCmd struct {
	MetadataFlags
	GlobalDataFlags

	ObjectPath  string `arg:"" name:"object" help:"Path to the BPF object file (.o)."`
	ProgramName string `arg:"" name:"program" help:"Name of the BPF program to load."`
}

// Run executes the load file command.
func (c *LoadFileCmd) Run(cli *CLI) error {
	// Validate object file exists
	objPath, err := ParseObjectPath(c.ObjectPath)
	if err != nil {
		return err
	}

	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	// Generate a unique pin directory name using timestamp
	// The actual kernel_id becomes known only after loading
	pinDir := filepath.Join(cli.RuntimeDirs().FS, fmt.Sprintf("%d", time.Now().UnixNano()))

	// Convert global data
	var globalData map[string][]byte
	if len(c.GlobalData) > 0 {
		globalData = GlobalDataMap(c.GlobalData)
	}

	// Build load spec and options
	spec := managed.LoadSpec{
		ObjectPath:  objPath.Path,
		ProgramName: c.ProgramName,
		PinPath:     pinDir,
		GlobalData:  globalData,
	}
	opts := manager.LoadOpts{
		UserMetadata: MetadataMap(c.Metadata),
	}

	// Load through client
	ctx := context.Background()
	loaded, err := b.Load(ctx, spec, opts)
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(loaded, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	fmt.Println(string(output))
	return nil
}
