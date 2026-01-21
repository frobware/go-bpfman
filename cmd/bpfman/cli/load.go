package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	"github.com/frobware/go-bpfman/pkg/bpfman/server"
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

	// Set up manager
	mgr, cleanup, err := manager.Setup(cli.DB.Path, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	// Generate UUID and derive pin path
	programUUID := uuid.New().String()
	pinDir := filepath.Join(server.DefaultBpfmanRoot, programUUID)

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
		UUID:         programUUID,
		UserMetadata: MetadataMap(c.Metadata),
	}

	// Load through manager (transactional)
	ctx := context.Background()
	loaded, err := mgr.Load(ctx, spec, opts)
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
