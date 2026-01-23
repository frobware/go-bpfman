package cli

import (
	"context"
	"fmt"

	"github.com/frobware/go-bpfman/client"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/managed"
)

// LoadImageCmd loads BPF programs from an OCI container image.
type LoadImageCmd struct {
	OutputFlags
	MetadataFlags
	GlobalDataFlags

	ImageURL   string          `arg:"" name:"image" help:"OCI image reference (e.g., quay.io/bpfman-bytecode/xdp_pass:latest)."`
	Programs   []ProgramSpec   `short:"p" name:"program" help:"TYPE:NAME program to load (can be repeated)." required:""`
	PullPolicy ImagePullPolicy `name:"pull-policy" help:"Image pull policy (Always, IfNotPresent, Never)." default:"IfNotPresent"`
	Username   string          `name:"username" help:"Registry username for authentication."`
	Password   string          `name:"password" help:"Registry password for authentication."`
}

// Run executes the load image command.
func (c *LoadImageCmd) Run(cli *CLI) error {
	logger, err := cli.Logger()
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	logger.Info("loading BPF programs from OCI image",
		"image", c.ImageURL,
		"programs", len(c.Programs),
		"pull_policy", c.PullPolicy.Value,
	)

	// Parse pull policy
	pullPolicy, ok := managed.ParseImagePullPolicy(c.PullPolicy.Value)
	if !ok {
		return fmt.Errorf("invalid pull policy %q", c.PullPolicy.Value)
	}

	// Get client
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	// Build auth config
	var authConfig *interpreter.ImageAuth
	if c.Username != "" {
		logger.Debug("using explicit credentials", "username", c.Username)
		authConfig = &interpreter.ImageAuth{
			Username: c.Username,
			Password: c.Password,
		}
	}

	// Build image reference
	ref := interpreter.ImageRef{
		URL:        c.ImageURL,
		PullPolicy: pullPolicy,
		Auth:       authConfig,
	}

	// Convert global data
	var globalData map[string][]byte
	if len(c.GlobalData) > 0 {
		globalData = GlobalDataMap(c.GlobalData)
	}

	// Build LoadSpecs for each program
	programs := make([]managed.LoadSpec, 0, len(c.Programs))
	for _, spec := range c.Programs {
		programs = append(programs, managed.LoadSpec{
			ProgramName: spec.Name,
			ProgramType: spec.Type,
			GlobalData:  globalData,
		})
	}

	// Load via gRPC - server handles image pulling
	ctx := context.Background()
	results, err := b.LoadImage(ctx, ref, programs, client.LoadImageOpts{
		UserMetadata: MetadataMap(c.Metadata),
	})
	if err != nil {
		return fmt.Errorf("failed to load from image: %w", err)
	}

	for _, loaded := range results {
		logger.Info("program loaded successfully",
			"name", loaded.Kernel.Name(),
			"kernel_id", loaded.Kernel.ID(),
			"pin_path", loaded.Managed.PinPath(),
		)
	}

	// Output results
	output, err := FormatLoadedPrograms(results, &c.OutputFlags)
	if err != nil {
		return err
	}

	fmt.Print(output)
	return nil
}
