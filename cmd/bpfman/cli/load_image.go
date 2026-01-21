package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/image/oci"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	"github.com/frobware/go-bpfman/pkg/bpfman/server"
)

// LoadImageCmd loads BPF programs from an OCI container image.
type LoadImageCmd struct {
	MetadataFlags
	GlobalDataFlags

	ImageURL     string          `arg:"" name:"image" help:"OCI image reference (e.g., quay.io/bpfman-bytecode/xdp_pass:latest)."`
	Programs     []ProgramSpec   `short:"p" name:"program" help:"TYPE:NAME program to load (can be repeated)." required:""`
	PullPolicy   ImagePullPolicy `name:"pull-policy" help:"Image pull policy (Always, IfNotPresent, Never)." default:"IfNotPresent"`
	Username     string          `name:"username" help:"Registry username for authentication."`
	Password     string          `name:"password" help:"Registry password for authentication."`
	RegistryAuth string          `name:"registry-auth" help:"Base64-encoded registry auth (alternative to username/password)."`
	CacheDir     string          `name:"cache-dir" help:"Image cache directory (default: ~/.cache/bpfman/images)."`
}

// Run executes the load image command.
func (c *LoadImageCmd) Run(cli *CLI) error {
	// Set up logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

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

	// Create image puller options
	pullerOpts := []oci.Option{oci.WithLogger(logger)}
	if c.CacheDir != "" {
		pullerOpts = append(pullerOpts, oci.WithCacheDir(c.CacheDir))
	}

	puller, err := oci.NewPuller(pullerOpts...)
	if err != nil {
		return fmt.Errorf("failed to create image puller: %w", err)
	}

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

	// Pull the image
	ctx := context.Background()
	logger.Info("pulling image", "url", c.ImageURL)

	pulledImage, err := puller.Pull(ctx, ref)
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}

	logger.Info("image pulled successfully",
		"digest", pulledImage.Digest,
		"object_path", pulledImage.ObjectPath,
		"available_programs", pulledImage.Programs,
	)

	// Validate requested programs exist in the image
	for _, spec := range c.Programs {
		if len(pulledImage.Programs) > 0 {
			// Image has program metadata - validate against it
			expectedType, exists := pulledImage.Programs[spec.Name]
			if !exists {
				available := make([]string, 0, len(pulledImage.Programs))
				for name := range pulledImage.Programs {
					available = append(available, name)
				}
				return fmt.Errorf("program %q not found in image; available programs: %v", spec.Name, available)
			}

			// Warn if type mismatch (but don't fail - image metadata might be incomplete)
			if expectedType != "" && expectedType != spec.Type {
				logger.Warn("program type mismatch",
					"program", spec.Name,
					"specified", spec.Type,
					"image_metadata", expectedType,
				)
			}
		}
	}

	// Set up manager
	mgr, cleanup, err := manager.Setup(cli.DB.Path, logger)
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	// Convert global data
	var globalData map[string][]byte
	if len(c.GlobalData) > 0 {
		globalData = GlobalDataMap(c.GlobalData)
	}

	// Load each program
	results := make([]managed.Loaded, 0, len(c.Programs))

	for _, spec := range c.Programs {
		logger.Info("loading program",
			"name", spec.Name,
			"type", spec.Type,
		)

		// Parse program type
		progType, ok := bpfman.ParseProgramType(spec.Type)
		if !ok {
			return fmt.Errorf("invalid program type %q for program %q", spec.Type, spec.Name)
		}

		// Generate UUID and derive pin path
		programUUID := uuid.New().String()
		pinDir := filepath.Join(server.DefaultBpfmanRoot, programUUID)

		// Build load spec
		loadSpec := managed.LoadSpec{
			ObjectPath:  pulledImage.ObjectPath,
			ProgramName: spec.Name,
			ProgramType: progType,
			PinPath:     pinDir,
			GlobalData:  globalData,
			ImageSource: &managed.ImageSource{
				URL:        c.ImageURL,
				Digest:     pulledImage.Digest,
				PullPolicy: pullPolicy,
			},
		}

		opts := manager.LoadOpts{
			UUID:         programUUID,
			UserMetadata: MetadataMap(c.Metadata),
		}

		// Load through manager (transactional)
		loaded, err := mgr.Load(ctx, loadSpec, opts)
		if err != nil {
			// If we've already loaded some programs, report partial success
			if len(results) > 0 {
				logger.Error("partial load failure",
					"loaded", len(results),
					"failed_at", spec.Name,
					"error", err,
				)
			}
			return fmt.Errorf("failed to load program %q: %w", spec.Name, err)
		}

		logger.Info("program loaded successfully",
			"name", spec.Name,
			"kernel_id", loaded.ID,
			"pin_path", loaded.PinPath,
		)

		results = append(results, loaded)
	}

	// Output results
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	fmt.Println(string(output))
	return nil
}
