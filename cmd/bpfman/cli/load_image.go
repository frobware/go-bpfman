package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/client"
	"github.com/frobware/go-bpfman/interpreter"
)

// LoadImageCmd loads BPF programs from an OCI container image.
type LoadImageCmd struct {
	OutputFlags
	MetadataFlags
	GlobalDataFlags

	ImageURL     string          `short:"i" name:"image-url" help:"OCI image reference (e.g., quay.io/bpfman-bytecode/xdp_pass:latest)." required:""`
	Programs     []ProgramSpec   `name:"programs" help:"TYPE:NAME or TYPE:NAME:ATTACH_FUNC program to load (can be repeated). For fentry/fexit, ATTACH_FUNC is required." required:""`
	PullPolicy   ImagePullPolicy `short:"p" name:"pull-policy" help:"Image pull policy (Always, IfNotPresent, Never)." default:"IfNotPresent"`
	RegistryAuth string          `name:"registry-auth" help:"Base64-encoded registry auth (username:password)."`
	Application  string          `short:"a" name:"application" help:"Application name to group programs (stored as bpfman.io/application metadata)."`
	MapOwnerID   uint32          `name:"map-owner-id" help:"Program ID of another program to share maps with."`
}

// Run executes the load image command.
func (c *LoadImageCmd) Run(cli *CLI, ctx context.Context) error {
	logger, err := cli.Logger()
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	logger.Info("loading BPF programs from OCI image",
		"image", c.ImageURL,
		"programs", len(c.Programs),
		"pull_policy", c.PullPolicy.Value,
	)

	// Parse pull policy (before acquiring lock)
	pullPolicy, ok := bpfman.ParseImagePullPolicy(c.PullPolicy.Value)
	if !ok {
		return fmt.Errorf("invalid pull policy %q", c.PullPolicy.Value)
	}

	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

	results, err := RunWithLockValue(ctx, cli, func(ctx context.Context) ([]bpfman.ManagedProgram, error) {
		// Build auth config from base64-encoded registry-auth
		var authConfig *interpreter.ImageAuth
		if c.RegistryAuth != "" {
			username, password, err := parseRegistryAuth(c.RegistryAuth)
			if err != nil {
				return nil, fmt.Errorf("invalid registry-auth: %w", err)
			}
			logger.Debug("using registry auth", "username", username)
			authConfig = &interpreter.ImageAuth{
				Username: username,
				Password: password,
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

		// Build metadata map, adding application if specified
		metadata := MetadataMap(c.Metadata)
		if c.Application != "" {
			if metadata == nil {
				metadata = make(map[string]string)
			}
			metadata["bpfman.io/application"] = c.Application
		}

		// Build ImageProgramSpecs for each program
		programs := make([]client.ImageProgramSpec, 0, len(c.Programs))
		for _, spec := range c.Programs {
			var progSpec client.ImageProgramSpec
			var specErr error
			if spec.Type.RequiresAttachFunc() {
				progSpec, specErr = client.NewImageProgramSpecWithAttach(spec.Name, spec.Type, spec.AttachFunc)
			} else {
				progSpec, specErr = client.NewImageProgramSpec(spec.Name, spec.Type)
			}
			if specErr != nil {
				return nil, fmt.Errorf("invalid program spec for %q: %w", spec.Name, specErr)
			}
			if globalData != nil {
				progSpec = progSpec.WithGlobalData(globalData)
			}
			if c.MapOwnerID != 0 {
				progSpec = progSpec.WithMapOwnerID(c.MapOwnerID)
			}
			programs = append(programs, progSpec)
		}

		// Load via gRPC - server handles image pulling
		results, err := b.LoadImage(ctx, ref, programs, client.LoadImageOpts{
			UserMetadata: metadata,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to load from image: %w", err)
		}

		for _, loaded := range results {
			logger.Info("program loaded successfully",
				"name", loaded.Kernel.Name(),
				"kernel_id", loaded.Kernel.ID(),
				"pin_path", loaded.Managed.PinPath,
			)
		}

		return results, nil
	})
	if err != nil {
		return err
	}

	// Format and emit output outside the lock
	output, err := FormatLoadedPrograms(results, &c.OutputFlags)
	if err != nil {
		return err
	}
	return cli.PrintOut(output)
}

// parseRegistryAuth parses a base64-encoded "username:password" string.
func parseRegistryAuth(encoded string) (username, password string, err error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", fmt.Errorf("invalid base64 encoding: %w", err)
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected 'username:password' format")
	}

	return parts[0], parts[1], nil
}
