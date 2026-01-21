package cli

import (
	"context"
	"fmt"

	"github.com/frobware/go-bpfman/pkg/bpfman/config"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/image/cosign"
)

// ImageCmd groups image-related subcommands.
type ImageCmd struct {
	Verify ImageVerifyCmd `cmd:"" help:"Verify an OCI image signature."`
}

// ImageVerifyCmd verifies the signature of an OCI image.
type ImageVerifyCmd struct {
	ImageURL string `arg:"" name:"image" help:"OCI image reference (e.g., quay.io/bpfman-bytecode/xdp_pass:latest)."`

	// Signing configuration
	AllowUnsigned *bool `name:"allow-unsigned" help:"Allow unsigned images (overrides config file)."`
}

// Run executes the image verify command.
func (c *ImageVerifyCmd) Run(cli *CLI) error {
	logger, err := cli.Logger()
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	logger.Info("verifying image signature", "image", c.ImageURL)

	// Load configuration (use CLI's config, not the deprecated --config flag)
	cfg, err := cli.LoadConfig()
	if err != nil {
		logger.Warn("failed to load config file, using defaults", "path", cli.Config, "error", err)
		cfg = config.DefaultConfig()
	}

	// Apply CLI overrides
	if c.AllowUnsigned != nil {
		cfg.Signing.AllowUnsigned = *c.AllowUnsigned
	}

	// For verify command, always enable verification (that's the point)
	cfg.Signing.VerifyEnabled = true

	logger.Debug("signing configuration",
		"allow_unsigned", cfg.Signing.AllowUnsigned,
	)

	// Create verifier
	verifier := cosign.NewVerifier(
		cosign.WithLogger(logger),
		cosign.WithAllowUnsigned(cfg.Signing.AllowUnsigned),
	)

	// Verify
	ctx := context.Background()
	if err := verifier.Verify(ctx, c.ImageURL); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Printf("Image %s: signature verified\n", c.ImageURL)
	return nil
}
