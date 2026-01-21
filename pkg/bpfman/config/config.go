// Package config handles bpfman daemon configuration.
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

const (
	// DefaultConfigPath is the default path to the bpfman config file.
	DefaultConfigPath = "/etc/bpfman/bpfman.toml"
)

// Config is the top-level bpfman configuration.
type Config struct {
	Signing SigningConfig `toml:"signing"`
}

// SigningConfig controls image signature verification.
// These settings match the Rust bpfman implementation.
type SigningConfig struct {
	// AllowUnsigned controls whether unsigned images are accepted.
	// When true (default), unsigned images can be loaded.
	// When false, all images must have valid signatures.
	AllowUnsigned bool `toml:"allow_unsigned"`

	// VerifyEnabled controls whether signature verification is performed.
	// When true (default), images with signatures are verified.
	// When false, signature verification is skipped entirely.
	VerifyEnabled bool `toml:"verify_enabled"`
}

// DefaultConfig returns the default configuration with permissive defaults.
// This matches the Rust bpfman defaults for fail-safe operation.
func DefaultConfig() Config {
	return Config{
		Signing: SigningConfig{
			AllowUnsigned: true,
			VerifyEnabled: true,
		},
	}
}

// Load reads configuration from a file path.
// If the file does not exist, returns the default configuration.
func Load(path string) (Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}

	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Config file is optional - use defaults
			return cfg, nil
		}
		return cfg, fmt.Errorf("failed to read config file: %w", err)
	}

	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for consistency.
func (c *Config) Validate() error {
	// Currently no cross-field validation needed
	return nil
}

// MustRequireSignatures returns true if all images must be signed.
func (c *SigningConfig) MustRequireSignatures() bool {
	return !c.AllowUnsigned && c.VerifyEnabled
}

// ShouldVerify returns true if signature verification should be performed.
func (c *SigningConfig) ShouldVerify() bool {
	return c.VerifyEnabled
}
