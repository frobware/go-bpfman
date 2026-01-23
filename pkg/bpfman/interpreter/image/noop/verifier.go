// Package noop provides a no-op signature verifier.
package noop

import (
	"context"

	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
)

// verifier is a no-op signature verifier that always succeeds.
// Use this when signature verification is disabled via configuration.
type verifier struct{}

// NewVerifier creates a no-op signature verifier.
func NewVerifier() interpreter.SignatureVerifier {
	return verifier{}
}

// Verify always returns nil, indicating success.
func (verifier) Verify(ctx context.Context, imageRef string) error {
	return nil
}
