// Package noop provides a no-op signature verifier.
package noop

import (
	"context"
)

// Verifier is a no-op signature verifier that always succeeds.
// Use this when signature verification is disabled via configuration.
type Verifier struct{}

// Verify always returns nil, indicating success.
func (Verifier) Verify(ctx context.Context, imageRef string) error {
	return nil
}
