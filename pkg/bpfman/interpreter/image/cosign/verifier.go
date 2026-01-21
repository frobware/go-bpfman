// Package cosign provides sigstore/cosign signature verification for OCI images.
package cosign

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

// Verifier verifies OCI image signatures using cosign/sigstore.
type Verifier struct {
	logger        *slog.Logger
	allowUnsigned bool
	// Identity constraints for certificate verification
	issuerRegexp  string
	subjectRegexp string
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(v *Verifier) {
		v.logger = logger
	}
}

// WithAllowUnsigned controls whether unsigned images are accepted.
func WithAllowUnsigned(allow bool) Option {
	return func(v *Verifier) {
		v.allowUnsigned = allow
	}
}

// WithIdentity sets the certificate identity constraints.
// Use ".*" for either value to accept any valid certificate.
func WithIdentity(issuerRegexp, subjectRegexp string) Option {
	return func(v *Verifier) {
		v.issuerRegexp = issuerRegexp
		v.subjectRegexp = subjectRegexp
	}
}

// NewVerifier creates a new cosign signature verifier.
func NewVerifier(opts ...Option) *Verifier {
	v := &Verifier{
		logger:        slog.Default(),
		allowUnsigned: true, // Permissive default
		issuerRegexp:  ".*", // Accept any issuer by default
		subjectRegexp: ".*", // Accept any subject by default
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify checks that the image has a valid sigstore signature.
func (v *Verifier) Verify(ctx context.Context, imageRef string) error {
	logger := v.logger.With("image", imageRef)
	logger.Debug("verifying image signature")

	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("failed to parse image reference: %w", err)
	}

	// Get Fulcio root certificates for keyless verification
	rootCerts, err := fulcio.GetRoots()
	if err != nil {
		return fmt.Errorf("failed to get Fulcio root certificates: %w", err)
	}

	intermediateCerts, err := fulcio.GetIntermediates()
	if err != nil {
		return fmt.Errorf("failed to get Fulcio intermediate certificates: %w", err)
	}

	// Create Rekor client for transparency log verification
	rekorClient, err := rekor.NewClient(options.DefaultRekorURL)
	if err != nil {
		return fmt.Errorf("failed to create Rekor client: %w", err)
	}

	// Get Rekor public keys for verifying transparency log entries
	rekorPubKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Rekor public keys: %w", err)
	}

	// Get CT log public keys for SCT verification
	ctLogPubKeys, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CT log public keys: %w", err)
	}

	// Build verification options for keyless (Fulcio) verification
	// This is the standard sigstore public good instance
	co := &cosign.CheckOpts{
		RekorClient:       rekorClient,
		RekorPubKeys:      rekorPubKeys,
		RootCerts:         rootCerts,
		IntermediateCerts: intermediateCerts,
		CTLogPubKeys:      ctLogPubKeys,
		// Identity constraints for certificate verification
		// These specify which certificates are trusted
		Identities: []cosign.Identity{
			{
				IssuerRegExp:  v.issuerRegexp,
				SubjectRegExp: v.subjectRegexp,
			},
		},
	}

	// Attempt to verify signatures
	logger.Debug("calling cosign.VerifyImageSignatures",
		"issuer_regexp", v.issuerRegexp,
		"subject_regexp", v.subjectRegexp,
	)
	signatures, bundleVerified, err := cosign.VerifyImageSignatures(ctx, ref, co)
	if err != nil {
		logger.Debug("VerifyImageSignatures returned error", "error", err)
		// Check if this is a "no signatures found" error
		if isNoSignaturesError(err) {
			if v.allowUnsigned {
				logger.Debug("image has no signatures, but unsigned images are allowed")
				return nil
			}
			logger.Error("image has no signatures and unsigned images are not allowed")
			return fmt.Errorf("image %s has no signatures and unsigned images are not allowed", imageRef)
		}
		logger.Error("signature verification failed", "error", err)
		return fmt.Errorf("signature verification failed for %s: %w", imageRef, err)
	}

	logger.Info("image signature verified",
		"signatures", len(signatures),
		"bundle_verified", bundleVerified,
	)

	return nil
}

// isNoSignaturesError checks if the error indicates no signatures were found.
func isNoSignaturesError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "no matching signatures") ||
		strings.Contains(errMsg, "no signatures found") ||
		strings.Contains(errMsg, "MANIFEST_UNKNOWN")
}
