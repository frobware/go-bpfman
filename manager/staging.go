package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// stagingTx represents a staging transaction for bpffs pins.
// All kernel pins land in the staging directory first, then get
// promoted to their final paths after the store commits.
type stagingTx struct {
	id         string            // unique transaction ID
	dir        string            // staging directory path
	promotions map[string]string // staging path -> final path
}

// newStagingTx creates a new staging transaction.
// The staging directory is created under {bpffsRoot}/.staging/{txid}/
func newStagingTx(bpffsRoot string) (*stagingTx, error) {
	id := uuid.New().String()
	dir := filepath.Join(bpffsRoot, ".staging", id)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	return &stagingTx{
		id:         id,
		dir:        dir,
		promotions: make(map[string]string),
	}, nil
}

// stagingPath returns a staging path for the given final path.
// The staging name is a hash of the final path to avoid collisions.
func (tx *stagingTx) stagingPath(finalPath string) string {
	// Hash the final path to get a unique, collision-free name
	sum := sha256.Sum256([]byte(finalPath))
	name := hex.EncodeToString(sum[:8]) // 16 hex chars
	return filepath.Join(tx.dir, name)
}

// stage registers a pin for later promotion.
// Returns the staging path where the kernel should pin.
func (tx *stagingTx) stage(finalPath string) string {
	staging := tx.stagingPath(finalPath)
	tx.promotions[staging] = finalPath
	return staging
}

// promote moves all staged pins to their final locations.
// Call this AFTER the store transaction has committed.
func (tx *stagingTx) promote() error {
	for staging, final := range tx.promotions {
		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(final), 0755); err != nil {
			return err
		}
		// Atomic rename
		if err := os.Rename(staging, final); err != nil {
			return err
		}
	}
	return nil
}

// cleanup removes the staging directory.
// Safe to call whether promote succeeded or not.
func (tx *stagingTx) cleanup() {
	os.RemoveAll(tx.dir)
}
