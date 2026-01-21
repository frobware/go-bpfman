// Package memory provides an in-memory fake ImagePuller for testing.
package memory

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
)

// FakePuller is an in-memory ImagePuller for testing.
type FakePuller struct {
	mu     sync.RWMutex
	images map[string]interpreter.PulledImage
	logger *slog.Logger

	// PullCount tracks the number of Pull calls per URL.
	PullCount map[string]int

	// PullError allows tests to inject errors.
	PullError error
}

// Option configures a FakePuller.
type Option func(*FakePuller)

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(p *FakePuller) {
		p.logger = logger
	}
}

// NewFakePuller creates a new in-memory fake puller.
func NewFakePuller(opts ...Option) *FakePuller {
	p := &FakePuller{
		images:    make(map[string]interpreter.PulledImage),
		PullCount: make(map[string]int),
		logger:    slog.Default(),
	}

	for _, opt := range opts {
		opt(p)
	}

	p.logger.Debug("created fake image puller")
	return p
}

// AddImage registers an image that can be "pulled".
func (p *FakePuller) AddImage(url string, image interpreter.PulledImage) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.logger.Debug("registering fake image", "url", url, "digest", image.Digest)
	p.images[url] = image
}

// RemoveImage removes a registered image.
func (p *FakePuller) RemoveImage(url string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.logger.Debug("removing fake image", "url", url)
	delete(p.images, url)
}

// Pull implements interpreter.ImagePuller.
func (p *FakePuller) Pull(ctx context.Context, ref interpreter.ImageRef) (interpreter.PulledImage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.logger.Info("fake pulling image", "url", ref.URL, "policy", ref.PullPolicy.String())
	p.PullCount[ref.URL]++

	if p.PullError != nil {
		p.logger.Error("fake pull error", "error", p.PullError)
		return interpreter.PulledImage{}, p.PullError
	}

	image, ok := p.images[ref.URL]
	if !ok {
		err := fmt.Errorf("image not found: %s", ref.URL)
		p.logger.Error("fake pull failed", "error", err)
		return interpreter.PulledImage{}, err
	}

	p.logger.Info("fake pull successful", "url", ref.URL, "digest", image.Digest)
	return image, nil
}

// Reset clears all state.
func (p *FakePuller) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.logger.Debug("resetting fake puller")
	p.images = make(map[string]interpreter.PulledImage)
	p.PullCount = make(map[string]int)
	p.PullError = nil
}

// Ensure FakePuller implements ImagePuller.
var _ interpreter.ImagePuller = (*FakePuller)(nil)
