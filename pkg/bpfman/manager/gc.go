// Package manager provides high-level orchestration using
// the fetch/compute/execute pattern.

package manager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
)

// GCConfig configures garbage collection behaviour.
type GCConfig struct {
	// Now is the reference time for staleness calculations.
	// If zero, time.Now() is used.
	Now time.Time

	// StaleLoadingTTL is how long a loading reservation can exist
	// before being considered stale. Default: 5 minutes.
	StaleLoadingTTL time.Duration

	// StaleUnloadingTTL is how long an unloading entry can exist
	// before being considered stale. Default: 5 minutes.
	StaleUnloadingTTL time.Duration

	// Which classes of garbage to include.
	IncludeLoading   bool
	IncludeUnloading bool
	IncludeError     bool
	IncludeOrphans   bool

	// DryRun prevents any modifications when true.
	DryRun bool

	// MaxDeletions limits how many items can be deleted in one run.
	// Zero means no limit.
	MaxDeletions int

	// BpfmanRoot is the root directory for bpfman-owned pins.
	// Default: /sys/fs/bpf/bpfman
	BpfmanRoot string
}

// DefaultGCConfig returns a GCConfig with sensible defaults.
func DefaultGCConfig() GCConfig {
	return GCConfig{
		Now:               time.Now(),
		StaleLoadingTTL:   5 * time.Minute,
		StaleUnloadingTTL: 5 * time.Minute,
		IncludeLoading:    true,
		IncludeUnloading:  true,
		IncludeError:      true,
		IncludeOrphans:    true,
		DryRun:            true, // Safe by default
		MaxDeletions:      0,
		BpfmanRoot:        "/sys/fs/bpf/bpfman",
	}
}

// GCReason describes why an item is considered garbage.
type GCReason string

const (
	// GCStaleLoading indicates a reservation that has been in loading
	// state longer than the TTL.
	GCStaleLoading GCReason = "stale_loading"

	// GCStaleUnloading indicates an entry that has been in unloading
	// state longer than the TTL (interrupted unload 2PC).
	GCStaleUnloading GCReason = "stale_unloading"

	// GCStateError indicates a reservation that failed and was marked
	// as error state.
	GCStateError GCReason = "state_error"

	// GCOrphanPin indicates a pin directory under the bpfman root that
	// has no corresponding loaded entry in the database.
	GCOrphanPin GCReason = "orphan_pin"
)

// GCItem represents a single item identified for garbage collection.
type GCItem struct {
	Reason    GCReason
	UUID      string
	PinPath   string
	State     managed.State
	UpdatedAt time.Time
	Age       time.Duration
	ErrorMsg  string
}

// GCPlan contains the items identified for garbage collection.
type GCPlan struct {
	Items    []GCItem
	Config   GCConfig
	PlanTime time.Time
}

// CountByReason returns counts grouped by reason.
func (p GCPlan) CountByReason() map[GCReason]int {
	counts := make(map[GCReason]int)
	for _, item := range p.Items {
		counts[item.Reason]++
	}
	return counts
}

// GCItemResult records the outcome of attempting to clean up an item.
type GCItemResult struct {
	Item    GCItem
	Deleted bool
	Error   error
}

// GCResult summarises the outcome of applying a GC plan.
type GCResult struct {
	Attempted int
	Deleted   int
	Failed    int
	Skipped   int // Due to MaxDeletions limit
	Items     []GCItemResult
}

// PlanGC discovers what would be cleaned and why, without side effects.
func (m *Manager) PlanGC(ctx context.Context, cfg GCConfig) (GCPlan, error) {
	if cfg.Now.IsZero() {
		cfg.Now = time.Now()
	}
	if cfg.StaleLoadingTTL == 0 {
		cfg.StaleLoadingTTL = 5 * time.Minute
	}
	if cfg.BpfmanRoot == "" {
		cfg.BpfmanRoot = "/sys/fs/bpf/bpfman"
	}

	plan := GCPlan{
		Config:   cfg,
		PlanTime: cfg.Now,
	}

	// Collect stale loading reservations
	if cfg.IncludeLoading {
		items, err := m.planStaleLoading(ctx, cfg)
		if err != nil {
			return plan, fmt.Errorf("plan stale loading: %w", err)
		}
		plan.Items = append(plan.Items, items...)
	}

	// Collect stale unloading entries (interrupted 2PC)
	if cfg.IncludeUnloading {
		items, err := m.planStaleUnloading(ctx, cfg)
		if err != nil {
			return plan, fmt.Errorf("plan stale unloading: %w", err)
		}
		plan.Items = append(plan.Items, items...)
	}

	// Collect error entries
	if cfg.IncludeError {
		items, err := m.planErrorEntries(ctx, cfg)
		if err != nil {
			return plan, fmt.Errorf("plan error entries: %w", err)
		}
		plan.Items = append(plan.Items, items...)
	}

	// Collect orphan pins
	if cfg.IncludeOrphans {
		items, err := m.planOrphanPins(ctx, cfg)
		if err != nil {
			return plan, fmt.Errorf("plan orphan pins: %w", err)
		}
		plan.Items = append(plan.Items, items...)
	}

	return plan, nil
}

func (m *Manager) planStaleLoading(ctx context.Context, cfg GCConfig) ([]GCItem, error) {
	entries, err := m.store.ListByState(ctx, managed.StateLoading)
	if err != nil {
		return nil, err
	}

	cutoff := cfg.Now.Add(-cfg.StaleLoadingTTL)
	var items []GCItem

	for _, e := range entries {
		if e.Metadata.UpdatedAt.Before(cutoff) {
			items = append(items, GCItem{
				Reason:    GCStaleLoading,
				UUID:      e.Metadata.UUID,
				PinPath:   e.Metadata.LoadSpec.PinPath,
				State:     e.Metadata.State,
				UpdatedAt: e.Metadata.UpdatedAt,
				Age:       cfg.Now.Sub(e.Metadata.UpdatedAt),
			})
		}
	}

	return items, nil
}

func (m *Manager) planStaleUnloading(ctx context.Context, cfg GCConfig) ([]GCItem, error) {
	entries, err := m.store.ListByState(ctx, managed.StateUnloading)
	if err != nil {
		return nil, err
	}

	cutoff := cfg.Now.Add(-cfg.StaleUnloadingTTL)
	var items []GCItem

	for _, e := range entries {
		if e.Metadata.UpdatedAt.Before(cutoff) {
			items = append(items, GCItem{
				Reason:    GCStaleUnloading,
				UUID:      e.Metadata.UUID,
				PinPath:   e.Metadata.LoadSpec.PinPath,
				State:     e.Metadata.State,
				UpdatedAt: e.Metadata.UpdatedAt,
				Age:       cfg.Now.Sub(e.Metadata.UpdatedAt),
			})
		}
	}

	return items, nil
}

func (m *Manager) planErrorEntries(ctx context.Context, cfg GCConfig) ([]GCItem, error) {
	entries, err := m.store.ListByState(ctx, managed.StateError)
	if err != nil {
		return nil, err
	}

	var items []GCItem
	for _, e := range entries {
		items = append(items, GCItem{
			Reason:    GCStateError,
			UUID:      e.Metadata.UUID,
			PinPath:   e.Metadata.LoadSpec.PinPath,
			State:     e.Metadata.State,
			UpdatedAt: e.Metadata.UpdatedAt,
			Age:       cfg.Now.Sub(e.Metadata.UpdatedAt),
			ErrorMsg:  e.Metadata.ErrorMessage,
		})
	}

	return items, nil
}

func (m *Manager) planOrphanPins(ctx context.Context, cfg GCConfig) ([]GCItem, error) {
	// Get all loaded programs from DB
	loaded, err := m.store.List(ctx)
	if err != nil {
		return nil, err
	}

	// Build set of known pin paths
	knownPaths := make(map[string]bool)
	for _, meta := range loaded {
		knownPaths[meta.LoadSpec.PinPath] = true
	}

	// Also include loading/unloading/error entries (we don't want to double-report)
	loading, _ := m.store.ListByState(ctx, managed.StateLoading)
	for _, e := range loading {
		knownPaths[e.Metadata.LoadSpec.PinPath] = true
	}
	unloading, _ := m.store.ListByState(ctx, managed.StateUnloading)
	for _, e := range unloading {
		knownPaths[e.Metadata.LoadSpec.PinPath] = true
	}
	errors, _ := m.store.ListByState(ctx, managed.StateError)
	for _, e := range errors {
		knownPaths[e.Metadata.LoadSpec.PinPath] = true
	}

	// Scan bpfman root for directories
	entries, err := os.ReadDir(cfg.BpfmanRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No bpfman root, no orphans
		}
		return nil, fmt.Errorf("read bpfman root: %w", err)
	}

	var items []GCItem
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pinPath := filepath.Join(cfg.BpfmanRoot, entry.Name())
		if knownPaths[pinPath] {
			continue // Known, not an orphan
		}

		// Get directory info for age
		info, err := entry.Info()
		var modTime time.Time
		if err == nil {
			modTime = info.ModTime()
		}

		items = append(items, GCItem{
			Reason:    GCOrphanPin,
			UUID:      entry.Name(), // Directory name is typically the UUID
			PinPath:   pinPath,
			UpdatedAt: modTime,
			Age:       cfg.Now.Sub(modTime),
		})
	}

	return items, nil
}

// ApplyGC executes a GC plan, returning per-item results.
func (m *Manager) ApplyGC(ctx context.Context, plan GCPlan) (GCResult, error) {
	result := GCResult{
		Items: make([]GCItemResult, 0, len(plan.Items)),
	}

	if plan.Config.DryRun {
		// In dry-run mode, report all items as skipped
		for _, item := range plan.Items {
			result.Items = append(result.Items, GCItemResult{
				Item:    item,
				Deleted: false,
			})
		}
		result.Skipped = len(plan.Items)
		return result, nil
	}

	for _, item := range plan.Items {
		// Check deletion limit
		if plan.Config.MaxDeletions > 0 && result.Deleted >= plan.Config.MaxDeletions {
			result.Skipped++
			result.Items = append(result.Items, GCItemResult{
				Item:    item,
				Deleted: false,
			})
			continue
		}

		result.Attempted++
		itemResult := GCItemResult{Item: item}

		var err error
		switch item.Reason {
		case GCStaleLoading, GCStaleUnloading, GCStateError:
			err = m.cleanupDBEntry(ctx, item)
		case GCOrphanPin:
			err = m.cleanupOrphanPin(ctx, item)
		}

		if err != nil {
			itemResult.Error = err
			result.Failed++
		} else {
			itemResult.Deleted = true
			result.Deleted++
		}
		result.Items = append(result.Items, itemResult)
	}

	return result, nil
}

func (m *Manager) cleanupDBEntry(ctx context.Context, item GCItem) error {
	// Attempt to unpin first (best effort)
	if item.PinPath != "" {
		_ = m.kernel.Unload(ctx, item.PinPath)
	}

	// Delete the DB reservation
	return m.store.DeleteReservation(ctx, item.UUID)
}

func (m *Manager) cleanupOrphanPin(ctx context.Context, item GCItem) error {
	return m.kernel.Unload(ctx, item.PinPath)
}
