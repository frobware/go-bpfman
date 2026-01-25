// Package manager provides high-level orchestration using
// the fetch/compute/execute pattern.

package manager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// GCConfig configures garbage collection behaviour.
type GCConfig struct {
	// Now is the reference time for staleness calculations.
	// If zero, time.Now() is used.
	Now time.Time

	// MinOrphanAge is the minimum age an orphan pin must be before
	// it can be collected. This prevents collecting pins that are
	// being created during a concurrent load operation.
	// Default: 5 minutes.
	MinOrphanAge time.Duration

	// IncludeOrphans controls whether orphan pins are collected.
	IncludeOrphans bool

	// IncludeDBOrphans controls whether DB entries without kernel
	// objects are collected.
	IncludeDBOrphans bool

	// DryRun prevents any modifications when true.
	DryRun bool

	// MaxDeletions limits how many items can be deleted in one run.
	// Zero means no limit.
	MaxDeletions int
}

// DefaultGCConfig returns a GCConfig with sensible defaults.
func DefaultGCConfig() GCConfig {
	return GCConfig{
		Now:              time.Now(),
		MinOrphanAge:     5 * time.Minute,
		IncludeOrphans:   true,
		IncludeDBOrphans: true,
		DryRun:           true, // Safe by default
		MaxDeletions:     0,
	}
}

// GCReason describes why an item is considered garbage.
type GCReason string

const (
	// GCOrphanPin indicates a pin directory under the bpfman root that
	// has no corresponding entry in the database. This can happen if
	// a crash occurs after kernel load but before DB persist.
	GCOrphanPin GCReason = "orphan_pin"

	// GCOrphanDB indicates a DB entry whose kernel object no longer
	// exists. This can happen if the kernel unloads a program (e.g.,
	// due to the last fd being closed).
	GCOrphanDB GCReason = "orphan_db"
)

// GCItem represents a single item identified for garbage collection.
type GCItem struct {
	Reason   GCReason
	KernelID uint32
	PinPath  string
	Age      time.Duration
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
	Skipped   int // Due to MaxDeletions limit or DryRun
	Items     []GCItemResult
}

// PlanGC discovers what would be cleaned and why, without side effects.
//
// With the atomic load model, GC focuses on two scenarios:
//  1. Orphan pins: Pins on bpffs without corresponding DB entries (crash recovery)
//  2. Orphan DB: DB entries without corresponding kernel objects (kernel cleanup)
func (m *Manager) PlanGC(ctx context.Context, cfg GCConfig) (GCPlan, error) {
	if cfg.Now.IsZero() {
		cfg.Now = time.Now()
	}
	if cfg.MinOrphanAge == 0 {
		cfg.MinOrphanAge = 5 * time.Minute
	}

	plan := GCPlan{
		Config:   cfg,
		PlanTime: cfg.Now,
	}

	// Collect orphan pins (pins on disk without DB entries)
	if cfg.IncludeOrphans {
		items, err := m.planOrphanPins(ctx, cfg)
		if err != nil {
			return plan, fmt.Errorf("plan orphan pins: %w", err)
		}
		plan.Items = append(plan.Items, items...)
	}

	// Collect orphan DB entries (DB entries without kernel objects)
	if cfg.IncludeDBOrphans {
		items, err := m.planOrphanDBEntries(ctx, cfg)
		if err != nil {
			return plan, fmt.Errorf("plan orphan DB entries: %w", err)
		}
		plan.Items = append(plan.Items, items...)
	}

	return plan, nil
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
		knownPaths[meta.PinPath] = true
	}

	// Scan bpfman root for directories
	bpfmanRoot := m.dirs.FS
	entries, err := os.ReadDir(bpfmanRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No bpfman root, no orphans
		}
		return nil, fmt.Errorf("read bpfman root: %w", err)
	}

	cutoff := cfg.Now.Add(-cfg.MinOrphanAge)
	var items []GCItem

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pinPath := filepath.Join(bpfmanRoot, entry.Name())
		if knownPaths[pinPath] {
			continue // Known, not an orphan
		}

		// Get directory info for age
		info, err := entry.Info()
		if err != nil {
			continue // Skip if we can't get info
		}

		modTime := info.ModTime()
		if modTime.After(cutoff) {
			continue // Too recent, might be in-flight load
		}

		items = append(items, GCItem{
			Reason:  GCOrphanPin,
			PinPath: pinPath,
			Age:     cfg.Now.Sub(modTime),
		})
	}

	return items, nil
}

func (m *Manager) planOrphanDBEntries(ctx context.Context, cfg GCConfig) ([]GCItem, error) {
	// Get all programs from DB
	stored, err := m.store.List(ctx)
	if err != nil {
		return nil, err
	}

	// Find DB entries whose pin paths no longer exist.
	// The pin path is the source of truth for ownership - if the
	// directory is gone, our program is gone (regardless of whether
	// some other program now has the same kernel ID).
	var items []GCItem
	for kernelID, meta := range stored {
		pinPath := meta.PinPath
		if _, err := os.Stat(pinPath); err == nil {
			continue // Pin path exists, not an orphan
		}

		items = append(items, GCItem{
			Reason:   GCOrphanDB,
			KernelID: kernelID,
			PinPath:  pinPath,
			Age:      cfg.Now.Sub(meta.CreatedAt),
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
		case GCOrphanPin:
			err = m.cleanupOrphanPin(ctx, item)
		case GCOrphanDB:
			err = m.cleanupOrphanDB(ctx, item)
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

func (m *Manager) cleanupOrphanPin(ctx context.Context, item GCItem) error {
	return m.kernel.Unload(ctx, item.PinPath)
}

func (m *Manager) cleanupOrphanDB(ctx context.Context, item GCItem) error {
	return m.store.Delete(ctx, item.KernelID)
}
