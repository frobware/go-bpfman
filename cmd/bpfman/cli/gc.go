package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

// GCCmd garbage collects stale and orphaned resources.
type GCCmd struct {
	Prune     bool          `help:"Actually delete (default: dry-run)."`
	TTL       time.Duration `help:"Stale loading TTL." default:"5m"`
	Loading   bool          `help:"Only stale loading reservations."`
	Unloading bool          `help:"Only stale unloading entries."`
	Errors    bool          `help:"Only error entries."`
	Orphans   bool          `help:"Only orphaned pins."`
	Max       int           `help:"Maximum deletions (0=unlimited)." default:"0"`
}

// Run executes the gc command.
func (c *GCCmd) Run(cli *CLI) error {
	cfg := manager.DefaultGCConfig()
	cfg.StaleLoadingTTL = c.TTL
	cfg.MaxDeletions = c.Max

	// If prune flag is set, actually delete
	if c.Prune {
		cfg.DryRun = false
	}

	// If any specific filter is provided, disable all by default
	if c.Loading || c.Unloading || c.Errors || c.Orphans {
		cfg.IncludeLoading = c.Loading
		cfg.IncludeUnloading = c.Unloading
		cfg.IncludeError = c.Errors
		cfg.IncludeOrphans = c.Orphans
	}

	// Set up manager
	mgr, cleanup, err := manager.Setup(cli.DB.Path, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return fmt.Errorf("failed to set up manager: %w", err)
	}
	defer cleanup()

	ctx := context.Background()

	// Plan GC
	plan, err := mgr.PlanGC(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to plan GC: %w", err)
	}

	// Print plan grouped by reason
	counts := plan.CountByReason()

	if len(plan.Items) == 0 {
		fmt.Println("Nothing to clean up.")
		return nil
	}

	// Print stale loading
	if counts[manager.GCStaleLoading] > 0 {
		fmt.Printf("Stale loading reservations (%d):\n", counts[manager.GCStaleLoading])
		for _, item := range plan.Items {
			if item.Reason == manager.GCStaleLoading {
				fmt.Printf("  uuid=%s  age=%s  pin=%s\n", item.UUID, item.Age.Truncate(time.Second), item.PinPath)
			}
		}
		fmt.Println()
	}

	// Print stale unloading
	if counts[manager.GCStaleUnloading] > 0 {
		fmt.Printf("Stale unloading entries (%d):\n", counts[manager.GCStaleUnloading])
		for _, item := range plan.Items {
			if item.Reason == manager.GCStaleUnloading {
				fmt.Printf("  uuid=%s  age=%s  pin=%s\n", item.UUID, item.Age.Truncate(time.Second), item.PinPath)
			}
		}
		fmt.Println()
	}

	// Print error entries
	if counts[manager.GCStateError] > 0 {
		fmt.Printf("Error entries (%d):\n", counts[manager.GCStateError])
		for _, item := range plan.Items {
			if item.Reason == manager.GCStateError {
				errMsg := item.ErrorMsg
				if len(errMsg) > 60 {
					errMsg = errMsg[:60] + "..."
				}
				fmt.Printf("  uuid=%s  error=%q  pin=%s\n", item.UUID, errMsg, item.PinPath)
			}
		}
		fmt.Println()
	}

	// Print orphan pins
	if counts[manager.GCOrphanPin] > 0 {
		fmt.Printf("Orphaned pins (%d):\n", counts[manager.GCOrphanPin])
		for _, item := range plan.Items {
			if item.Reason == manager.GCOrphanPin {
				fmt.Printf("  path=%s  age=%s\n", item.PinPath, item.Age.Truncate(time.Second))
			}
		}
		fmt.Println()
	}

	// Apply if not dry-run
	if cfg.DryRun {
		fmt.Printf("Total: %d items. Run with --prune to delete.\n", len(plan.Items))
		return nil
	}

	result, err := mgr.ApplyGC(ctx, plan)
	if err != nil {
		return fmt.Errorf("failed to apply GC: %w", err)
	}

	fmt.Printf("GC complete: %d deleted, %d failed, %d skipped\n",
		result.Deleted, result.Failed, result.Skipped)

	// Print failures
	for _, item := range result.Items {
		if item.Error != nil {
			fmt.Printf("  FAILED: %s (%s): %v\n", item.Item.UUID, item.Item.Reason, item.Error)
		}
	}

	return nil
}
