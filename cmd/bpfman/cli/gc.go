package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/frobware/go-bpfman/client"
	"github.com/frobware/go-bpfman/manager"
)

// GCCmd garbage collects orphaned resources.
type GCCmd struct {
	Prune     bool          `help:"Actually delete (default: dry-run)."`
	MinAge    time.Duration `help:"Minimum orphan age before collection." default:"5m"`
	Orphans   bool          `help:"Only orphaned pins (no DB entry)."`
	DBOrphans bool          `help:"Only orphan DB entries (no kernel object)."`
	Max       int           `help:"Maximum deletions (0=unlimited)." default:"0"`
}

// Run executes the gc command.
func (c *GCCmd) Run(cli *CLI) error {
	cfg := manager.DefaultGCConfig()
	cfg.MinOrphanAge = c.MinAge
	cfg.MaxDeletions = c.Max

	// If prune flag is set, actually delete
	if c.Prune {
		cfg.DryRun = false
	}

	// If any specific filter is provided, disable all by default
	if c.Orphans || c.DBOrphans {
		cfg.IncludeOrphans = c.Orphans
		cfg.IncludeDBOrphans = c.DBOrphans
	}

	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	ctx := context.Background()

	// Plan GC
	plan, err := b.PlanGC(ctx, cfg)
	if errors.Is(err, client.ErrNotSupported) {
		return fmt.Errorf("garbage collection is only available in local mode")
	}
	if err != nil {
		return fmt.Errorf("failed to plan GC: %w", err)
	}

	// Print plan grouped by reason
	counts := plan.CountByReason()

	if len(plan.Items) == 0 {
		fmt.Println("Nothing to clean up.")
		return nil
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

	// Print orphan DB entries
	if counts[manager.GCOrphanDB] > 0 {
		fmt.Printf("Orphan DB entries (%d):\n", counts[manager.GCOrphanDB])
		for _, item := range plan.Items {
			if item.Reason == manager.GCOrphanDB {
				fmt.Printf("  kernel_id=%d  pin=%s  age=%s\n", item.KernelID, item.PinPath, item.Age.Truncate(time.Second))
			}
		}
		fmt.Println()
	}

	// Apply if not dry-run
	if cfg.DryRun {
		fmt.Printf("Total: %d items. Run with --prune to delete.\n", len(plan.Items))
		return nil
	}

	result, err := b.ApplyGC(ctx, plan)
	if err != nil {
		return fmt.Errorf("failed to apply GC: %w", err)
	}

	fmt.Printf("GC complete: %d deleted, %d failed, %d skipped\n",
		result.Deleted, result.Failed, result.Skipped)

	// Print failures
	for _, item := range result.Items {
		if item.Error != nil {
			fmt.Printf("  FAILED: kernel_id=%d pin=%s (%s): %v\n", item.Item.KernelID, item.Item.PinPath, item.Item.Reason, item.Error)
		}
	}

	return nil
}
