package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/frobware/go-bpfman/client"
	"github.com/frobware/go-bpfman/manager"
)

// Doctor2Cmd checks coherency using the rule engine.
type Doctor2Cmd struct{}

// Run executes the doctor2 command.
func (c *Doctor2Cmd) Run(cli *CLI) error {
	b, err := cli.Client()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer b.Close()

	ctx := context.Background()

	report, err := b.Doctor2(ctx)
	if errors.Is(err, client.ErrNotSupported) {
		return fmt.Errorf("doctor2 is only available in local mode")
	}
	if err != nil {
		return fmt.Errorf("doctor2 failed: %w", err)
	}

	if len(report.Findings) == 0 {
		fmt.Println("All checks passed. Database, kernel, and filesystem are coherent. (rule engine)")
		return nil
	}

	var errorCount, warningCount int
	lastCategory := ""

	for _, f := range report.Findings {
		category := categoryHeading(f.Category)
		if category != lastCategory {
			if lastCategory != "" {
				fmt.Println()
			}
			fmt.Println(category)
			lastCategory = category
		}
		fmt.Printf("  %-7s  %s\n", f.Severity, f.Description)
		switch f.Severity {
		case manager.SeverityError:
			errorCount++
		case manager.SeverityWarning:
			warningCount++
		}
	}

	fmt.Printf("\nSummary: %d error(s), %d warning(s) (rule engine)\n", errorCount, warningCount)

	return nil
}
