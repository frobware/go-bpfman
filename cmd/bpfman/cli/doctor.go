package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/frobware/go-bpfman/client"
	"github.com/frobware/go-bpfman/manager"
)

// DoctorCmd checks coherency of database, kernel, and filesystem state.
type DoctorCmd struct{}

// Run executes the doctor command.
func (c *DoctorCmd) Run(cli *CLI, ctx context.Context) error {
	b, err := cli.Client(ctx)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}
	defer b.Close()

	report, err := b.Doctor(ctx)
	if errors.Is(err, client.ErrNotSupported) {
		return fmt.Errorf("doctor is only available in local mode")
	}
	if err != nil {
		return fmt.Errorf("doctor failed: %w", err)
	}

	if len(report.Findings) == 0 {
		return cli.PrintOut("All checks passed. Database, kernel, and filesystem are coherent.\n")
	}

	// Build output in memory then write once
	var out strings.Builder
	var errorCount, warningCount int
	lastCategory := ""

	for _, f := range report.Findings {
		category := categoryHeading(f.Category)
		if category != lastCategory {
			if lastCategory != "" {
				out.WriteString("\n")
			}
			out.WriteString(category)
			out.WriteString("\n")
			lastCategory = category
		}
		fmt.Fprintf(&out, "  %-7s  %s\n", f.Severity, f.Description)
		switch f.Severity {
		case manager.SeverityError:
			errorCount++
		case manager.SeverityWarning:
			warningCount++
		}
	}

	fmt.Fprintf(&out, "\nSummary: %d error(s), %d warning(s)\n", errorCount, warningCount)

	return cli.PrintOut(out.String())
}

func categoryHeading(cat string) string {
	switch cat {
	case "db-vs-kernel":
		return "Checking database vs kernel..."
	case "db-vs-fs":
		return "Checking database vs filesystem..."
	case "fs-vs-db":
		return "Checking filesystem for orphans..."
	case "consistency":
		return "Checking derived state consistency..."
	default:
		return cat
	}
}
