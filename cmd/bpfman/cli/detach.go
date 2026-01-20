package cli

import (
	"fmt"
)

// DetachCmd detaches a link.
type DetachCmd struct {
	LinkUUID LinkUUID `arg:"" name:"link-uuid" help:"UUID of the link to detach."`
}

// Run executes the detach command.
func (c *DetachCmd) Run(cli *CLI) error {
	// Detach is not yet implemented in the manager
	return fmt.Errorf("detach not yet implemented for link %s", c.LinkUUID.Value)
}
