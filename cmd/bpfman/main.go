// bpfman is a minimal BPF program manager.
package main

import (
	"github.com/alecthomas/kong"

	"github.com/frobware/go-bpfman/cmd/bpfman/cli"
)

func main() {
	var c cli.CLI
	ctx := kong.Parse(&c, cli.KongOptions()...)
	err := ctx.Run(&c)
	ctx.FatalIfErrorf(err)
}
