// bpfman is a minimal BPF program manager.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/frobware/go-bpfman/cmd/bpfman/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		os.Exit(1)
	}()

	cli.Run(ctx)
}
