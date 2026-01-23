package client_test

import (
	"context"
	"fmt"
	"log"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/client"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
)

func ExampleDial() {
	c, err := client.Dial(client.DefaultSocketPath())
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	programs, err := c.List(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range programs {
		fmt.Printf("Program %d: %s\n", p.KernelProgram.ID, p.KernelProgram.Name)
	}
}

func ExampleOpen() {
	c, err := client.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	programs, err := c.List(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d programs\n", len(programs))
}

func ExampleClient_Load() {
	c, err := client.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	spec := managed.LoadSpec{
		ObjectPath:  "/path/to/program.o",
		ProgramName: "my_xdp_prog",
		ProgramType: bpfman.ProgramTypeXDP,
	}

	prog, err := c.Load(context.Background(), spec, manager.LoadOpts{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Loaded program with kernel ID %d\n", prog.Kernel.ID())
}

func ExampleClient_List() {
	c, err := client.Dial(client.DefaultSocketPath())
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	programs, err := c.List(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	for _, p := range programs {
		fmt.Printf("%d\t%s\t%s\n", p.KernelProgram.ID, p.KernelProgram.ProgramType, p.KernelProgram.Name)
	}
}
