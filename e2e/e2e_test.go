//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/client"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/manager"
)

func TestMain(m *testing.M) {
	// Fail fast on prerequisites
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "e2e tests require root privileges")
		os.Exit(1)
	}

	// Clean up stale test directories from crashed runs
	cleanupStaleTestDirs()

	os.Exit(m.Run())
}

// TestTracepoint_LoadAttachDetachUnload tests the full lifecycle of a tracepoint program.
func TestTracepoint_LoadAttachDetachUnload(t *testing.T) {
	t.Parallel()
	RequireRoot(t)
	RequireTracepoint(t, "syscalls", "sys_enter_kill")

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// When: load from OCI image via client
	imageRef := interpreter.ImageRef{
		URL: "quay.io/bpfman-bytecode/go-tracepoint-counter:latest",
	}
	programs, err := env.Client.LoadImage(ctx, imageRef, []client.ImageProgramSpec{
		{
			ProgramType: bpfman.ProgramTypeTracepoint,
			ProgramName: "tracepoint_kill_recorder",
		},
	}, client.LoadImageOpts{})
	require.NoError(t, err)
	require.Len(t, programs, 1)

	prog := programs[0]

	// Then: program has expected properties
	require.NotZero(t, prog.Kernel.ID(), "kernel should assign program ID")
	require.Equal(t, bpfman.ProgramTypeTracepoint, prog.Kernel.Type())

	// Register cleanup for the program
	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Round-trip: Get should return matching program info
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Kernel)
	require.NotNil(t, gotProg.Kernel.Program)
	require.Equal(t, prog.Kernel.ID(), gotProg.Kernel.Program.ID)
	require.Equal(t, prog.Kernel.Type().String(), gotProg.Kernel.Program.ProgramType)
	// KernelInfo.Name should match the kernel-reported (truncated) name
	require.Equal(t, prog.Kernel.Name(), gotProg.Kernel.Program.Name)
	require.NotEmpty(t, gotProg.Kernel.Program.Tag, "kernel should assign tag")
	require.False(t, gotProg.Kernel.Program.LoadedAt.IsZero(), "kernel should track LoadedAt")
	// Verify bpfman-managed metadata has full name and pin path
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)
	require.Equal(t, "tracepoint_kill_recorder", gotProg.Bpfman.Program.ProgramName)
	require.NotEmpty(t, gotProg.Bpfman.Program.PinPath, "program should have pin path")
	// Kernel-reported name is truncated (16 chars max), verify it's a prefix of the full name
	kernelName := prog.Kernel.Name()
	require.True(t, strings.HasPrefix("tracepoint_kill_recorder", kernelName),
		"kernel name %q should be prefix of full name", kernelName)

	// Round-trip: List should include our program
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.Equal(t, prog.Kernel.ID(), listedProgs[0].KernelProgram.ID)
	require.Equal(t, prog.Kernel.Type().String(), listedProgs[0].KernelProgram.ProgramType)
	// KernelProgram.Name should match kernel-reported name
	require.Equal(t, kernelName, listedProgs[0].KernelProgram.Name)
	require.NotEmpty(t, listedProgs[0].KernelProgram.Tag)
	require.False(t, listedProgs[0].KernelProgram.LoadedAt.IsZero())
	// Metadata has full name
	require.NotNil(t, listedProgs[0].Metadata)
	require.Equal(t, "tracepoint_kill_recorder", listedProgs[0].Metadata.ProgramName)
	require.NotEmpty(t, listedProgs[0].Metadata.PinPath)

	// When: attach via client
	tpSpec, err := bpfman.NewTracepointAttachSpec(prog.Kernel.ID(), "syscalls", "sys_enter_kill")
	require.NoError(t, err)
	link, err := env.Client.AttachTracepoint(ctx, tpSpec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Then: link has expected properties
	require.NotZero(t, link.KernelLinkID, "kernel should assign link ID")
	require.Equal(t, bpfman.LinkTypeTracepoint, link.LinkType)
	require.Equal(t, prog.Kernel.ID(), link.KernelProgramID, "link should reference correct program")

	// Register cleanup for the link
	t.Cleanup(func() {
		env.Client.Detach(context.Background(), link.KernelLinkID)
	})

	// Round-trip: GetLink should return matching link info
	gotLinkSummary, gotLinkDetails, err := env.Client.GetLink(ctx, link.KernelLinkID)
	require.NoError(t, err)
	require.Equal(t, link.KernelLinkID, gotLinkSummary.KernelLinkID)
	require.Equal(t, link.LinkType, gotLinkSummary.LinkType)
	require.Equal(t, link.KernelProgramID, gotLinkSummary.KernelProgramID)
	// Verify tracepoint-specific details
	tpDetails, ok := gotLinkDetails.(bpfman.TracepointDetails)
	require.True(t, ok, "expected TracepointDetails, got %T", gotLinkDetails)
	require.Equal(t, "syscalls", tpDetails.Group)
	require.Equal(t, "sys_enter_kill", tpDetails.Name)

	// Round-trip: ListLinks should include our link
	listedLinks, err := env.Client.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, listedLinks, 1)
	require.Equal(t, link.KernelLinkID, listedLinks[0].KernelLinkID)
	require.Equal(t, link.LinkType, listedLinks[0].LinkType)
	require.Equal(t, link.KernelProgramID, listedLinks[0].KernelProgramID)

	// When: detach
	err = env.Client.Detach(ctx, link.KernelLinkID)
	require.NoError(t, err)

	// Then: no links, and GetLink should return error
	env.AssertLinkCount(0)
	_, _, err = env.Client.GetLink(ctx, link.KernelLinkID)
	require.Error(t, err, "GetLink should fail after detach")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state, and Get should return error
	env.AssertCleanState()
	_, err = env.Client.Get(ctx, prog.Kernel.ID())
	require.Error(t, err, "Get should fail after unload")
}

// TestKprobe_LoadAttachDetachUnload tests the full lifecycle of a kprobe program.
func TestKprobe_LoadAttachDetachUnload(t *testing.T) {
	t.Parallel()
	RequireRoot(t)
	RequireKernelFunction(t, "try_to_wake_up")

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// When: load from OCI image via client
	imageRef := interpreter.ImageRef{
		URL: "quay.io/bpfman-bytecode/go-kprobe-counter:latest",
	}
	programs, err := env.Client.LoadImage(ctx, imageRef, []client.ImageProgramSpec{
		{
			ProgramType: bpfman.ProgramTypeKprobe,
			ProgramName: "kprobe_counter",
		},
	}, client.LoadImageOpts{})
	require.NoError(t, err)
	require.Len(t, programs, 1)

	prog := programs[0]

	// Then: program has expected properties
	require.NotZero(t, prog.Kernel.ID(), "kernel should assign program ID")
	require.Equal(t, bpfman.ProgramTypeKprobe, prog.Kernel.Type())

	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Round-trip: Get should return matching program info
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Kernel)
	require.NotNil(t, gotProg.Kernel.Program)
	require.Equal(t, prog.Kernel.ID(), gotProg.Kernel.Program.ID)
	require.Equal(t, prog.Kernel.Type().String(), gotProg.Kernel.Program.ProgramType)
	require.Equal(t, prog.Kernel.Name(), gotProg.Kernel.Program.Name)
	require.NotEmpty(t, gotProg.Kernel.Program.Tag, "kernel should assign tag")
	require.False(t, gotProg.Kernel.Program.LoadedAt.IsZero(), "kernel should track LoadedAt")
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)
	require.Equal(t, "kprobe_counter", gotProg.Bpfman.Program.ProgramName)
	require.NotEmpty(t, gotProg.Bpfman.Program.PinPath, "program should have pin path")

	// Round-trip: List should include our program
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.Equal(t, prog.Kernel.ID(), listedProgs[0].KernelProgram.ID)
	require.Equal(t, prog.Kernel.Name(), listedProgs[0].KernelProgram.Name)
	require.NotEmpty(t, listedProgs[0].KernelProgram.Tag)
	require.False(t, listedProgs[0].KernelProgram.LoadedAt.IsZero())
	require.NotNil(t, listedProgs[0].Metadata)
	require.Equal(t, "kprobe_counter", listedProgs[0].Metadata.ProgramName)
	require.NotEmpty(t, listedProgs[0].Metadata.PinPath)

	// When: attach via client
	kpSpec, err := bpfman.NewKprobeAttachSpec(prog.Kernel.ID(), "try_to_wake_up")
	require.NoError(t, err)
	link, err := env.Client.AttachKprobe(ctx, kpSpec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Then: link has expected properties
	require.NotZero(t, link.KernelLinkID, "kernel should assign link ID")
	require.Equal(t, bpfman.LinkTypeKprobe, link.LinkType)
	require.Equal(t, prog.Kernel.ID(), link.KernelProgramID, "link should reference correct program")

	t.Cleanup(func() {
		env.Client.Detach(context.Background(), link.KernelLinkID)
	})

	// Round-trip: GetLink should return matching link info
	gotLinkSummary, gotLinkDetails, err := env.Client.GetLink(ctx, link.KernelLinkID)
	require.NoError(t, err)
	require.Equal(t, link.KernelLinkID, gotLinkSummary.KernelLinkID)
	require.Equal(t, link.LinkType, gotLinkSummary.LinkType)
	require.Equal(t, link.KernelProgramID, gotLinkSummary.KernelProgramID)
	kprobeDetails, ok := gotLinkDetails.(bpfman.KprobeDetails)
	require.True(t, ok, "expected KprobeDetails, got %T", gotLinkDetails)
	require.Equal(t, "try_to_wake_up", kprobeDetails.FnName)
	require.Equal(t, uint64(0), kprobeDetails.Offset, "offset should match what was passed")
	require.False(t, kprobeDetails.Retprobe)

	// Round-trip: ListLinks should include our link
	listedLinks, err := env.Client.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, listedLinks, 1)
	require.Equal(t, link.KernelLinkID, listedLinks[0].KernelLinkID)
	require.Equal(t, link.LinkType, listedLinks[0].LinkType)
	require.Equal(t, link.KernelProgramID, listedLinks[0].KernelProgramID)

	// When: detach
	err = env.Client.Detach(ctx, link.KernelLinkID)
	require.NoError(t, err)

	// Then: no links, and GetLink should return error
	env.AssertLinkCount(0)
	_, _, err = env.Client.GetLink(ctx, link.KernelLinkID)
	require.Error(t, err, "GetLink should fail after detach")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state, and Get should return error
	env.AssertCleanState()
	_, err = env.Client.Get(ctx, prog.Kernel.ID())
	require.Error(t, err, "Get should fail after unload")
}

// TestKretprobe_LoadAttachDetachUnload tests the full lifecycle of a kretprobe program.
func TestKretprobe_LoadAttachDetachUnload(t *testing.T) {
	t.Parallel()
	RequireRoot(t)
	RequireKernelFunction(t, "try_to_wake_up")

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// When: load from OCI image via client
	// Note: kretprobe uses the same image as kprobe but loads the kretprobe program
	imageRef := interpreter.ImageRef{
		URL: "quay.io/bpfman-bytecode/go-kprobe-counter:latest",
	}
	programs, err := env.Client.LoadImage(ctx, imageRef, []client.ImageProgramSpec{
		{
			ProgramType: bpfman.ProgramTypeKretprobe,
			ProgramName: "kprobe_counter", // Same program as kprobe, loaded as kretprobe
		},
	}, client.LoadImageOpts{})
	require.NoError(t, err)
	require.Len(t, programs, 1)

	prog := programs[0]

	// Then: program has expected properties
	require.NotZero(t, prog.Kernel.ID(), "kernel should assign program ID")
	require.Equal(t, bpfman.ProgramTypeKretprobe, prog.Kernel.Type())

	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Round-trip: Get should return matching program info
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Kernel)
	require.NotNil(t, gotProg.Kernel.Program)
	require.Equal(t, prog.Kernel.ID(), gotProg.Kernel.Program.ID)
	require.Equal(t, prog.Kernel.Type().String(), gotProg.Kernel.Program.ProgramType)
	require.Equal(t, prog.Kernel.Name(), gotProg.Kernel.Program.Name)
	require.NotEmpty(t, gotProg.Kernel.Program.Tag, "kernel should assign tag")
	require.False(t, gotProg.Kernel.Program.LoadedAt.IsZero(), "kernel should track LoadedAt")
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)
	require.Equal(t, "kprobe_counter", gotProg.Bpfman.Program.ProgramName)
	require.NotEmpty(t, gotProg.Bpfman.Program.PinPath, "program should have pin path")

	// Round-trip: List should include our program
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.Equal(t, prog.Kernel.ID(), listedProgs[0].KernelProgram.ID)
	require.Equal(t, prog.Kernel.Name(), listedProgs[0].KernelProgram.Name)
	require.NotEmpty(t, listedProgs[0].KernelProgram.Tag)
	require.False(t, listedProgs[0].KernelProgram.LoadedAt.IsZero())
	require.NotNil(t, listedProgs[0].Metadata)
	require.Equal(t, "kprobe_counter", listedProgs[0].Metadata.ProgramName)
	require.NotEmpty(t, listedProgs[0].Metadata.PinPath)

	// When: attach via client (kretprobe uses AttachKprobe API)
	kpSpec, err := bpfman.NewKprobeAttachSpec(prog.Kernel.ID(), "try_to_wake_up")
	require.NoError(t, err)
	link, err := env.Client.AttachKprobe(ctx, kpSpec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Then: link has expected properties
	// Note: AttachKprobe returns LinkTypeKprobe (the API doesn't know the program type),
	// but GetLink will return the authoritative LinkTypeKretprobe from the server.
	require.NotZero(t, link.KernelLinkID, "kernel should assign link ID")
	require.Equal(t, prog.Kernel.ID(), link.KernelProgramID, "link should reference correct program")

	t.Cleanup(func() {
		env.Client.Detach(context.Background(), link.KernelLinkID)
	})

	// Round-trip: GetLink should return authoritative link info from server
	gotLinkSummary, gotLinkDetails, err := env.Client.GetLink(ctx, link.KernelLinkID)
	require.NoError(t, err)
	require.Equal(t, link.KernelLinkID, gotLinkSummary.KernelLinkID)
	require.Equal(t, bpfman.LinkTypeKretprobe, gotLinkSummary.LinkType, "server should report kretprobe link type")
	require.Equal(t, link.KernelProgramID, gotLinkSummary.KernelProgramID)
	kprobeDetails, ok := gotLinkDetails.(bpfman.KprobeDetails)
	require.True(t, ok, "expected KprobeDetails, got %T", gotLinkDetails)
	require.Equal(t, "try_to_wake_up", kprobeDetails.FnName)
	require.Equal(t, uint64(0), kprobeDetails.Offset, "offset should match what was passed")
	require.True(t, kprobeDetails.Retprobe, "kretprobe should have Retprobe=true")

	// Round-trip: ListLinks should include our link
	listedLinks, err := env.Client.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, listedLinks, 1)
	require.Equal(t, link.KernelLinkID, listedLinks[0].KernelLinkID)
	require.Equal(t, bpfman.LinkTypeKretprobe, listedLinks[0].LinkType, "ListLinks should report kretprobe")
	require.Equal(t, link.KernelProgramID, listedLinks[0].KernelProgramID)

	// When: detach
	err = env.Client.Detach(ctx, link.KernelLinkID)
	require.NoError(t, err)

	// Then: no links, and GetLink should return error
	env.AssertLinkCount(0)
	_, _, err = env.Client.GetLink(ctx, link.KernelLinkID)
	require.Error(t, err, "GetLink should fail after detach")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state, and Get should return error
	env.AssertCleanState()
	_, err = env.Client.Get(ctx, prog.Kernel.ID())
	require.Error(t, err, "Get should fail after unload")
}

// TestUprobe_LoadAttachDetachUnload tests the full lifecycle of a uprobe program.
func TestUprobe_LoadAttachDetachUnload(t *testing.T) {
	t.Parallel()
	RequireRoot(t)

	target, fnName := uprobeTarget()
	if target == "" {
		t.Skip("libc not found at standard paths")
	}

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// When: load from OCI image via client
	imageRef := interpreter.ImageRef{
		URL: "quay.io/bpfman-bytecode/go-uprobe-counter:latest",
	}
	programs, err := env.Client.LoadImage(ctx, imageRef, []client.ImageProgramSpec{
		{
			ProgramType: bpfman.ProgramTypeUprobe,
			ProgramName: "uprobe_counter",
		},
	}, client.LoadImageOpts{})
	require.NoError(t, err)
	require.Len(t, programs, 1)

	prog := programs[0]

	// Then: program has expected properties
	require.NotZero(t, prog.Kernel.ID(), "kernel should assign program ID")
	require.Equal(t, bpfman.ProgramTypeUprobe, prog.Kernel.Type())

	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Round-trip: Get should return matching program info
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Kernel)
	require.NotNil(t, gotProg.Kernel.Program)
	require.Equal(t, prog.Kernel.ID(), gotProg.Kernel.Program.ID)
	require.Equal(t, prog.Kernel.Type().String(), gotProg.Kernel.Program.ProgramType)
	require.Equal(t, prog.Kernel.Name(), gotProg.Kernel.Program.Name)
	require.NotEmpty(t, gotProg.Kernel.Program.Tag, "kernel should assign tag")
	require.False(t, gotProg.Kernel.Program.LoadedAt.IsZero(), "kernel should track LoadedAt")
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)
	require.Equal(t, "uprobe_counter", gotProg.Bpfman.Program.ProgramName)
	require.NotEmpty(t, gotProg.Bpfman.Program.PinPath, "program should have pin path")

	// Round-trip: List should include our program
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.Equal(t, prog.Kernel.ID(), listedProgs[0].KernelProgram.ID)
	require.Equal(t, prog.Kernel.Name(), listedProgs[0].KernelProgram.Name)
	require.NotEmpty(t, listedProgs[0].KernelProgram.Tag)
	require.False(t, listedProgs[0].KernelProgram.LoadedAt.IsZero())
	require.NotNil(t, listedProgs[0].Metadata)
	require.Equal(t, "uprobe_counter", listedProgs[0].Metadata.ProgramName)
	require.NotEmpty(t, listedProgs[0].Metadata.PinPath)

	// When: attach via client to malloc in libc
	upSpec, err := bpfman.NewUprobeAttachSpec(prog.Kernel.ID(), target)
	require.NoError(t, err)
	upSpec = upSpec.WithFnName(fnName)
	link, err := env.Client.AttachUprobe(ctx, upSpec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Then: link has expected properties
	require.NotZero(t, link.KernelLinkID, "kernel should assign link ID")
	require.Equal(t, bpfman.LinkTypeUprobe, link.LinkType)
	require.Equal(t, prog.Kernel.ID(), link.KernelProgramID, "link should reference correct program")

	t.Cleanup(func() {
		env.Client.Detach(context.Background(), link.KernelLinkID)
	})

	// Round-trip: GetLink should return matching link info
	gotLinkSummary, gotLinkDetails, err := env.Client.GetLink(ctx, link.KernelLinkID)
	require.NoError(t, err)
	require.Equal(t, link.KernelLinkID, gotLinkSummary.KernelLinkID)
	require.Equal(t, link.LinkType, gotLinkSummary.LinkType)
	require.Equal(t, link.KernelProgramID, gotLinkSummary.KernelProgramID)
	uprobeDetails, ok := gotLinkDetails.(bpfman.UprobeDetails)
	require.True(t, ok, "expected UprobeDetails, got %T", gotLinkDetails)
	require.Equal(t, target, uprobeDetails.Target)
	require.Equal(t, fnName, uprobeDetails.FnName)
	require.Equal(t, uint64(0), uprobeDetails.Offset, "offset should match what was passed")
	require.False(t, uprobeDetails.Retprobe)

	// Round-trip: ListLinks should include our link
	listedLinks, err := env.Client.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, listedLinks, 1)
	require.Equal(t, link.KernelLinkID, listedLinks[0].KernelLinkID)
	require.Equal(t, link.LinkType, listedLinks[0].LinkType)
	require.Equal(t, link.KernelProgramID, listedLinks[0].KernelProgramID)

	// When: detach
	err = env.Client.Detach(ctx, link.KernelLinkID)
	require.NoError(t, err)

	// Then: no links, and GetLink should return error
	env.AssertLinkCount(0)
	_, _, err = env.Client.GetLink(ctx, link.KernelLinkID)
	require.Error(t, err, "GetLink should fail after detach")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state, and Get should return error
	env.AssertCleanState()
	_, err = env.Client.Get(ctx, prog.Kernel.ID())
	require.Error(t, err, "Get should fail after unload")
}

// TestUretprobe_LoadAttachDetachUnload tests the full lifecycle of a uretprobe program.
func TestUretprobe_LoadAttachDetachUnload(t *testing.T) {
	t.Parallel()
	RequireRoot(t)

	target, fnName := uprobeTarget()
	if target == "" {
		t.Skip("libc not found at standard paths")
	}

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// When: load from OCI image via client
	imageRef := interpreter.ImageRef{
		URL: "quay.io/bpfman-bytecode/go-uprobe-counter:latest",
	}
	programs, err := env.Client.LoadImage(ctx, imageRef, []client.ImageProgramSpec{
		{
			ProgramType: bpfman.ProgramTypeUretprobe,
			ProgramName: "uprobe_counter", // Same program as uprobe, loaded as uretprobe
		},
	}, client.LoadImageOpts{})
	require.NoError(t, err)
	require.Len(t, programs, 1)

	prog := programs[0]

	// Then: program has expected properties
	require.NotZero(t, prog.Kernel.ID(), "kernel should assign program ID")
	require.Equal(t, bpfman.ProgramTypeUretprobe, prog.Kernel.Type())

	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Round-trip: Get should return matching program info
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Kernel)
	require.NotNil(t, gotProg.Kernel.Program)
	require.Equal(t, prog.Kernel.ID(), gotProg.Kernel.Program.ID)
	require.Equal(t, prog.Kernel.Type().String(), gotProg.Kernel.Program.ProgramType)
	require.Equal(t, prog.Kernel.Name(), gotProg.Kernel.Program.Name)
	require.NotEmpty(t, gotProg.Kernel.Program.Tag, "kernel should assign tag")
	require.False(t, gotProg.Kernel.Program.LoadedAt.IsZero(), "kernel should track LoadedAt")
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)
	require.Equal(t, "uprobe_counter", gotProg.Bpfman.Program.ProgramName)
	require.NotEmpty(t, gotProg.Bpfman.Program.PinPath, "program should have pin path")

	// Round-trip: List should include our program
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.Equal(t, prog.Kernel.ID(), listedProgs[0].KernelProgram.ID)
	require.Equal(t, prog.Kernel.Name(), listedProgs[0].KernelProgram.Name)
	require.NotEmpty(t, listedProgs[0].KernelProgram.Tag)
	require.False(t, listedProgs[0].KernelProgram.LoadedAt.IsZero())
	require.NotNil(t, listedProgs[0].Metadata)
	require.Equal(t, "uprobe_counter", listedProgs[0].Metadata.ProgramName)
	require.NotEmpty(t, listedProgs[0].Metadata.PinPath)

	// When: attach via client to malloc in libc (uretprobe uses AttachUprobe API)
	upSpec, err := bpfman.NewUprobeAttachSpec(prog.Kernel.ID(), target)
	require.NoError(t, err)
	upSpec = upSpec.WithFnName(fnName)
	link, err := env.Client.AttachUprobe(ctx, upSpec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Then: link has expected properties
	// Note: AttachUprobe returns LinkTypeUprobe (the API doesn't know the program type),
	// but GetLink will return the authoritative LinkTypeUretprobe from the server.
	require.NotZero(t, link.KernelLinkID, "kernel should assign link ID")
	require.Equal(t, prog.Kernel.ID(), link.KernelProgramID, "link should reference correct program")

	t.Cleanup(func() {
		env.Client.Detach(context.Background(), link.KernelLinkID)
	})

	// Round-trip: GetLink should return authoritative link info from server
	gotLinkSummary, gotLinkDetails, err := env.Client.GetLink(ctx, link.KernelLinkID)
	require.NoError(t, err)
	require.Equal(t, link.KernelLinkID, gotLinkSummary.KernelLinkID)
	require.Equal(t, bpfman.LinkTypeUretprobe, gotLinkSummary.LinkType, "server should report uretprobe link type")
	require.Equal(t, link.KernelProgramID, gotLinkSummary.KernelProgramID)
	uprobeDetails, ok := gotLinkDetails.(bpfman.UprobeDetails)
	require.True(t, ok, "expected UprobeDetails, got %T", gotLinkDetails)
	require.Equal(t, target, uprobeDetails.Target)
	require.Equal(t, fnName, uprobeDetails.FnName)
	require.Equal(t, uint64(0), uprobeDetails.Offset, "offset should match what was passed")
	require.True(t, uprobeDetails.Retprobe, "uretprobe should have Retprobe=true")

	// Round-trip: ListLinks should include our link
	listedLinks, err := env.Client.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, listedLinks, 1)
	require.Equal(t, link.KernelLinkID, listedLinks[0].KernelLinkID)
	require.Equal(t, bpfman.LinkTypeUretprobe, listedLinks[0].LinkType, "ListLinks should report uretprobe")
	require.Equal(t, link.KernelProgramID, listedLinks[0].KernelProgramID)

	// When: detach
	err = env.Client.Detach(ctx, link.KernelLinkID)
	require.NoError(t, err)

	// Then: no links, and GetLink should return error
	env.AssertLinkCount(0)
	_, _, err = env.Client.GetLink(ctx, link.KernelLinkID)
	require.Error(t, err, "GetLink should fail after detach")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state, and Get should return error
	env.AssertCleanState()
	_, err = env.Client.Get(ctx, prog.Kernel.ID())
	require.Error(t, err, "Get should fail after unload")
}

// TestFentry_LoadAttachDetachUnload tests the full lifecycle of a fentry program.
func TestFentry_LoadAttachDetachUnload(t *testing.T) {
	t.Parallel()
	RequireRoot(t)
	RequireBTF(t)
	RequireKernelFunction(t, "do_unlinkat")

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// For fentry/fexit, we load from a local bytecode file
	// The attach function is specified at load time
	bytecodeFile := findBytecodeFile("fentry.bpf.o")
	if bytecodeFile == "" {
		t.Skip("fentry.bpf.o bytecode file not found")
	}

	// When: load from file via client
	spec, err := bpfman.NewAttachLoadSpec(bytecodeFile, "test_fentry", bpfman.ProgramTypeFentry, "do_unlinkat")
	require.NoError(t, err)
	prog, err := env.Client.Load(ctx, spec, manager.LoadOpts{})
	require.NoError(t, err)

	// Then: program has expected properties
	require.NotZero(t, prog.Kernel.ID(), "kernel should assign program ID")
	require.Equal(t, bpfman.ProgramTypeFentry, prog.Kernel.Type())

	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Round-trip: Get should return matching program info
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Kernel)
	require.NotNil(t, gotProg.Kernel.Program)
	require.Equal(t, prog.Kernel.ID(), gotProg.Kernel.Program.ID)
	require.Equal(t, prog.Kernel.Type().String(), gotProg.Kernel.Program.ProgramType)
	require.Equal(t, prog.Kernel.Name(), gotProg.Kernel.Program.Name)
	require.NotEmpty(t, gotProg.Kernel.Program.Tag, "kernel should assign tag")
	require.False(t, gotProg.Kernel.Program.LoadedAt.IsZero(), "kernel should track LoadedAt")
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)
	require.Equal(t, "test_fentry", gotProg.Bpfman.Program.ProgramName)
	require.NotEmpty(t, gotProg.Bpfman.Program.PinPath, "program should have pin path")

	// Round-trip: List should include our program
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.Equal(t, prog.Kernel.ID(), listedProgs[0].KernelProgram.ID)
	require.Equal(t, prog.Kernel.Name(), listedProgs[0].KernelProgram.Name)
	require.NotEmpty(t, listedProgs[0].KernelProgram.Tag)
	require.False(t, listedProgs[0].KernelProgram.LoadedAt.IsZero())
	require.NotNil(t, listedProgs[0].Metadata)
	require.Equal(t, "test_fentry", listedProgs[0].Metadata.ProgramName)
	require.NotEmpty(t, listedProgs[0].Metadata.PinPath)

	// When: attach via client (fentry doesn't need additional params - target is in program)
	feSpec, err := bpfman.NewFentryAttachSpec(prog.Kernel.ID())
	require.NoError(t, err)
	link, err := env.Client.AttachFentry(ctx, feSpec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Then: link has expected properties
	require.NotZero(t, link.KernelLinkID, "kernel should assign link ID")
	require.Equal(t, bpfman.LinkTypeFentry, link.LinkType)
	require.Equal(t, prog.Kernel.ID(), link.KernelProgramID, "link should reference correct program")

	t.Cleanup(func() {
		env.Client.Detach(context.Background(), link.KernelLinkID)
	})

	// Round-trip: GetLink should return matching link info
	gotLinkSummary, gotLinkDetails, err := env.Client.GetLink(ctx, link.KernelLinkID)
	require.NoError(t, err)
	require.Equal(t, link.KernelLinkID, gotLinkSummary.KernelLinkID)
	require.Equal(t, link.LinkType, gotLinkSummary.LinkType)
	require.Equal(t, link.KernelProgramID, gotLinkSummary.KernelProgramID)
	fentryDetails, ok := gotLinkDetails.(bpfman.FentryDetails)
	require.True(t, ok, "expected FentryDetails, got %T", gotLinkDetails)
	require.Equal(t, "do_unlinkat", fentryDetails.FnName)

	// Round-trip: ListLinks should include our link
	listedLinks, err := env.Client.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, listedLinks, 1)
	require.Equal(t, link.KernelLinkID, listedLinks[0].KernelLinkID)
	require.Equal(t, link.LinkType, listedLinks[0].LinkType)
	require.Equal(t, link.KernelProgramID, listedLinks[0].KernelProgramID)

	// When: detach
	err = env.Client.Detach(ctx, link.KernelLinkID)
	require.NoError(t, err)

	// Then: no links, and GetLink should return error
	env.AssertLinkCount(0)
	_, _, err = env.Client.GetLink(ctx, link.KernelLinkID)
	require.Error(t, err, "GetLink should fail after detach")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state, and Get should return error
	env.AssertCleanState()
	_, err = env.Client.Get(ctx, prog.Kernel.ID())
	require.Error(t, err, "Get should fail after unload")
}

// TestFexit_LoadAttachDetachUnload tests the full lifecycle of a fexit program.
func TestFexit_LoadAttachDetachUnload(t *testing.T) {
	t.Parallel()
	RequireRoot(t)
	RequireBTF(t)
	RequireKernelFunction(t, "do_unlinkat")

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// For fentry/fexit, we load from a local bytecode file
	bytecodeFile := findBytecodeFile("fentry.bpf.o")
	if bytecodeFile == "" {
		t.Skip("fentry.bpf.o bytecode file not found")
	}

	// When: load from file via client
	spec, err := bpfman.NewAttachLoadSpec(bytecodeFile, "test_fexit", bpfman.ProgramTypeFexit, "do_unlinkat")
	require.NoError(t, err)
	prog, err := env.Client.Load(ctx, spec, manager.LoadOpts{})
	require.NoError(t, err)

	// Then: program has expected properties
	require.NotZero(t, prog.Kernel.ID(), "kernel should assign program ID")
	require.Equal(t, bpfman.ProgramTypeFexit, prog.Kernel.Type())

	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Round-trip: Get should return matching program info
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Kernel)
	require.NotNil(t, gotProg.Kernel.Program)
	require.Equal(t, prog.Kernel.ID(), gotProg.Kernel.Program.ID)
	require.Equal(t, prog.Kernel.Type().String(), gotProg.Kernel.Program.ProgramType)
	require.Equal(t, prog.Kernel.Name(), gotProg.Kernel.Program.Name)
	require.NotEmpty(t, gotProg.Kernel.Program.Tag, "kernel should assign tag")
	require.False(t, gotProg.Kernel.Program.LoadedAt.IsZero(), "kernel should track LoadedAt")
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)
	require.Equal(t, "test_fexit", gotProg.Bpfman.Program.ProgramName)
	require.NotEmpty(t, gotProg.Bpfman.Program.PinPath, "program should have pin path")

	// Round-trip: List should include our program
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.Equal(t, prog.Kernel.ID(), listedProgs[0].KernelProgram.ID)
	require.Equal(t, prog.Kernel.Name(), listedProgs[0].KernelProgram.Name)
	require.NotEmpty(t, listedProgs[0].KernelProgram.Tag)
	require.False(t, listedProgs[0].KernelProgram.LoadedAt.IsZero())
	require.NotNil(t, listedProgs[0].Metadata)
	require.Equal(t, "test_fexit", listedProgs[0].Metadata.ProgramName)
	require.NotEmpty(t, listedProgs[0].Metadata.PinPath)

	// When: attach via client
	fxSpec, err := bpfman.NewFexitAttachSpec(prog.Kernel.ID())
	require.NoError(t, err)
	link, err := env.Client.AttachFexit(ctx, fxSpec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Then: link has expected properties
	require.NotZero(t, link.KernelLinkID, "kernel should assign link ID")
	require.Equal(t, bpfman.LinkTypeFexit, link.LinkType)
	require.Equal(t, prog.Kernel.ID(), link.KernelProgramID, "link should reference correct program")

	t.Cleanup(func() {
		env.Client.Detach(context.Background(), link.KernelLinkID)
	})

	// Round-trip: GetLink should return matching link info
	gotLinkSummary, gotLinkDetails, err := env.Client.GetLink(ctx, link.KernelLinkID)
	require.NoError(t, err)
	require.Equal(t, link.KernelLinkID, gotLinkSummary.KernelLinkID)
	require.Equal(t, link.LinkType, gotLinkSummary.LinkType)
	require.Equal(t, link.KernelProgramID, gotLinkSummary.KernelProgramID)
	fexitDetails, ok := gotLinkDetails.(bpfman.FexitDetails)
	require.True(t, ok, "expected FexitDetails, got %T", gotLinkDetails)
	require.Equal(t, "do_unlinkat", fexitDetails.FnName)

	// Round-trip: ListLinks should include our link
	listedLinks, err := env.Client.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, listedLinks, 1)
	require.Equal(t, link.KernelLinkID, listedLinks[0].KernelLinkID)
	require.Equal(t, link.LinkType, listedLinks[0].LinkType)
	require.Equal(t, link.KernelProgramID, listedLinks[0].KernelProgramID)

	// When: detach
	err = env.Client.Detach(ctx, link.KernelLinkID)
	require.NoError(t, err)

	// Then: no links, and GetLink should return error
	env.AssertLinkCount(0)
	_, _, err = env.Client.GetLink(ctx, link.KernelLinkID)
	require.Error(t, err, "GetLink should fail after detach")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state, and Get should return error
	env.AssertCleanState()
	_, err = env.Client.Get(ctx, prog.Kernel.ID())
	require.Error(t, err, "Get should fail after unload")
}

// TestTC_LoadAttachDetachUnload tests the full lifecycle of a TC program.
// TC programs use dispatchers for multi-program support.
func TestTC_LoadAttachDetachUnload(t *testing.T) {
	t.Parallel()
	RequireRoot(t)

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// When: load from OCI image via client
	imageRef := interpreter.ImageRef{
		URL: "quay.io/bpfman-bytecode/go-tc-counter:latest",
	}
	programs, err := env.Client.LoadImage(ctx, imageRef, []client.ImageProgramSpec{
		{
			ProgramType: bpfman.ProgramTypeTC,
			ProgramName: "stats",
		},
	}, client.LoadImageOpts{})
	require.NoError(t, err)
	require.Len(t, programs, 1)

	prog := programs[0]

	// Then: program has expected properties
	require.NotZero(t, prog.Kernel.ID(), "kernel should assign program ID")
	require.Equal(t, bpfman.ProgramTypeTC, prog.Kernel.Type())

	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Round-trip: Get should return matching program info
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Kernel)
	require.NotNil(t, gotProg.Kernel.Program)
	require.Equal(t, prog.Kernel.ID(), gotProg.Kernel.Program.ID)
	require.Equal(t, prog.Kernel.Type().String(), gotProg.Kernel.Program.ProgramType)
	require.Equal(t, prog.Kernel.Name(), gotProg.Kernel.Program.Name)
	require.NotEmpty(t, gotProg.Kernel.Program.Tag, "kernel should assign tag")
	require.False(t, gotProg.Kernel.Program.LoadedAt.IsZero(), "kernel should track LoadedAt")
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)
	require.Equal(t, "stats", gotProg.Bpfman.Program.ProgramName)
	require.NotEmpty(t, gotProg.Bpfman.Program.PinPath, "program should have pin path")

	// Round-trip: List should include our program
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.Equal(t, prog.Kernel.ID(), listedProgs[0].KernelProgram.ID)
	require.Equal(t, prog.Kernel.Name(), listedProgs[0].KernelProgram.Name)
	require.NotEmpty(t, listedProgs[0].KernelProgram.Tag)
	require.False(t, listedProgs[0].KernelProgram.LoadedAt.IsZero())
	require.NotNil(t, listedProgs[0].Metadata)
	require.Equal(t, "stats", listedProgs[0].Metadata.ProgramName)
	require.NotEmpty(t, listedProgs[0].Metadata.PinPath)

	// When: attach via client to lo interface (always available)
	// TC uses dispatchers and supports both ingress and egress
	tcSpec, err := bpfman.NewTCAttachSpec(prog.Kernel.ID(), "lo", 1, "ingress")
	require.NoError(t, err)
	tcSpec = tcSpec.WithPriority(50)
	link, err := env.Client.AttachTC(ctx, tcSpec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Then: link has expected properties
	require.NotZero(t, link.KernelLinkID, "kernel should assign link ID")
	require.Equal(t, bpfman.LinkTypeTC, link.LinkType)
	require.Equal(t, prog.Kernel.ID(), link.KernelProgramID, "link should reference correct program")

	t.Cleanup(func() {
		env.Client.Detach(context.Background(), link.KernelLinkID)
	})

	// Round-trip: GetLink should return matching link info
	gotLinkSummary, gotLinkDetails, err := env.Client.GetLink(ctx, link.KernelLinkID)
	require.NoError(t, err)
	require.Equal(t, link.KernelLinkID, gotLinkSummary.KernelLinkID)
	require.Equal(t, link.LinkType, gotLinkSummary.LinkType)
	require.Equal(t, link.KernelProgramID, gotLinkSummary.KernelProgramID)
	tcDetails, ok := gotLinkDetails.(bpfman.TCDetails)
	require.True(t, ok, "expected TCDetails, got %T", gotLinkDetails)
	require.Equal(t, "lo", tcDetails.Interface)
	require.Equal(t, uint32(1), tcDetails.Ifindex, "ifindex should match lo")
	require.Equal(t, "ingress", tcDetails.Direction)
	require.Equal(t, int32(50), tcDetails.Priority)
	require.NotZero(t, tcDetails.DispatcherID, "TC should use dispatcher")
	require.NotZero(t, tcDetails.Revision, "dispatcher should have revision")

	// Round-trip: ListLinks should include our link
	listedLinks, err := env.Client.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, listedLinks, 1)
	require.Equal(t, link.KernelLinkID, listedLinks[0].KernelLinkID)
	require.Equal(t, link.LinkType, listedLinks[0].LinkType)
	require.Equal(t, link.KernelProgramID, listedLinks[0].KernelProgramID)

	// When: detach
	err = env.Client.Detach(ctx, link.KernelLinkID)
	require.NoError(t, err)

	// Then: no links, and GetLink should return error
	env.AssertLinkCount(0)
	_, _, err = env.Client.GetLink(ctx, link.KernelLinkID)
	require.Error(t, err, "GetLink should fail after detach")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state, and Get should return error
	env.AssertCleanState()
	_, err = env.Client.Get(ctx, prog.Kernel.ID())
	require.Error(t, err, "Get should fail after unload")
}

// TestTCX_LoadAttachDetachUnload tests the full lifecycle of a TCX program.
// TCX requires kernel 6.6+ and uses native multi-program support.
func TestTCX_LoadAttachDetachUnload(t *testing.T) {
	t.Parallel()
	RequireRoot(t)
	RequireKernelVersion(t, 6, 6)

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// When: load from OCI image via client
	imageRef := interpreter.ImageRef{
		URL: "quay.io/bpfman-bytecode/go-tc-counter:latest",
	}
	programs, err := env.Client.LoadImage(ctx, imageRef, []client.ImageProgramSpec{
		{
			ProgramType: bpfman.ProgramTypeTCX,
			ProgramName: "stats",
		},
	}, client.LoadImageOpts{})
	require.NoError(t, err)
	require.Len(t, programs, 1)

	prog := programs[0]

	// Then: program has expected properties
	require.NotZero(t, prog.Kernel.ID(), "kernel should assign program ID")
	require.Equal(t, bpfman.ProgramTypeTCX, prog.Kernel.Type())

	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Round-trip: Get should return matching program info
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Kernel)
	require.NotNil(t, gotProg.Kernel.Program)
	require.Equal(t, prog.Kernel.ID(), gotProg.Kernel.Program.ID)
	require.Equal(t, prog.Kernel.Type().String(), gotProg.Kernel.Program.ProgramType)
	require.Equal(t, prog.Kernel.Name(), gotProg.Kernel.Program.Name)
	require.NotEmpty(t, gotProg.Kernel.Program.Tag, "kernel should assign tag")
	require.False(t, gotProg.Kernel.Program.LoadedAt.IsZero(), "kernel should track LoadedAt")
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)
	require.Equal(t, "stats", gotProg.Bpfman.Program.ProgramName)
	require.NotEmpty(t, gotProg.Bpfman.Program.PinPath, "program should have pin path")

	// Round-trip: List should include our program
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.Equal(t, prog.Kernel.ID(), listedProgs[0].KernelProgram.ID)
	require.Equal(t, prog.Kernel.Name(), listedProgs[0].KernelProgram.Name)
	require.NotEmpty(t, listedProgs[0].KernelProgram.Tag)
	require.False(t, listedProgs[0].KernelProgram.LoadedAt.IsZero())
	require.NotNil(t, listedProgs[0].Metadata)
	require.Equal(t, "stats", listedProgs[0].Metadata.ProgramName)
	require.NotEmpty(t, listedProgs[0].Metadata.PinPath)

	// When: attach via client to lo interface
	tcxSpec, err := bpfman.NewTCXAttachSpec(prog.Kernel.ID(), "lo", 1, "ingress")
	require.NoError(t, err)
	tcxSpec = tcxSpec.WithPriority(50)
	link, err := env.Client.AttachTCX(ctx, tcxSpec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Then: link has expected properties
	require.NotZero(t, link.KernelLinkID, "kernel should assign link ID")
	require.Equal(t, bpfman.LinkTypeTCX, link.LinkType)
	require.Equal(t, prog.Kernel.ID(), link.KernelProgramID, "link should reference correct program")

	t.Cleanup(func() {
		env.Client.Detach(context.Background(), link.KernelLinkID)
	})

	// Round-trip: GetLink should return matching link info
	gotLinkSummary, gotLinkDetails, err := env.Client.GetLink(ctx, link.KernelLinkID)
	require.NoError(t, err)
	require.Equal(t, link.KernelLinkID, gotLinkSummary.KernelLinkID)
	require.Equal(t, link.LinkType, gotLinkSummary.LinkType)
	require.Equal(t, link.KernelProgramID, gotLinkSummary.KernelProgramID)
	tcxDetails, ok := gotLinkDetails.(bpfman.TCXDetails)
	require.True(t, ok, "expected TCXDetails, got %T", gotLinkDetails)
	require.Equal(t, "lo", tcxDetails.Interface)
	require.Equal(t, uint32(1), tcxDetails.Ifindex, "ifindex should match lo")
	require.Equal(t, "ingress", tcxDetails.Direction)
	require.Equal(t, int32(50), tcxDetails.Priority)
	// TCX uses native kernel multi-prog support, not dispatchers

	// Round-trip: ListLinks should include our link
	listedLinks, err := env.Client.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, listedLinks, 1)
	require.Equal(t, link.KernelLinkID, listedLinks[0].KernelLinkID)
	require.Equal(t, link.LinkType, listedLinks[0].LinkType)
	require.Equal(t, link.KernelProgramID, listedLinks[0].KernelProgramID)

	// When: detach
	err = env.Client.Detach(ctx, link.KernelLinkID)
	require.NoError(t, err)

	// Then: no links, and GetLink should return error
	env.AssertLinkCount(0)
	_, _, err = env.Client.GetLink(ctx, link.KernelLinkID)
	require.Error(t, err, "GetLink should fail after detach")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state, and Get should return error
	env.AssertCleanState()
	_, err = env.Client.Get(ctx, prog.Kernel.ID())
	require.Error(t, err, "Get should fail after unload")
}

// TestXDP_LoadAttachDetachUnload tests the full lifecycle of an XDP program.
// XDP programs use dispatchers for multi-program support.
func TestXDP_LoadAttachDetachUnload(t *testing.T) {
	t.Parallel()
	RequireRoot(t)

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// When: load from OCI image via client
	imageRef := interpreter.ImageRef{
		URL: "quay.io/bpfman-bytecode/xdp_pass:latest",
	}
	programs, err := env.Client.LoadImage(ctx, imageRef, []client.ImageProgramSpec{
		{
			ProgramType: bpfman.ProgramTypeXDP,
			ProgramName: "pass",
		},
	}, client.LoadImageOpts{})
	require.NoError(t, err)
	require.Len(t, programs, 1)

	prog := programs[0]

	// Then: program has expected properties
	require.NotZero(t, prog.Kernel.ID(), "kernel should assign program ID")
	require.Equal(t, bpfman.ProgramTypeXDP, prog.Kernel.Type())

	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Round-trip: Get should return matching program info
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Kernel)
	require.NotNil(t, gotProg.Kernel.Program)
	require.Equal(t, prog.Kernel.ID(), gotProg.Kernel.Program.ID)
	require.Equal(t, prog.Kernel.Type().String(), gotProg.Kernel.Program.ProgramType)
	require.Equal(t, prog.Kernel.Name(), gotProg.Kernel.Program.Name)
	require.NotEmpty(t, gotProg.Kernel.Program.Tag, "kernel should assign tag")
	require.False(t, gotProg.Kernel.Program.LoadedAt.IsZero(), "kernel should track LoadedAt")
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)
	require.Equal(t, "pass", gotProg.Bpfman.Program.ProgramName)
	require.NotEmpty(t, gotProg.Bpfman.Program.PinPath, "program should have pin path")

	// Round-trip: List should include our program
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.Equal(t, prog.Kernel.ID(), listedProgs[0].KernelProgram.ID)
	require.Equal(t, prog.Kernel.Name(), listedProgs[0].KernelProgram.Name)
	require.NotEmpty(t, listedProgs[0].KernelProgram.Tag)
	require.False(t, listedProgs[0].KernelProgram.LoadedAt.IsZero())
	require.NotNil(t, listedProgs[0].Metadata)
	require.Equal(t, "pass", listedProgs[0].Metadata.ProgramName)
	require.NotEmpty(t, listedProgs[0].Metadata.PinPath)

	// When: attach via client to lo interface
	xdpSpec, err := bpfman.NewXDPAttachSpec(prog.Kernel.ID(), "lo", 1)
	require.NoError(t, err)
	link, err := env.Client.AttachXDP(ctx, xdpSpec, bpfman.AttachOpts{})
	require.NoError(t, err)

	// Then: link has expected properties
	require.NotZero(t, link.KernelLinkID, "kernel should assign link ID")
	require.Equal(t, bpfman.LinkTypeXDP, link.LinkType)
	require.Equal(t, prog.Kernel.ID(), link.KernelProgramID, "link should reference correct program")

	t.Cleanup(func() {
		env.Client.Detach(context.Background(), link.KernelLinkID)
	})

	// Round-trip: GetLink should return matching link info
	gotLinkSummary, gotLinkDetails, err := env.Client.GetLink(ctx, link.KernelLinkID)
	require.NoError(t, err)
	require.Equal(t, link.KernelLinkID, gotLinkSummary.KernelLinkID)
	require.Equal(t, link.LinkType, gotLinkSummary.LinkType)
	require.Equal(t, link.KernelProgramID, gotLinkSummary.KernelProgramID)
	xdpDetails, ok := gotLinkDetails.(bpfman.XDPDetails)
	require.True(t, ok, "expected XDPDetails, got %T", gotLinkDetails)
	require.Equal(t, "lo", xdpDetails.Interface)
	require.Equal(t, uint32(1), xdpDetails.Ifindex, "ifindex should match lo")
	require.NotZero(t, xdpDetails.DispatcherID, "XDP should use dispatcher")
	require.NotZero(t, xdpDetails.Revision, "dispatcher should have revision")

	// Round-trip: ListLinks should include our link
	listedLinks, err := env.Client.ListLinks(ctx)
	require.NoError(t, err)
	require.Len(t, listedLinks, 1)
	require.Equal(t, link.KernelLinkID, listedLinks[0].KernelLinkID)
	require.Equal(t, link.LinkType, listedLinks[0].LinkType)
	require.Equal(t, link.KernelProgramID, listedLinks[0].KernelProgramID)

	// When: detach
	err = env.Client.Detach(ctx, link.KernelLinkID)
	require.NoError(t, err)

	// Then: no links, and GetLink should return error
	env.AssertLinkCount(0)
	_, _, err = env.Client.GetLink(ctx, link.KernelLinkID)
	require.Error(t, err, "GetLink should fail after detach")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state, and Get should return error
	env.AssertCleanState()
	_, err = env.Client.Get(ctx, prog.Kernel.ID())
	require.Error(t, err, "Get should fail after unload")
}

// TestLoadWithMetadataAndGlobalData verifies that user-supplied metadata and
// global data are stored and returned correctly through the full stack.
func TestLoadWithMetadataAndGlobalData(t *testing.T) {
	t.Parallel()
	RequireRoot(t)

	env := NewTestEnv(t)
	ctx := context.Background()

	// Given: clean state
	env.AssertCleanState()

	// Define user metadata and global data
	userMetadata := map[string]string{
		"owner":                 "test-team",
		"environment":           "e2e-testing",
		"bpfman.io/application": "metadata-test",
	}
	globalData := map[string][]byte{
		"config_u8":  {0x42},
		"config_u32": {0xDE, 0xAD, 0xBE, 0xEF},
	}

	// When: load from OCI image with metadata and global data
	imageRef := interpreter.ImageRef{
		URL: "quay.io/bpfman-bytecode/xdp_pass:latest",
	}
	programs, err := env.Client.LoadImage(ctx, imageRef, []client.ImageProgramSpec{
		{
			ProgramType: bpfman.ProgramTypeXDP,
			ProgramName: "pass",
		},
	}, client.LoadImageOpts{
		UserMetadata: userMetadata,
		GlobalData:   globalData,
	})
	require.NoError(t, err)
	require.Len(t, programs, 1)

	prog := programs[0]
	t.Cleanup(func() {
		env.Client.Unload(context.Background(), prog.Kernel.ID())
	})

	// Then: Get should return the user metadata and global data
	gotProg, err := env.Client.Get(ctx, prog.Kernel.ID())
	require.NoError(t, err)
	require.NotNil(t, gotProg.Bpfman)
	require.NotNil(t, gotProg.Bpfman.Program)

	// Verify user metadata is returned
	require.Equal(t, "test-team", gotProg.Bpfman.Program.UserMetadata["owner"],
		"Get should return user metadata 'owner'")
	require.Equal(t, "e2e-testing", gotProg.Bpfman.Program.UserMetadata["environment"],
		"Get should return user metadata 'environment'")
	require.Equal(t, "metadata-test", gotProg.Bpfman.Program.UserMetadata["bpfman.io/application"],
		"Get should return user metadata 'bpfman.io/application'")

	// Verify global data is returned
	require.Equal(t, []byte{0x42}, gotProg.Bpfman.Program.GlobalData["config_u8"],
		"Get should return global data 'config_u8'")
	require.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, gotProg.Bpfman.Program.GlobalData["config_u32"],
		"Get should return global data 'config_u32'")

	// Then: List should also return the user metadata and global data
	listedProgs, err := env.Client.List(ctx)
	require.NoError(t, err)
	require.Len(t, listedProgs, 1)
	require.NotNil(t, listedProgs[0].Metadata)

	// Verify user metadata via List
	require.Equal(t, "test-team", listedProgs[0].Metadata.UserMetadata["owner"],
		"List should return user metadata 'owner'")
	require.Equal(t, "e2e-testing", listedProgs[0].Metadata.UserMetadata["environment"],
		"List should return user metadata 'environment'")

	// Verify global data via List
	require.Equal(t, []byte{0x42}, listedProgs[0].Metadata.GlobalData["config_u8"],
		"List should return global data 'config_u8'")
	require.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, listedProgs[0].Metadata.GlobalData["config_u32"],
		"List should return global data 'config_u32'")

	// When: unload
	err = env.Client.Unload(ctx, prog.Kernel.ID())
	require.NoError(t, err)

	// Then: clean state
	env.AssertCleanState()
}

// uprobeTarget returns the path and function name for uprobe tests.
// Uses libc malloc - works on standard Linux and NixOS.
func uprobeTarget() (target, fnName string) {
	// Patterns to find libc. Order matters - check direct paths first,
	// then paths with one subdirectory level (for arch-specific dirs like x86_64-linux-gnu).
	// Note: filepath.Glob's * doesn't match /, so /lib/*/libc.so.* handles subdirs.
	patterns := []string{
		"/lib/libc.so.*",
		"/lib64/libc.so.*",
		"/lib/*/libc.so.*",
		"/usr/lib/libc.so.*",
		"/usr/lib64/libc.so.*",
		"/usr/lib/*/libc.so.*",
		"/nix/store/*glibc*/lib/libc.so.*",
	}

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			// Skip the linker script (libc.so), use the real library (libc.so.6)
			if filepath.Ext(path) != ".so" {
				return path, "malloc"
			}
		}
	}

	return "", ""
}

// findBytecodeFile looks for a bytecode file in the integration-tests/bytecode directory.
func findBytecodeFile(name string) string {
	// Try relative to current directory
	candidates := []string{
		filepath.Join("integration-tests", "bytecode", name),
		filepath.Join("..", "integration-tests", "bytecode", name),
	}

	// Also try from the e2e directory
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "integration-tests", "bytecode", name),
			filepath.Join(filepath.Dir(wd), "integration-tests", "bytecode", name),
		)
	}

	for _, path := range candidates {
		if absPath, err := filepath.Abs(path); err == nil {
			if _, err := os.Stat(absPath); err == nil {
				return absPath
			}
		}
	}

	return ""
}
