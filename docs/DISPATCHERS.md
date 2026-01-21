# XDP and TC Dispatchers

This document describes the dispatcher implementation for multi-program
chaining on XDP and TC hooks.

## Overview

Dispatchers allow multiple BPF programs to be attached to a single
network interface. Rather than replacing each other, programs are
chained together and executed in sequence. Each program can decide
whether to continue to the next program based on its return value.

The dispatcher model matches upstream bpfman's behaviour, ensuring
drop-in compatibility.

## Architecture

### Dispatcher Programs

The dispatcher is a BPF program with 10 stub functions (`prog0` through
`prog9`) that can be replaced at runtime using the kernel's freplace
mechanism. When a packet arrives:

1. The dispatcher calls each enabled stub function in order
2. After each call, it checks the return value against a "proceed-on" mask
3. If the return value matches the mask, it continues to the next program
4. Otherwise, it returns the value immediately

### BPF Extension (freplace)

User programs are attached to dispatcher slots using BPF extensions
(`BPF_PROG_TYPE_EXT`). This is a kernel mechanism that replaces a
function in one BPF program with another.

**Key insight**: The same ELF bytecode can be loaded as different
program types. For dispatcher attachment, we reload the program from
the original ELF file with:

- `Type = Extension` (not XDP)
- `AttachTarget = dispatcher program`
- `AttachTo = "prog0"` (or other slot name)

This is different from direct XDP attachment where the program is
loaded as `BPF_PROG_TYPE_XDP`.

## Implementation

### Package Structure

```
pkg/bpfman/dispatcher/     # Dispatcher loading and config
  dispatcher.go            # Load functions, config structs
  xdp_dispatcher_v2.bpf.o  # Embedded XDP dispatcher bytecode
  tc_dispatcher.bpf.o      # Embedded TC dispatcher bytecode

dispatchers/               # BPF source files
  xdp_dispatcher_v2.bpf.c
  tc_dispatcher.bpf.c
  Makefile
```

### Config Injection

The dispatcher config is a C struct embedded in the `.rodata` section:

```c
struct xdp_dispatcher_conf {
    __u8 magic;
    __u8 dispatcher_version;
    __u8 num_progs_enabled;
    __u8 is_xdp_frags;
    __u32 chain_call_actions[10];
    __u32 run_prios[10];
    __u32 program_flags[10];
};

static volatile const struct xdp_dispatcher_conf conf = {};
```

Because the variable is `static`, it's not exported as a global symbol.
We inject the config by directly modifying the `.rodata` map contents
before loading:

```go
rodata := spec.Maps[".rodata"]
rodata.Contents = []ebpf.MapKV{
    {Key: uint32(0), Value: configBytes},
}
```

Note: `RewriteConstants` and the Variables API don't work for static
variables in cilium/ebpf.

### Pin Paths

```
/sys/fs/bpf/bpfman/dispatchers/<ifname>/
    xdp_dispatcher    # The dispatcher program
    link              # XDP link attaching dispatcher to interface

/sys/fs/bpf/bpfman/<program-uuid>/
    <program-name>    # Original program (loaded as XDP type)
    link              # Extension link (freplace to dispatcher slot)
```

### Attachment Flow

1. **Load program** (via `bpfman load`):
   - Program loaded as XDP type
   - Pinned at `/sys/fs/bpf/bpfman/<uuid>/<name>`
   - ObjectPath stored in database

2. **Attach XDP** (via `bpfman attach xdp`):
   - Check if dispatcher exists for interface
   - If not, create dispatcher and attach to interface
   - Reload program from ObjectPath as Extension type
   - Set AttachTarget to dispatcher, AttachTo to slot name
   - Create freplace link
   - Pin extension link

3. **Detach** (via `bpfman detach`):
   - Remove extension link pin
   - Dispatcher remains attached (for reuse)

## Current Limitations

### Single Slot (Position 0)

Currently all programs are attached to slot 0. The code has:

```go
// TODO: Track positions per interface and find next available slot
position := 0
```

Future work: Track occupied positions per interface and allocate the
next available slot based on priority.

### No Dispatcher Lifecycle Management

Dispatchers are created on first attachment but never automatically
removed. After detaching all programs from an interface, the dispatcher
remains until manually cleaned up:

```bash
rm -rf /sys/fs/bpf/bpfman/dispatchers/<ifname>
```

Future work: Track extension count per dispatcher and remove when
count reaches zero.

### Dispatcher ID Not Retrieved on Reuse

When reusing an existing dispatcher, we don't retrieve its kernel ID:

```go
} else {
    m.logger.Debug("using existing dispatcher", ...)
    // TODO: Get dispatcher ID from pinned program
}
```

This means `XDPDetails.DispatcherID` is 0 when reusing a dispatcher.

### Hardcoded Proceed-On

Currently hardcoded to proceed on XDP_PASS only:

```go
xdpProceedOnPass = 1 << 2  // Continue on XDP_PASS
```

The CLI doesn't expose proceed-on configuration. Future work: add
`--proceed-on` flag to `attach xdp` command.

### No Multi-Program Testing

Only single program attachment has been tested. Attaching multiple
programs to the same interface (using different slots) is untested.

## XDP vs Extension Program Types

A common confusion: why can't we just attach an already-loaded XDP
program to the dispatcher?

The kernel's freplace mechanism requires `BPF_PROG_TYPE_EXT`. When you
load a program, the kernel assigns it a type that cannot be changed.
An XDP program (type 6) cannot be used for freplace.

cilium/ebpf enforces this:

```go
// link/tracing.go
if prog.Type() != ebpf.Extension {
    return nil, fmt.Errorf("eBPF program type %s is not an Extension", prog.Type())
}
```

The solution is to reload the same bytecode with different load
parameters. The ELF file doesn't mandate a specific program type - it
contains the instructions which are valid for both XDP and Extension
contexts when the target is an XDP function.

## Testing

Manual test flow:

```bash
# Load a program
bpfman load image --program=xdp:pass quay.io/bpfman-bytecode/xdp_pass:latest

# Attach using dispatcher (program ID from load output)
bpfman attach xdp --program-id=<id> lo

# Verify
ip link show lo                              # Shows xdpgeneric
ls /sys/fs/bpf/bpfman/dispatchers/lo/        # Dispatcher pins
bpfman list links                            # Shows extension link

# Detach
bpfman detach <link-uuid>

# Clean up dispatcher manually
sudo rm -rf /sys/fs/bpf/bpfman/dispatchers/lo
```

## Future Work

1. **Position tracking**: Allocate slots based on priority, track
   occupied positions per interface

2. **Dispatcher lifecycle**: Remove dispatcher when last extension is
   detached

3. **Proceed-on configuration**: CLI flag to configure which return
   values continue the chain

4. **TC dispatcher**: Same model for TC programs (implementation
   exists but untested)

5. **Revision-based updates**: Atomic dispatcher replacement for
   config changes (matches upstream bpfman)

6. **Multi-program testing**: Verify multiple programs can be attached
   to different slots on the same interface
