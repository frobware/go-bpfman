# Design: Image-Backed `.bpfman` E2E Scripts

## Problem

The `.bpfman` e2e corpus exercises a broad set of daemon behaviour:
program load, attach, link get/list, dispatcher ordering, traffic
delivery, detach, and unload. Today those scripts load bytecode almost
entirely from local object files:

```bpfman
bpfman program load file --path testdata/bpf/tc_counter.bpf.o --programs tc:stats
```

The operator integration tests, by contrast, create Kubernetes
resources whose net effect is an image-backed daemon load. A
`ClusterBpfApplication` eventually causes bpfman to pull bytecode from
an OCI image and load programs from that pulled object.

The Go daemon has `bpfman program load image`, and the manager has an
OCI image pull path, but the current `.bpfman` e2e corpus does not
exercise that path. This leaves a gap: file-backed daemon behaviour is
well covered, while image pull/build/provenance behaviour is mostly
unit-tested or indirectly covered by the operator stack.

There is also no Go equivalent of the Rust daemon's:

```sh
bpfman image build ...
```

The Rust implementation can build bytecode images from local `.o`
files. The Go implementation needs comparable image-building support
before the e2e corpus can cheaply test image-backed loads without
depending on public registries.

## Goals

- Keep existing `.bpfman` scripts unchanged.
- Add a mode that transparently turns file loads into image loads.
- Exercise real OCI push and pull semantics, not a fake cache-only
  shortcut.
- Hide registry ports and lifecycle from users and scripts.
- Make the mode suitable for a CI matrix so the same script corpus can
  run file-backed and image-backed.
- Keep production manager and image puller paths honest: they should
  see ordinary image URLs and perform ordinary pulls.

## Non-Goals

- Do not replace operator integration tests. `.bpfman` cannot validate
  Kubernetes CRD reconciliation, `ClusterBpfApplicationState`,
  DaemonSet readiness, node selection, or userspace pod logs.
- Do not require scripts to name a registry or port.
- Do not depend on `quay.io` or any external registry for routine e2e
  execution.
- Do not make image-backed mode the default path for local script
  development.

## Current State

The Go CLI and shell support image loads:

```sh
bpfman program load image \
  --image-url quay.io/bpfman-bytecode/go-tc-counter:latest \
  --programs tc:stats \
  --pull-policy IfNotPresent
```

The shell builtin also supports `program load image`, including:

- `--image-url`
- `--programs`
- `--pull-policy`
- `--registry-auth`
- `--application`
- `--metadata`
- `--global`
- `--map-owner-id`

However, e2e scripts use `program load file`, and there is no
transparent image-backed e2e mode. There is also no Go `bpfman image
build` command to package local bytecode into an OCI image.

## Proposed Design

Add an image-backed script mode:

```sh
direnv exec . make test-e2e-scripts-image-load
```

In this mode, the same script command:

```bpfman
bpfman program load file --path testdata/bpf/tc_counter.bpf.o --programs tc:stats
```

is executed as if the script had written:

```bpfman
bpfman program load image \
  --image-url 127.0.0.1:<hidden-port>/bpfman-e2e/tc_counter:<digest> \
  --programs tc:stats \
  --pull-policy Always
```

The script does not see the registry, port, image tag, or rewrite. It
receives the same structured `{ programs: [...] }` value that file load
returns today.

### Execution Flow

```text
.bpfman script
  bpfman program load file --path X --programs S
        |
        | BPFMAN_E2E_LOAD_FILE_VIA_IMAGE=1
        v
bpfman-shell builtin
  build OCI bytecode image from X
  push image to in-process registry
  rewrite to program load image --image-url REF --programs S
        |
        v
manager LoadSource{Image: REF}
        |
        v
OCI puller
  resolve manifest from registry
  fetch config and layer blobs
  extract bytecode
  cache bytecode and provenance
        |
        v
normal program load, attach, test assertions
```

This exercises real push and pull semantics while keeping scripts
portable.

## In-Process Registry

The e2e script runner should start an in-process OCI registry in
`TestMain` when image-backed mode is enabled.

Properties:

- bind to `127.0.0.1:0` so the OS chooses a free port;
- expose the chosen registry URL only through environment variables
  passed to script subprocesses;
- store blobs/manifests in memory or a temporary directory;
- shut down automatically when the runner exits;
- require no Docker, Podman, external registry, or fixed port.

Minimum registry API surface for ORAS push and the existing puller:

```text
GET  /v2/
HEAD /v2/<name>/blobs/<digest>
GET  /v2/<name>/blobs/<digest>
POST /v2/<name>/blobs/uploads/
PATCH /v2/<name>/blobs/uploads/<uuid>
PUT  /v2/<name>/blobs/uploads/<uuid>?digest=<digest>
PUT  /v2/<name>/manifests/<reference>
HEAD /v2/<name>/manifests/<reference>
GET  /v2/<name>/manifests/<reference>
```

The registry should be test infrastructure only. The production image
puller should not know it is talking to a test registry.

## Image Builder

Add Go support equivalent to Rust `bpfman image build`.

The Rust bytecode container shape is simple:

```Dockerfile
FROM scratch

ARG BYTECODE_FILE
ARG PROGRAMS
ARG MAPS

LABEL "io.ebpf.programs"=$PROGRAMS
LABEL "io.ebpf.maps"=$MAPS

COPY  $BYTECODE_FILE /
```

The Go implementation can build this OCI image directly with `oras-go`
instead of shelling out to Docker or Podman.

Inputs:

- local bytecode object path;
- optional program specs from `--programs`;
- deterministic image name prefix, for example `bpfman-e2e`;
- target registry URL supplied by the e2e runner.

Outputs:

- pushed image reference;
- content digest;
- labels for programs/maps where available.

The image reference should be deterministic enough for caching and
diagnostics, for example:

```text
127.0.0.1:<port>/bpfman-e2e/tc_counter:<sha256>
```

The digest should include the bytecode content and load-relevant
metadata, so changing the object or program selection produces a new
tag/reference.

## Shell Rewrite

The rewrite should live in `bpfman-shell`'s builtin execution path for
`program load file`, not in the manager or puller.

Controlled by environment:

```text
BPFMAN_E2E_LOAD_FILE_VIA_IMAGE=1
BPFMAN_E2E_IMAGE_REGISTRY=127.0.0.1:<port>
```

When enabled, `execLoadFile` should:

1. resolve the local object path exactly as it does today;
2. build and push an OCI bytecode image to `BPFMAN_E2E_IMAGE_REGISTRY`;
3. construct a `LoadImageCommand` preserving:
   - `Programs`
   - `Metadata`
   - `GlobalData`
   - `Application`
   - `MapOwnerID`
   - `Output`
4. set `PullPolicy` to `Always`;
5. call the same `execLoadImage` path used by explicit image loads.

The returned value must remain the same shape as file load:

```json
{ "programs": [...] }
```

## Makefile And CI

Add a new target:

```sh
direnv exec . make test-e2e-scripts-image-load
```

The target should:

- build `bpfman`, `bpfman-shell`, BPF objects, and the script runner;
- reload the e2e kmod as `test-e2e-scripts` does;
- run the same script runner with image-backed mode enabled.

The existing target remains file-backed:

```sh
direnv exec . make test-e2e-scripts
```

CI can then run a matrix:

```text
script_load_mode=file
script_load_mode=image
```

Initially, the image-backed matrix can run a small subset:

- `TestXDP_LinkRoundTrip.bpfman`
- `TestTC_LinkRoundTrip.bpfman`
- `TestTCX_LinkRoundTrip.bpfman`
- `TestKprobe_LinkRoundTrip.bpfman`
- `TestTracepoint_LinkRoundTrip.bpfman`
- `TestUprobe_LinkRoundTrip.bpfman`

Once stable, expand to the full `.bpfman` corpus.

## What This Closes

This closes the loop between local daemon e2e tests and operator-style
image-backed bytecode loading:

- existing scripts keep proving daemon behaviour;
- image-backed mode proves the same behaviour after OCI build, push,
  pull, cache, provenance, and load;
- no external registry or fixed port is exposed to scripts or users;
- production manager/puller code remains exercised through ordinary
  image URLs.

The operator tests still remain necessary for Kubernetes reconciliation,
but this mode gives fast, deterministic coverage for the daemon-side net
effect of those resources.
