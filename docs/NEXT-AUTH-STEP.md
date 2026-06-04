# Next auth step

A working note on where OCI registry auth and signature verification
stand after PR #121, and what the next decision is.

## What landed (PR #121)

Registry credentials are now threaded through both halves of an image
load: the pull and the signature check.

The load-bearing fact is that there are two independent OCI-registry
clients in the codebase, and they do not share an auth path:

- The puller uses `oras.land/oras-go/v2` to pull the bytecode image.
  Credentials reach it via `ImageRef.Auth` ->
  `configureAuth` -> an oras `auth.Client`.
- The cosign verifier uses `github.com/google/go-containerregistry` to
  fetch the signature during verification. Credentials reach it via
  `SignatureVerificationRequest.Auth` ->
  `cosign.CheckOpts.RegistryClientOpts` -> go-containerregistry's
  `remote.WithAuth`.

Because the two clients are separate, the same credentials have to be
handed to each one explicitly. Before this work the puller had auth but
the verifier did not, so a private signed image could be pulled with
credentials and then fail verification when the signature fetch went
out anonymously.

Completeness is settled by a single predicate,
`platform.ImageAuth.Complete()` (both username and password present).
Both consumers gate on it, so they cannot disagree on a half-populated
credential. The CLI and shell reject an incomplete `--registry-auth` as
malformed input; the gRPC server normalises incomplete proto
credentials to anonymous, matching the Rust API boundary.

## The next step: cache vs verify ordering

The remaining behavioural gap against Rust is the order of the cache
check and signature verification in the puller.

Today the Go puller consults the cache before it verifies. For pull
policies `IfNotPresent` and `Never`, a cache hit returns the cached
image without re-running signature verification (the cache lookup
happens earlier in `Pull` than the verifier call). Per the comparison
with the Rust implementation, Rust verifies the image before it
consults cache policy, so a cached image is still held to the signing
policy.

The consequence is that a signed-image policy can be bypassed on the
second and later loads of the same image: the first load verifies and
populates the cache, and subsequent `IfNotPresent` loads short-circuit
on the cache and skip verification entirely. That is a
correctness/security gap, not just a cosmetic divergence.

The decision to make is how to close it. Two shapes:

- Verify-then-cache. Always resolve the digest and run verification,
  then serve from the cache keyed by the verified digest. Simple and
  matches Rust, but it costs a registry round-trip (digest resolution
  plus signature fetch) even on a cache hit, which weakens the cache
  for the offline and `Never` cases.
- Record the verification verdict in the cache and re-check it against
  current policy on a hit, re-verifying only when policy demands it
  (e.g. always for `Always`). Keeps cache hits cheap but adds state and
  a trust assumption about the recorded verdict.

Open question before choosing: what does Rust actually do for `Never`
and for a genuinely offline host -- does it require a reachable
registry to verify on every load, or does it have an equivalent
short-circuit?

## Further out

- Standalone `image pull` CLI command. Go has the backend
  (`platform.ImagePuller.Pull`, `manager.PullBytecode`, gRPC
  `PullBytecode`) but no CLI surface. Rust exposes one. Pull and cache
  semantics differ between the two implementations, so this needs its
  own design pass rather than riding on the auth work.
- Offline trusted root. The stronger future model is in
  `docs/DESIGN-OFFLINE-SIGNATURE-VERIFICATION.md`: a pinned
  `trusted_root.json` and offline verification with no network
  Rekor/TUF lookup at verify time. That is well beyond Rust parity and
  is tracked separately.
