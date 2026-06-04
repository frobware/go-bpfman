# Design: Offline Trusted-Root Signature Verification

## Problem

bpfman verifies OCI bytecode-image signatures with sigstore/cosign. The
current verifier resolves its trust material -- Fulcio roots, Rekor
public keys, CT-log keys -- at load time through cosign's helper APIs,
which initialise a sigstore TUF client and cache the trust root in a
LevelDB under `$HOME/.sigstore/root/tuf.db`.

That is fine for a long-lived process: TUF init is a per-process
singleton, so the cache is created once and every subsequent
verification hits the warm path. It stops being fine once each top-level
`bpfman` command runs as a discrete, short-lived Kubernetes job, which is
the direction bpfman is heading for OpenShift. In that model many such
jobs run concurrently, each a separate process that must initialise TUF,
and two failure modes fall out:

1. **Shared trust-root cache (a mounted volume, to avoid re-fetching).**
   Concurrent jobs race the LevelDB's non-blocking exclusive lock and
   fail with `creating cached local store: resource temporarily
   unavailable`. This is reproducible: 16 concurrent `bpfman image
   verify` processes against a cold `/root/.sigstore` produce 15
   failures.

2. **Isolated per-pod cache.** No lock race, but every job cold-fetches
   the trust root from `tuf-repo-cdn.sigstore.dev`. That is a hard egress
   dependency (it fails in network-restricted clusters), adds per-request
   latency, and loads the public CDN.

You cannot escape both with runtime TUF init in short-lived jobs: shared
caches give the lock race, isolated caches give the egress dependency.

## Background: how verification works today

`platform/image/verify/verify.go` (`cosignVerifier.Verify`) currently:

- calls `fulcio.GetRoots()` / `fulcio.GetIntermediates()` for the Fulcio
  certificate chain,
- calls `rekor.NewClient(...)` and `cosign.GetRekorPubs(ctx)` for Rekor,
- calls `cosign.GetCTLogPubs(ctx)` for the CT log,
- assembles a `cosign.CheckOpts` from those (`RootCerts`,
  `IntermediateCerts`, `RekorPubKeys`, `CTLogPubKeys`, `RekorClient`,
  `Identities`),
- and calls `cosign.VerifyImageSignatures(...)`, which both **discovers**
  the cosign signatures attached to the image in the registry **and**
  **verifies** them against that material and the identity policy.

The three `Get*` helpers are exactly the calls that enter the deprecated
`github.com/sigstore/sigstore/pkg/tuf` and create the LevelDB cache.

## Goals

The offline contract verification must satisfy:

- Trust is anchored by an offline, read-only trusted root.
- No writes to `$HOME/.sigstore`; no writable TUF database.
- No runtime TUF refresh; no egress to the sigstore TUF CDN at load.
- No online Rekor lookup; a signature must carry its own bundled
  transparency-log entry to verify offline, and one that does not fails
  closed.
- Existing policy is preserved: the keyless `trusted_identities` policy
  and the `allow_unsigned` / `verify_enabled` semantics are unchanged.
- Deterministic and safe under many concurrent short-lived processes.
- Fail closed: a missing or unreadable trusted root, and a
  present-but-invalid signature, deny the load -- never a silent downgrade
  to live TUF or to "unsigned".

## Non-Goals

- Do not embed signing. Users still run `cosign sign` out of band; bpfman
  only verifies.
- Do not replace the identity policy. A trusted root supplies the
  cryptographic anchors (which Fulcio/Rekor/CT roots are trusted); it
  does not say which signer identities are acceptable. Both
  `trusted_root` and `trusted_identities` remain, and both are required
  for a keyless verification.
- Do not rewrite the verifier onto sigstore-go wholesale in the first
  step. cosign already exposes the seam needed to swap only the
  trust source (see below).

## Proposed design

### Configuration

```toml
[signing]
verify_enabled = true
allow_unsigned = false
trusted_root   = "/etc/bpfman/sigstore/trusted_root.json"
offline        = true
```

- `trusted_root` is a path to a pinned sigstore `trusted_root.json` (the
  protobuf `TrustedRoot`). For the public-good instance, pin (or embed) a
  copy of sigstore's published `trusted_root.json` and update it
  deliberately on root rotation -- you control the cadence instead of
  pulling it live. For a private sigstore instance (the likely OpenShift
  case) it is that instance's `trusted_root.json`, mounted read-only via
  a ConfigMap or Secret.
- `offline`, when true, forbids any network access during verification.

### Verifier changes

The change is contained to the trust-source plumbing; cosign keeps doing
discovery and verification.

When `trusted_root` is configured:

- Load it once, offline:
  ```go
  tr, err := root.NewTrustedRootFromPath(cfg.Signing.TrustedRoot) // sigstore-go/pkg/root
  ```
  `*root.TrustedRoot` is a `root.TrustedMaterial`.
- Build `cosign.CheckOpts` with:
  - `TrustedMaterial: tr` -- this field is documented as exclusive with
    `RootCerts` / `IntermediateCerts` / `RekorPubKeys` / `CTLogPubKeys`,
    so those are no longer populated, and the `Get*` TUF helpers are no
    longer called.
  - `Offline: true` (when `cfg.Signing.Offline`) and **no** `RekorClient`
    -- verification then uses the bundled tlog entry rather than an online
    Rekor lookup. Use `Offline`, not `IgnoreTlog`: the latter skips the
    transparency-log check entirely, which is not what we want.
  - `Identities: v.identities` -- unchanged.
- Keep `cosign.VerifyImageSignatures(...)` for discovery and
  verification.

With this, verification never initialises TUF, never opens a LevelDB,
never writes `$HOME/.sigstore`, and never makes a network call -- so the
cross-process lock race cannot occur at any concurrency, and the egress
dependency is gone.

### Trusted-root provenance and rotation

The trusted root is operator-provided and updated as an operator action
(replace the file or update the mounted ConfigMap/Secret), never as a
runtime fetch. Rotation must happen before the embedded keys/certificates
reach their validity bounds.

## Security posture

This is a security-relevant change, so the design is shaped around
fail-closed behaviour rather than convenience. cosign's typed errors make
the outcomes unambiguous -- the verifier already distinguishes "no
signature" from "verification failed" via `cosign.ErrNoSignaturesFound`,
matched by type rather than by message precisely so that "unsigned" cannot
be widened by a brittle string match.

### Verification outcomes

- `offline = true`: never initialise TUF, never call Rekor online. A
  signature that cannot be verified from its own bundled material fails; it
  does not fall back to the network. "Offline" is enforced, not
  best-effort.
- `trusted_root` missing or unreadable while verification is enabled:
  **fail closed**. This matches the config loader, which already fails
  closed on an explicitly requested but unreadable file.
- A signature is present but does not satisfy the trust material or the
  identity policy: **fail, regardless of `allow_unsigned`**. `allow_unsigned`
  governs the *absence* of a signature, never a present-but-invalid one.
  The verifier enforces this today by routing only `ErrNoSignaturesFound`
  to the unsigned path; this design must preserve that.
- No signature present and `allow_unsigned = true`: accept, and record the
  outcome as "unsigned, accepted by policy" (the existing
  `unsigned_accepted` status) -- not as "verified".

### Strict identity policy

`allow_unsigned = false` with an empty `trusted_identities` means "require
a valid sigstore signature from *any* Fulcio identity" -- effectively
"anyone who can obtain a Fulcio certificate may sign bpfman bytecode." That
is a weak policy. A locked-down deployment must set both `allow_unsigned =
false` and a non-empty `trusted_identities`. The config validator should
reject the "require-signed, accept-any-signer" combination in a strict
mode, and at minimum warn loudly about it otherwise.

### The freshness trade-off, stated honestly

Pinning a trusted root is the right call for short-lived offline jobs, but
it is a genuine trade-off, not a pure win. TUF exists to provide
*automatic* freshness and revocation; pinning opts bpfman out of that and
shifts the obligation onto the operator. A stale `trusted_root.json` will
keep trusting roots that sigstore has since rotated or revoked. The
mitigation is operational and must be explicit:

- The pinned `trusted_root.json` is now a load-bearing trust anchor -- its
  provenance and integrity matter as much as any signing key, because a
  swapped file is a silent trust compromise. It must come from a controlled
  source (sigstore's published root, verified once, or a private instance's
  root) and be delivered through normal config controls: a ConfigMap or
  Secret, or an image layer, with clear ownership and immutability
  expectations.
- It carries validity windows. Operators must monitor and rotate before
  expiry; otherwise verification correctly begins to fail closed.

### Auditability

Each verification should log, in structured form, which trusted root was
used, whether the run was offline, which identity matched (for a verified
image), and whether an unsigned image was accepted by policy. The outcome
is already a typed status (`verified` / `unsigned_accepted` / `disabled`);
the logging makes the policy decision auditable after the fact.

## Testing

- The general lifecycle e2e suite stays decoupled from sigstore: image-mode
  fixtures are unsigned throwaway artefacts and the lane runs with
  `verify_enabled=false`. That is already in place and is orthogonal to
  this design.
- Signature-verification policy gets its own focused tests: serial
  execution, an isolated cache directory, explicit signed and unsigned
  fixtures, and the offline path driven by a pinned `trusted_root.json`.
- Determinism check, mirroring the lifecycle lane's observable: an offline
  verify must not create `$HOME/.sigstore`. If that path stays absent, the
  failure mechanism provably never ran.

## Open questions and risks

- **Discovery validation (the one spike).** Confirm that
  `cosign.VerifyImageSignatures` with `TrustedMaterial` and `Offline` set
  never re-enters the TUF path internally (no fallback into
  `GetRoots`/`GetRekorPubs`/`GetCTLogPubs`). If it does, the fallback is to
  discover signatures with cosign's `pkg/oci/remote` (which does not touch
  TUF), adapt each cosign simple-signing signature into a sigstore-go
  `SignedEntity`, and verify with `sigstore-go/pkg/verify` against the
  offline trusted root. This adapter is the only part that is more than
  mechanical, so it should be spiked before committing to a timeline.
- **Signature format.** cosign signatures use the simple-signing OCI
  layout (a `sha256-<digest>.sig` tag), not the protobuf `Bundle`. Offline
  verification requires the Rekor entry to be bundled with the signature;
  images signed without a bundled tlog entry will fail offline. The signing
  requirement (sign so the entry is bundled) must be documented for
  producers.
- **Default when `trusted_root` is unset.** Resolved by the fail-closed
  posture above: `offline = true` with no readable `trusted_root` fails
  closed rather than silently using live TUF. The legacy live-TUF path
  remains reachable only by explicitly leaving `offline` off, which is
  intended for local/dev and is unsafe for the kube-job model. A production
  deployment therefore sets both `trusted_root` and `offline = true`, and
  nothing falls back silently.
- **Trusted-root expiry.** A pinned `trusted_root.json` carries validity
  windows; operators must rotate before expiry or verification starts
  failing closed.

## Summary

Verification fails in the per-request kube-job model because it initialises
a sigstore TUF cache at load time -- a writable, network-backed, per-process
resource that short-lived concurrent jobs cannot share or cheaply rebuild.
Swapping the trust source from cosign's TUF-backed helpers to a pinned,
offline `TrustedMaterial` (loaded via sigstore-go, fed to cosign's existing
`CheckOpts`, with `Offline` set) removes that resource entirely while
keeping cosign's discovery and verification and the existing identity
policy. The only non-mechanical unknown is whether cosign's discovery path
stays clear of TUF once `TrustedMaterial` is supplied; everything else is
configuration and plumbing.
