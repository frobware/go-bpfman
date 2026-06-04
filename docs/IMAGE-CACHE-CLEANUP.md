# Image cache cleanup

A working note on the OCI image cache lifecycle. The cache grows
without bound because nothing ever evicts a successful entry.

## What the cache is

The puller stores each pulled image under
`/var/cache/bpfman/<sha256(url)>/` as `bytecode.o` plus a
`metadata.json` (digest, programs, maps, and a `PulledAt` timestamp).
The directory is persistent and survives reboots; it is separate from
the sqlite store. The key is the SHA-256 of the full image URL, so the
same URL always maps to the same directory and a re-pull overwrites in
place.

## The leak

Verified on the load branch:

- `ImageCache.RemoveCacheEntry` exists, but its only caller is the
  failed-pull rollback in `platform/image/oci/puller.go` (the freshly
  pulled ELF failed validation, so the half-written entry is torn
  down). It is never used to evict a successful entry.
- Nothing in `manager/` touches the cache: no GC phase, no unload
  hook, no TTL, no size cap.
- `metadata.json` records `PulledAt`, so the data for an age policy is
  already on disk, but it is only read for a debug log.

So once an entry is written it is immortal. Growth comes from distinct
image URLs accumulating: `:latest` re-maps to the same key and
overwrites, but every new tag, digest, or repository ever loaded leaves
a permanent directory, and unloading every program that came from an
image frees nothing.

## Adjacent: staleness

Same code, different symptom. Because the key is `sha256(url)` and
`checkCache` trusts the directory's existence without re-resolving the
digest, an `IfNotPresent` load of a re-pushed `:latest` serves stale
bytecode indefinitely. This shares a root cause with the
cache-versus-verify ordering noted in `NEXT-AUTH-STEP.md`, and a fix to
one should account for the other.

## Who should own cleanup

Three models, with the trade-offs that matter here:

- Reference-counted on unload -- drop the entry when the last program
  from an image unloads. Argue against this: it defeats the cache's
  purpose. The point of `IfNotPresent` is to skip the re-pull on the
  next load, and a load/unload/load cycle would re-pull every time. The
  cache should outlive the programs it seeds.
- Bounded automatic policy -- age (a TTL keyed on `PulledAt`) and/or a
  total-size LRU. Hands-off and bounds disk. Age is nearly free given
  `PulledAt`; true LRU additionally needs an access-time bump on each
  cache hit, which is more machinery.
- Explicit prune -- a `bpfman image prune` command (all, or by age),
  mirroring `podman image prune`. Operator-controlled and lowest risk,
  but bounds nothing on its own.

## Recommendation and open questions

The smallest change that actually fixes the leak is a prune command
plus an optional age cap. Skip the LRU and access-time tracking unless
a concrete disk-pressure requirement appears.

Before committing to a shape:

- What does Rust do? Its sled-backed cache stores manifest/config/layer
  data under an image-derived key. If Rust also never evicts, then
  "parity" and "fix the leak" point in different directions, and we
  need to decide which we are optimising for.
- Does any cleanup need to coordinate with the writer lock or the
  store, or can the cache be pruned independently since it is pure
  filesystem state keyed by URL?
