# Outstanding Design Issues

Observations from reviewing the codebase against two complementary
design philosophies: the fetch/compute/execute pattern from Chiusano
and Bjarnason's *Functional Programming in Scala* (2nd edition), and
Ousterhout's *A Philosophy of Software Design*.

## 1. Split coherency.go into types, gather, and rules files

`coherency.go` is 1,481 lines. It is not *complex* -- it is linearly
complex, with 19 independent rules -- but it mixes four concerns in a
single file: type definitions (`ObservedState`, `ProgramState`,
`Finding`, `Violation`, `Rule`), I/O gathering (`GatherState`), view
computation (lazy builders like `Programs()`, `Links()`,
`Dispatchers()`), and rule definitions (`CoherencyRules()`,
`GCRules()`).

Splitting along these natural seams (types/gather/rules, all within
`manager/`) would improve navigability without introducing any new
abstractions. Each rule is already a self-contained function; grouping
them in a dedicated file makes it easier to scan the rule catalogue
and add new rules without scrolling past the gather machinery.

This is a pure navigability win with zero abstraction cost.

## 2. Centralise the store.ErrNotFound to domain error translation

The pattern `if errors.Is(err, store.ErrNotFound) { return
ErrProgramNotFound{ID: id} }` appears at multiple call sites across
the manager. Each site manually translates the store's sentinel error
into the appropriate domain error type.

This is an Ousterhout "define errors out of existence" opportunity.
A single helper (or a method on the store adapter) could perform the
translation once:

```go
func programOrNotFound(store platform.ProgramReader, ctx context.Context, id uint32) (bpfman.ProgramRecord, error) {
    rec, err := store.Get(ctx, id)
    if errors.Is(err, store.ErrNotFound) {
        return rec, bpfman.ErrProgramNotFound{ID: id}
    }
    return rec, err
}
```

This eliminates scattered error-translation boilerplate and ensures
every call site produces consistent domain errors. The same pattern
applies to link lookups (`ErrLinkNotFound`).

## 3. Reduce outcome recording ceremony in mutating methods

The `outcome.OperationOutcome` and `ManagerError` system is thorough:
it captures timelines, rollback errors, and residual artefacts. But
roughly 40% of the lines in methods like `simpleAttach` and `load`
are dedicated to constructing `outcome.Step` structs, calling
`rec.Complete` or `rec.Fail`, and wrapping with detail types like
`outcome.LinkDetails` or `outcome.ProgramDetails`.

The reporting mechanism is visible in every mutating method. This is
the opposite of information hiding: business logic is interleaved with
recording plumbing.

One approach: push recording into the executor. Each `Action` already
carries enough information (its type, target identifiers) to generate
a step automatically. The executor could record a completed or failed
step for every action it interprets, without the caller manually
building the step struct. The current approach gives maximum control
(custom `StepKind`s, custom `Details`), but at the cost of manual
ceremony in every operation. The trade-off is whether the custom
detail types justify the per-method boilerplate, or whether
auto-derived steps are sufficient for most cases.

This is the least clear-cut of the three issues. The outcome system's
expressiveness is valuable for diagnostics and the `doctor` command.
Any simplification must preserve that expressiveness for the cases
that need it.

## 4. The Load path's bespoke rollback

`load.go` is 857 lines and deliberately opts out of the action system.
The doc.go explains this: Load must observe intermediate results (the
kernel-assigned ID) before computing the next phase. The `undoStack`
provides rollback.

This is a fair engineering decision. But the cost is that Load
re-implements its own rollback mechanism instead of leveraging the
executor's uniform error handling. Every other mutating operation
benefits from the action/executor abstraction. Load does not.

In a language with `IO[A]` or algebraic effects, the action type
would be parameterised by its result (`Action[A]`), and sequencing
would be `flatMap`: each step depends on the prior result, but the
interpreter still owns execution and recording. In Go, without
parametric effects, this would likely add more complexity than it
resolves. The `undoStack` approach is honest about the mismatch.

This is worth noting as a known asymmetry rather than a defect to
fix immediately.

## 5. KernelOperations is wide and expensive to fake

`KernelOperations` composes 10 sub-interfaces into approximately 25
methods. The sub-interface decomposition helps at call sites (methods
can accept only the narrow interface they need), but for testing the
full `fakeKernel` is 1,000 lines.

Ousterhout would ask: can the real implementation be split too, not
just the interface? If `ProgramLoader`, `ProgramAttacher`, and
`LinkDetacher` were truly independent subsystems, they could be tested
independently with smaller fakes. But they share the cilium/ebpf
adapter, so the wide interface reflects a genuinely wide subsystem.

If the fake continues to grow, consider composing it from smaller
fakes that implement the narrow sub-interfaces independently. This
would make it easier to write focused tests that only exercise one
facet of kernel interaction.

## 6. The root bpfman package is wide and shallow

46 exported types, 37 exported functions, spanning domain concerns:
programs, links, attach specs, load specs, image metadata, error
types, type enumerations. This is not a *module* in Ousterhout's
sense -- it is a namespace. It provides no information hiding; every
type is fully public and every consumer sees every type.

This is a Go convention (centralise types to avoid import cycles),
not a design principle. The cost is that changes to, say,
`TCXAttachOrder` are visible to code that only cares about
tracepoints.

This may be an acceptable trade-off. But if the root package
continues to grow, splitting by concern (e.g., separating attach
spec types from program types) might become worthwhile. The sealed
interface pattern used for `AttachSpec` and `LinkDetails` would still
work across package boundaries.
