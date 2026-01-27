package manager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/config"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter"
)

// --------------------------------------------------------------------
// Tuple types: correlated views across DB, kernel, and filesystem.
// Each field is nil when the object is absent in that source.
// --------------------------------------------------------------------

// ProgramState correlates a program across all three sources.
// Primary key: kernel program ID.
type ProgramState struct {
	KernelID uint32
	DB       *bpfman.Program // nil = no DB record
	Kernel   bool            // true = kernel program alive
	PinPath  string          // derived from DB; empty if no DB record
	PinExist *bool           // nil = not checked; non-nil = stat result
}

// LinkState correlates a link across DB and kernel.
// Primary key: kernel link ID.
type LinkState struct {
	DB        *bpfman.LinkSummary // nil = no DB record
	Kernel    bool                // true = kernel link alive
	Synthetic bool                // true = perf_event synthetic ID
	PinExist  *bool               // nil = not checked
}

// DispatcherState correlates a dispatcher across all three sources.
// Primary key: (type, nsid, ifindex).
type DispatcherState struct {
	DB           *dispatcher.State // nil = no DB record
	KernelProg   bool              // true = dispatcher kernel program alive
	KernelLink   bool              // true = XDP link alive (irrelevant for TC)
	ProgPinExist *bool             // nil = not checked
	LinkPinExist *bool             // nil = not checked (XDP only)
	TCFilterOK   *bool             // nil = not checked (TC only)
	LinkCount    int               // number of extension links (-1 = unknown)
	RevDir       string            // computed revision directory path
	ProgPin      string            // computed prog pin path
}

// FsOrphan represents a filesystem entry with no matching DB record.
type FsOrphan struct {
	Path     string
	KernelID uint32 // parsed from name; 0 if not parseable
	Kind     string // "prog-pin", "link-dir", "map-dir", "dispatcher-dir", "dispatcher-link"
}

// Operation is a planned mutation. Rules emit operations; the
// executor applies them. This separates planning from doing.
type Operation struct {
	Description string
	Execute     func() error
}

// Violation is a coherency rule violation with an optional planned
// operation for GC to execute.
type Violation struct {
	Severity    Severity
	Category    string
	Description string
	Op          *Operation // nil = report only
}

// Finding returns the violation as a Finding for doctor output.
func (v Violation) Finding() Finding {
	return Finding{
		Severity:    v.Severity,
		Category:    v.Category,
		Description: v.Description,
	}
}

// Rule is a declarative coherency check evaluated over an
// ObservedState snapshot.
type Rule struct {
	Name string
	Eval func(s *ObservedState) []Violation
}

// --------------------------------------------------------------------
// ObservedState: the system snapshot with correlated views.
// --------------------------------------------------------------------

// ObservedState is a point-in-time snapshot of all three state
// sources with pre-built correlated views. Rules consume this;
// they never reach back into raw maps.
type ObservedState struct {
	// Raw facts (private to view builders).
	dbPrograms    map[uint32]bpfman.Program
	dbLinks       []bpfman.LinkSummary
	dbDispatchers []dispatcher.State
	kernelProgs   map[uint32]bool
	kernelLinks   map[uint32]bool

	// Indexes.
	dbProgPins       map[string]bool
	dbProgIDs        map[uint32]bool
	dbDispatcherKeys map[string]bool

	// Runtime deps.
	dirs             config.RuntimeDirs
	countLinks       func(kernelID uint32) (int, error)
	findTCFilter     func(ifindex int, parent uint32, priority uint16) (uint32, error)
	deleteDispatcher func(dispType string, nsid uint64, ifindex uint32) error

	// Cached views (built lazily on first access).
	programs    []ProgramState
	links       []LinkState
	dispatchers []DispatcherState
	orphans     []FsOrphan
}

// GatherState builds an ObservedState by scanning all three sources.
func GatherState(ctx context.Context, store interpreter.Store, kernel interpreter.KernelOperations, dirs config.RuntimeDirs) (*ObservedState, error) {
	s := &ObservedState{
		kernelProgs:      make(map[uint32]bool),
		kernelLinks:      make(map[uint32]bool),
		dbProgPins:       make(map[string]bool),
		dbProgIDs:        make(map[uint32]bool),
		dbDispatcherKeys: make(map[string]bool),
		dirs:             dirs,
	}

	var err error

	s.dbPrograms, err = store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list programs: %w", err)
	}

	s.dbLinks, err = store.ListLinks(ctx)
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}

	s.dbDispatchers, err = store.ListDispatchers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list dispatchers: %w", err)
	}

	for kp, err := range kernel.Programs(ctx) {
		if err != nil {
			continue
		}
		s.kernelProgs[kp.ID] = true
	}

	for kl, err := range kernel.Links(ctx) {
		if err != nil {
			continue
		}
		s.kernelLinks[kl.ID] = true
	}

	// Build indexes.
	for kernelID, prog := range s.dbPrograms {
		s.dbProgIDs[kernelID] = true
		if prog.PinPath != "" {
			s.dbProgPins[prog.PinPath] = true
		}
	}
	for _, d := range s.dbDispatchers {
		s.dbDispatcherKeys[dispatcherKey(d.Type, d.Nsid, d.Ifindex)] = true
	}

	// Wire up query functions.
	s.countLinks = func(kernelID uint32) (int, error) {
		return store.CountDispatcherLinks(ctx, kernelID)
	}
	s.findTCFilter = func(ifindex int, parent uint32, priority uint16) (uint32, error) {
		return kernel.FindTCFilterHandle(ifindex, parent, priority)
	}
	s.deleteDispatcher = func(dispType string, nsid uint64, ifindex uint32) error {
		return store.DeleteDispatcher(ctx, dispType, nsid, ifindex)
	}

	return s, nil
}

// --------------------------------------------------------------------
// View builders: construct correlated tuples from raw facts.
// All joins happen here. Rules never touch raw maps.
// --------------------------------------------------------------------

// Programs returns one ProgramState per DB program, correlated with
// kernel and filesystem state.
func (s *ObservedState) Programs() []ProgramState {
	if s.programs != nil {
		return s.programs
	}
	for id, prog := range s.dbPrograms {
		ps := ProgramState{
			KernelID: id,
			DB:       &prog,
			Kernel:   s.kernelProgs[id],
			PinPath:  prog.PinPath,
		}
		if prog.PinPath != "" {
			_, err := os.Stat(prog.PinPath)
			exists := !os.IsNotExist(err)
			ps.PinExist = &exists
		}
		s.programs = append(s.programs, ps)
	}
	return s.programs
}

// Links returns one LinkState per DB link, correlated with kernel
// state and filesystem.
func (s *ObservedState) Links() []LinkState {
	if s.links != nil {
		return s.links
	}
	for i := range s.dbLinks {
		link := &s.dbLinks[i]
		ls := LinkState{
			DB:        link,
			Synthetic: bpfman.IsSyntheticLinkID(link.KernelLinkID),
			Kernel:    s.kernelLinks[link.KernelLinkID],
		}
		if link.PinPath != "" && !ls.Synthetic {
			_, err := os.Stat(link.PinPath)
			exists := !os.IsNotExist(err)
			ls.PinExist = &exists
		}
		s.links = append(s.links, ls)
	}
	return s.links
}

// Dispatchers returns one DispatcherState per DB dispatcher,
// correlated with kernel, filesystem, and extension link counts.
func (s *ObservedState) Dispatchers() []DispatcherState {
	if s.dispatchers != nil {
		return s.dispatchers
	}
	for _, d := range s.dbDispatchers {
		revDir := dispatcher.DispatcherRevisionDir(s.dirs.FS, d.Type, d.Nsid, d.Ifindex, d.Revision)
		progPin := dispatcher.DispatcherProgPath(revDir)

		ds := DispatcherState{
			DB:         &d,
			KernelProg: s.kernelProgs[d.KernelID],
			RevDir:     revDir,
			ProgPin:    progPin,
			LinkCount:  -1,
		}

		// Prog pin existence.
		_, err := os.Stat(progPin)
		ppExists := !os.IsNotExist(err)
		ds.ProgPinExist = &ppExists

		// XDP link checks.
		if d.Type == dispatcher.DispatcherTypeXDP {
			ds.KernelLink = d.LinkID != 0 && s.kernelLinks[d.LinkID]
			linkPin := dispatcher.DispatcherLinkPath(s.dirs.FS, d.Type, d.Nsid, d.Ifindex)
			_, err := os.Stat(linkPin)
			lpExists := !os.IsNotExist(err)
			ds.LinkPinExist = &lpExists
		}

		// TC filter check.
		if d.Type == dispatcher.DispatcherTypeTCIngress || d.Type == dispatcher.DispatcherTypeTCEgress {
			if d.Priority > 0 {
				parent := tcParent(d.Type)
				_, err := s.findTCFilter(int(d.Ifindex), parent, d.Priority)
				ok := err == nil
				ds.TCFilterOK = &ok
			}
		}

		// Extension link count.
		if count, err := s.countLinks(d.KernelID); err == nil {
			ds.LinkCount = count
		}

		s.dispatchers = append(s.dispatchers, ds)
	}
	return s.dispatchers
}

// OrphanFsEntries returns filesystem entries under the bpffs tree
// that have no corresponding DB record.
func (s *ObservedState) OrphanFsEntries() []FsOrphan {
	if s.orphans != nil {
		return s.orphans
	}
	s.orphans = make([]FsOrphan, 0)

	// Orphan prog_* pins.
	if entries, err := os.ReadDir(s.dirs.FS); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, "prog_") {
				continue
			}
			pinPath := filepath.Join(s.dirs.FS, name)
			if s.dbProgPins[pinPath] {
				continue
			}
			var kernelID uint32
			if n, _ := fmt.Sscanf(name, "prog_%d", &kernelID); n == 1 {
				s.orphans = append(s.orphans, FsOrphan{Path: pinPath, KernelID: kernelID, Kind: "prog-pin"})
			}
		}
	}

	// Orphan link pin directories.
	if entries, err := os.ReadDir(s.dirs.FS_LINKS); err == nil {
		for _, entry := range entries {
			var progID uint32
			if n, _ := fmt.Sscanf(entry.Name(), "%d", &progID); n != 1 {
				continue
			}
			if s.dbProgIDs[progID] {
				continue
			}
			s.orphans = append(s.orphans, FsOrphan{
				Path:     filepath.Join(s.dirs.FS_LINKS, entry.Name()),
				KernelID: progID,
				Kind:     "link-dir",
			})
		}
	}

	// Orphan map pin directories.
	if entries, err := os.ReadDir(s.dirs.FS_MAPS); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			var progID uint32
			if n, _ := fmt.Sscanf(entry.Name(), "%d", &progID); n != 1 {
				continue
			}
			if s.dbProgIDs[progID] {
				continue
			}
			s.orphans = append(s.orphans, FsOrphan{
				Path:     filepath.Join(s.dirs.FS_MAPS, entry.Name()),
				KernelID: progID,
				Kind:     "map-dir",
			})
		}
	}

	// Orphan dispatcher directories and link pins.
	dispTypes := []dispatcher.DispatcherType{
		dispatcher.DispatcherTypeXDP,
		dispatcher.DispatcherTypeTCIngress,
		dispatcher.DispatcherTypeTCEgress,
	}
	for _, dt := range dispTypes {
		typeDir := dispatcher.TypeDir(s.dirs.FS, dt)
		entries, err := os.ReadDir(typeDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, "dispatcher_") {
				continue
			}
			if entry.IsDir() {
				var nsid uint64
				var ifindex, revision uint32
				if n, _ := fmt.Sscanf(name, "dispatcher_%d_%d_%d", &nsid, &ifindex, &revision); n != 3 {
					continue
				}
				if s.dbDispatcherKeys[dispatcherKey(dt, nsid, ifindex)] {
					continue
				}
				s.orphans = append(s.orphans, FsOrphan{
					Path: filepath.Join(typeDir, name),
					Kind: "dispatcher-dir",
				})
			} else if strings.HasSuffix(name, "_link") {
				var nsid uint64
				var ifindex uint32
				if n, _ := fmt.Sscanf(name, "dispatcher_%d_%d_link", &nsid, &ifindex); n != 2 {
					continue
				}
				if s.dbDispatcherKeys[dispatcherKey(dt, nsid, ifindex)] {
					continue
				}
				s.orphans = append(s.orphans, FsOrphan{
					Path: filepath.Join(typeDir, name),
					Kind: "dispatcher-link",
				})
			}
		}
	}

	return s.orphans
}

// DispatcherFsLinkCount counts link_* files in the dispatcher's
// revision directory. Returns -1 on error.
func (s *ObservedState) DispatcherFsLinkCount(ds DispatcherState) int {
	entries, err := os.ReadDir(ds.RevDir)
	if err != nil {
		return -1
	}
	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "link_") {
			count++
		}
	}
	return count
}

// KernelAlive reports whether a kernel program ID is alive.
func (s *ObservedState) KernelAlive(kernelID uint32) bool {
	return s.kernelProgs[kernelID]
}

// DeleteDispatcher delegates to the store to remove a dispatcher.
func (s *ObservedState) DeleteDispatcher(dispType string, nsid uint64, ifindex uint32) error {
	return s.deleteDispatcher(dispType, nsid, ifindex)
}

func dispatcherKey(dt dispatcher.DispatcherType, nsid uint64, ifindex uint32) string {
	return fmt.Sprintf("%s/%d/%d", dt, nsid, ifindex)
}

// --------------------------------------------------------------------
// Evaluate: uniform rule evaluation.
// --------------------------------------------------------------------

// Evaluate runs all rules against the observed state and returns
// violations found.
func Evaluate(state *ObservedState, rules []Rule) []Violation {
	var violations []Violation
	for _, rule := range rules {
		violations = append(violations, rule.Eval(state)...)
	}
	return violations
}

// --------------------------------------------------------------------
// CoherencyRules: read-only doctor checks (D1-D14).
// Rules consume tuples. No raw map lookups. No joins.
// --------------------------------------------------------------------

// CoherencyRules returns all doctor rules.
func CoherencyRules() []Rule {
	return []Rule{
		// D1: DB program exists in kernel.
		{
			Name: "D1",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, p := range s.Programs() {
					if p.DB != nil && !p.Kernel {
						out = append(out, Violation{
							Severity:    SeverityError,
							Category:    "db-vs-kernel",
							Description: fmt.Sprintf("Program %d in DB not found in kernel (pin: %s)", p.KernelID, p.PinPath),
						})
					}
				}
				return out
			},
		},
		// D2: DB link exists in kernel.
		{
			Name: "D2",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, l := range s.Links() {
					if l.Synthetic || l.DB == nil {
						continue
					}
					if !l.Kernel {
						out = append(out, Violation{
							Severity:    SeverityError,
							Category:    "db-vs-kernel",
							Description: fmt.Sprintf("Link %d in DB not found in kernel (program: %d)", l.DB.KernelLinkID, l.DB.KernelProgramID),
						})
					}
				}
				return out
			},
		},
		// D3: DB dispatcher program exists in kernel.
		{
			Name: "D3",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, d := range s.Dispatchers() {
					if d.DB != nil && !d.KernelProg {
						out = append(out, Violation{
							Severity:    SeverityError,
							Category:    "db-vs-kernel",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: program %d not found in kernel", d.DB.Type, d.DB.Nsid, d.DB.Ifindex, d.DB.KernelID),
						})
					}
				}
				return out
			},
		},
		// D4: XDP dispatcher link exists in kernel.
		{
			Name: "D4",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, d := range s.Dispatchers() {
					if d.DB != nil && d.DB.Type == dispatcher.DispatcherTypeXDP && d.DB.LinkID != 0 && !d.KernelLink {
						out = append(out, Violation{
							Severity:    SeverityError,
							Category:    "db-vs-kernel",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: link %d not found in kernel", d.DB.Type, d.DB.Nsid, d.DB.Ifindex, d.DB.LinkID),
						})
					}
				}
				return out
			},
		},
		// D5: TC dispatcher filter exists in kernel.
		{
			Name: "D5",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, d := range s.Dispatchers() {
					if d.TCFilterOK != nil && !*d.TCFilterOK {
						out = append(out, Violation{
							Severity:    SeverityError,
							Category:    "db-vs-kernel",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: TC filter not found (priority %d)", d.DB.Type, d.DB.Nsid, d.DB.Ifindex, d.DB.Priority),
						})
					}
				}
				return out
			},
		},
		// D6: DB program pin exists on filesystem.
		{
			Name: "D6",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, p := range s.Programs() {
					if p.PinExist != nil && !*p.PinExist {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "db-vs-fs",
							Description: fmt.Sprintf("Program %d: pin path missing: %s", p.KernelID, p.PinPath),
						})
					}
				}
				return out
			},
		},
		// D7: DB link pin exists on filesystem.
		{
			Name: "D7",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, l := range s.Links() {
					if l.Synthetic || l.DB == nil {
						continue
					}
					if l.PinExist != nil && !*l.PinExist {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "db-vs-fs",
							Description: fmt.Sprintf("Link %d: pin path missing: %s", l.DB.KernelLinkID, l.DB.PinPath),
						})
					}
				}
				return out
			},
		},
		// D8: DB dispatcher prog pin exists on filesystem.
		{
			Name: "D8",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, d := range s.Dispatchers() {
					if d.ProgPinExist != nil && !*d.ProgPinExist {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "db-vs-fs",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: prog pin missing: %s", d.DB.Type, d.DB.Nsid, d.DB.Ifindex, d.ProgPin),
						})
					}
				}
				return out
			},
		},
		// D9: XDP dispatcher link pin exists on filesystem.
		{
			Name: "D9",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, d := range s.Dispatchers() {
					if d.LinkPinExist != nil && !*d.LinkPinExist {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "db-vs-fs",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: link pin missing", d.DB.Type, d.DB.Nsid, d.DB.Ifindex),
						})
					}
				}
				return out
			},
		},
		// D10-D13: Filesystem orphans.
		{
			Name: "D10-D13",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, o := range s.OrphanFsEntries() {
					out = append(out, Violation{
						Severity:    SeverityWarning,
						Category:    "fs-vs-db",
						Description: fmt.Sprintf("Orphan %s: %s", o.Kind, o.Path),
					})
				}
				return out
			},
		},
		// D14: Dispatcher link count matches filesystem.
		{
			Name: "D14",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, d := range s.Dispatchers() {
					if d.LinkCount < 0 {
						continue
					}
					fsCount := s.DispatcherFsLinkCount(d)
					if fsCount < 0 {
						continue
					}
					if d.LinkCount != fsCount {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "consistency",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: DB link count (%d) != filesystem link count (%d)", d.DB.Type, d.DB.Nsid, d.DB.Ifindex, d.LinkCount, fsCount),
						})
					}
				}
				return out
			},
		},
	}
}

// --------------------------------------------------------------------
// GCRules: rules that plan mutations (G5-G12).
// Each violation carries an Operation the executor can apply.
// --------------------------------------------------------------------

// GCRules returns rules that detect and plan repairs for stale state.
func GCRules() []Rule {
	return []Rule{
		// G5-G7: Stale dispatchers with zero extension links.
		{
			Name: "G5-G7",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, d := range s.Dispatchers() {
					if d.DB == nil || d.LinkCount > 0 {
						continue
					}
					stale := false
					if d.ProgPinExist != nil && !*d.ProgPinExist {
						stale = true // G5: prog pin missing
					} else if d.TCFilterOK != nil && !*d.TCFilterOK {
						stale = true // G6: TC filter missing
					}
					if !stale {
						continue
					}
					dd := d // capture
					out = append(out, Violation{
						Severity:    SeverityWarning,
						Category:    "gc-dispatcher",
						Description: fmt.Sprintf("Stale dispatcher %s nsid=%d ifindex=%d: no extensions, functionally dead", d.DB.Type, d.DB.Nsid, d.DB.Ifindex),
						Op: &Operation{
							Description: fmt.Sprintf("delete dispatcher %s/%d/%d and filesystem artefacts", d.DB.Type, d.DB.Nsid, d.DB.Ifindex),
							Execute: func() error {
								os.Remove(dd.ProgPin)
								os.Remove(dd.RevDir)
								if dd.DB.Type == dispatcher.DispatcherTypeXDP {
									linkPin := dispatcher.DispatcherLinkPath(s.dirs.FS, dd.DB.Type, dd.DB.Nsid, dd.DB.Ifindex)
									os.Remove(linkPin)
								}
								return s.DeleteDispatcher(string(dd.DB.Type), dd.DB.Nsid, dd.DB.Ifindex)
							},
						},
					})
				}
				return out
			},
		},
		// G8-G10: Orphan prog pins, link dirs, map dirs.
		{
			Name: "G8-G10",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, o := range s.OrphanFsEntries() {
					if o.Kind != "prog-pin" && o.Kind != "link-dir" && o.Kind != "map-dir" {
						continue
					}
					if o.KernelID != 0 && s.KernelAlive(o.KernelID) {
						continue // kernel object alive; leave it
					}
					oo := o // capture
					isDir := o.Kind != "prog-pin"
					out = append(out, Violation{
						Severity:    SeverityWarning,
						Category:    "gc-orphan-pin",
						Description: fmt.Sprintf("Orphan %s: %s", o.Kind, o.Path),
						Op: &Operation{
							Description: fmt.Sprintf("remove %s", o.Path),
							Execute: func() error {
								if isDir {
									return os.RemoveAll(oo.Path)
								}
								return os.Remove(oo.Path)
							},
						},
					})
				}
				return out
			},
		},
		// G11-G12: Orphan dispatcher directories and link pins.
		{
			Name: "G11-G12",
			Eval: func(s *ObservedState) []Violation {
				var out []Violation
				for _, o := range s.OrphanFsEntries() {
					if o.Kind != "dispatcher-dir" && o.Kind != "dispatcher-link" {
						continue
					}
					oo := o
					isDir := o.Kind == "dispatcher-dir"
					out = append(out, Violation{
						Severity:    SeverityWarning,
						Category:    "gc-orphan-pin",
						Description: fmt.Sprintf("Orphan %s: %s", o.Kind, o.Path),
						Op: &Operation{
							Description: fmt.Sprintf("remove %s", o.Path),
							Execute: func() error {
								if isDir {
									return os.RemoveAll(oo.Path)
								}
								return os.Remove(oo.Path)
							},
						},
					})
				}
				return out
			},
		},
	}
}

// --------------------------------------------------------------------
// Manager methods: Doctor2 and GC2 using the rule engine.
// --------------------------------------------------------------------

// Doctor2 gathers state and evaluates all coherency rules.
func (m *Manager) Doctor2(ctx context.Context) (DoctorReport, error) {
	state, err := GatherState(ctx, m.store, m.kernel, m.dirs)
	if err != nil {
		return DoctorReport{}, fmt.Errorf("gather state: %w", err)
	}

	violations := Evaluate(state, CoherencyRules())

	var report DoctorReport
	for _, v := range violations {
		report.Findings = append(report.Findings, v.Finding())
	}
	return report, nil
}

// GC2 gathers state, evaluates GC rules, and executes planned
// operations. Returns the number of operations applied.
func (m *Manager) GC2(ctx context.Context) (int, error) {
	state, err := GatherState(ctx, m.store, m.kernel, m.dirs)
	if err != nil {
		return 0, fmt.Errorf("gather state: %w", err)
	}

	violations := Evaluate(state, GCRules())

	applied := 0
	for _, v := range violations {
		if v.Op == nil {
			continue
		}
		if err := v.Op.Execute(); err != nil {
			m.logger.Warn("gc operation failed",
				"op", v.Op.Description,
				"error", err)
			continue
		}
		m.logger.Info("gc operation applied", "op", v.Op.Description)
		applied++
	}
	return applied, nil
}
