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

// Violation is a coherency rule violation. It carries a finding for
// reporting and an optional cleanup function for GC.
type Violation struct {
	Severity    Severity
	Category    string
	Description string
	Cleanup     func() error // nil = report only, non-nil = GC can act
}

// Finding returns the violation as a Finding for doctor output.
func (v Violation) Finding() Finding {
	return Finding{
		Severity:    v.Severity,
		Category:    v.Category,
		Description: v.Description,
	}
}

// Rule is a declarative coherency check. It evaluates a predicate
// over the gathered fact set and returns any violations found.
type Rule struct {
	Name string
	Eval func(facts *FactSet) []Violation
}

// FactSet holds gathered state from all three sources. Built once,
// then passed to every rule for evaluation.
type FactSet struct {
	// Database state.
	DBPrograms    map[uint32]bpfman.Program
	DBLinks       []bpfman.LinkSummary
	DBDispatchers []dispatcher.State

	// Kernel state.
	KernelPrograms map[uint32]bool
	KernelLinks    map[uint32]bool

	// Derived DB indexes (built during gathering).
	DBProgPins       map[string]bool // pin path -> exists
	DBProgIDs        map[uint32]bool // kernel ID -> exists
	DBDispatcherKeys map[string]bool // "type/nsid/ifindex" -> exists

	// Runtime dependencies for rules that need deeper queries.
	Dirs             config.RuntimeDirs
	CountLinks       func(dispatcherKernelID uint32) (int, error)
	FindTCFilter     func(ifindex int, parent uint32, priority uint16) (uint32, error)
	DeleteDispatcher func(dispType string, nsid uint64, ifindex uint32) error
}

// GatherFacts builds a FactSet by scanning all three state sources.
func GatherFacts(ctx context.Context, store interpreter.Store, kernel interpreter.KernelOperations, dirs config.RuntimeDirs) (*FactSet, error) {
	facts := &FactSet{
		KernelPrograms:   make(map[uint32]bool),
		KernelLinks:      make(map[uint32]bool),
		DBProgPins:       make(map[string]bool),
		DBProgIDs:        make(map[uint32]bool),
		DBDispatcherKeys: make(map[string]bool),
		Dirs:             dirs,
	}

	var err error

	facts.DBPrograms, err = store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list programs: %w", err)
	}

	facts.DBLinks, err = store.ListLinks(ctx)
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}

	facts.DBDispatchers, err = store.ListDispatchers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list dispatchers: %w", err)
	}

	for kp, err := range kernel.Programs(ctx) {
		if err != nil {
			continue
		}
		facts.KernelPrograms[kp.ID] = true
	}

	for kl, err := range kernel.Links(ctx) {
		if err != nil {
			continue
		}
		facts.KernelLinks[kl.ID] = true
	}

	// Build derived indexes.
	for kernelID, prog := range facts.DBPrograms {
		facts.DBProgIDs[kernelID] = true
		if prog.PinPath != "" {
			facts.DBProgPins[prog.PinPath] = true
		}
	}

	for _, d := range facts.DBDispatchers {
		key := fmt.Sprintf("%s/%d/%d", d.Type, d.Nsid, d.Ifindex)
		facts.DBDispatcherKeys[key] = true
	}

	// Wire up query functions.
	facts.CountLinks = func(kernelID uint32) (int, error) {
		return store.CountDispatcherLinks(ctx, kernelID)
	}
	facts.FindTCFilter = func(ifindex int, parent uint32, priority uint16) (uint32, error) {
		return kernel.FindTCFilterHandle(ifindex, parent, priority)
	}
	facts.DeleteDispatcher = func(dispType string, nsid uint64, ifindex uint32) error {
		return store.DeleteDispatcher(ctx, dispType, nsid, ifindex)
	}

	return facts, nil
}

// Evaluate runs all rules against the fact set and returns the
// violations found.
func Evaluate(facts *FactSet, rules []Rule) []Violation {
	var violations []Violation
	for _, rule := range rules {
		violations = append(violations, rule.Eval(facts)...)
	}
	return violations
}

// CoherencyRules returns all doctor rules. These are read-only checks
// that detect but do not repair inconsistencies.
func CoherencyRules() []Rule {
	return []Rule{
		// DB vs kernel.
		{
			Name: "D1: DB program exists in kernel",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for id, prog := range f.DBPrograms {
					if !f.KernelPrograms[id] {
						out = append(out, Violation{
							Severity:    SeverityError,
							Category:    "db-vs-kernel",
							Description: fmt.Sprintf("Program %d in DB not found in kernel (pin: %s)", id, prog.PinPath),
						})
					}
				}
				return out
			},
		},
		{
			Name: "D2: DB link exists in kernel",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for _, link := range f.DBLinks {
					if bpfman.IsSyntheticLinkID(link.KernelLinkID) {
						continue
					}
					if !f.KernelLinks[link.KernelLinkID] {
						out = append(out, Violation{
							Severity:    SeverityError,
							Category:    "db-vs-kernel",
							Description: fmt.Sprintf("Link %d in DB not found in kernel (program: %d)", link.KernelLinkID, link.KernelProgramID),
						})
					}
				}
				return out
			},
		},
		{
			Name: "D3: DB dispatcher program exists in kernel",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for _, d := range f.DBDispatchers {
					if !f.KernelPrograms[d.KernelID] {
						out = append(out, Violation{
							Severity:    SeverityError,
							Category:    "db-vs-kernel",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: program %d not found in kernel", d.Type, d.Nsid, d.Ifindex, d.KernelID),
						})
					}
				}
				return out
			},
		},
		{
			Name: "D4: XDP dispatcher link exists in kernel",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for _, d := range f.DBDispatchers {
					if d.Type == dispatcher.DispatcherTypeXDP && d.LinkID != 0 {
						if !f.KernelLinks[d.LinkID] {
							out = append(out, Violation{
								Severity:    SeverityError,
								Category:    "db-vs-kernel",
								Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: link %d not found in kernel", d.Type, d.Nsid, d.Ifindex, d.LinkID),
							})
						}
					}
				}
				return out
			},
		},
		{
			Name: "D5: TC dispatcher filter exists in kernel",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for _, d := range f.DBDispatchers {
					if d.Type != dispatcher.DispatcherTypeTCIngress && d.Type != dispatcher.DispatcherTypeTCEgress {
						continue
					}
					if d.Priority == 0 {
						continue
					}
					parent := tcParent(d.Type)
					if _, err := f.FindTCFilter(int(d.Ifindex), parent, d.Priority); err != nil {
						out = append(out, Violation{
							Severity:    SeverityError,
							Category:    "db-vs-kernel",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: TC filter not found (priority %d): %v", d.Type, d.Nsid, d.Ifindex, d.Priority, err),
						})
					}
				}
				return out
			},
		},

		// DB vs filesystem.
		{
			Name: "D6: DB program pin exists on filesystem",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for id, prog := range f.DBPrograms {
					if prog.PinPath == "" {
						continue
					}
					if _, err := os.Stat(prog.PinPath); os.IsNotExist(err) {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "db-vs-fs",
							Description: fmt.Sprintf("Program %d: pin path missing: %s", id, prog.PinPath),
						})
					}
				}
				return out
			},
		},
		{
			Name: "D7: DB link pin exists on filesystem",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for _, link := range f.DBLinks {
					if bpfman.IsSyntheticLinkID(link.KernelLinkID) {
						continue
					}
					if link.PinPath == "" {
						continue
					}
					if _, err := os.Stat(link.PinPath); os.IsNotExist(err) {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "db-vs-fs",
							Description: fmt.Sprintf("Link %d: pin path missing: %s", link.KernelLinkID, link.PinPath),
						})
					}
				}
				return out
			},
		},
		{
			Name: "D8: DB dispatcher prog pin exists on filesystem",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for _, d := range f.DBDispatchers {
					revDir := dispatcher.DispatcherRevisionDir(f.Dirs.FS, d.Type, d.Nsid, d.Ifindex, d.Revision)
					progPin := dispatcher.DispatcherProgPath(revDir)
					if _, err := os.Stat(progPin); os.IsNotExist(err) {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "db-vs-fs",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: prog pin missing: %s", d.Type, d.Nsid, d.Ifindex, progPin),
						})
					}
				}
				return out
			},
		},
		{
			Name: "D9: XDP dispatcher link pin exists on filesystem",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for _, d := range f.DBDispatchers {
					if d.Type != dispatcher.DispatcherTypeXDP {
						continue
					}
					linkPin := dispatcher.DispatcherLinkPath(f.Dirs.FS, d.Type, d.Nsid, d.Ifindex)
					if _, err := os.Stat(linkPin); os.IsNotExist(err) {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "db-vs-fs",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: link pin missing: %s", d.Type, d.Nsid, d.Ifindex, linkPin),
						})
					}
				}
				return out
			},
		},

		// Filesystem vs DB (orphans).
		{
			Name: "D10: prog pin has DB record",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				entries, err := os.ReadDir(f.Dirs.FS)
				if err != nil {
					return nil
				}
				for _, entry := range entries {
					name := entry.Name()
					if !strings.HasPrefix(name, "prog_") {
						continue
					}
					pinPath := filepath.Join(f.Dirs.FS, name)
					if !f.DBProgPins[pinPath] {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "fs-vs-db",
							Description: fmt.Sprintf("Orphan program pin: %s", pinPath),
						})
					}
				}
				return out
			},
		},
		{
			Name: "D11: link pin directory has DB record",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				entries, err := os.ReadDir(f.Dirs.FS_LINKS)
				if err != nil {
					return nil
				}
				for _, entry := range entries {
					var progID uint32
					if n, _ := fmt.Sscanf(entry.Name(), "%d", &progID); n != 1 {
						continue
					}
					if !f.DBProgIDs[progID] {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "fs-vs-db",
							Description: fmt.Sprintf("Orphan link pin directory: %s", filepath.Join(f.Dirs.FS_LINKS, entry.Name())),
						})
					}
				}
				return out
			},
		},
		{
			Name: "D12: map pin directory has DB record",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				entries, err := os.ReadDir(f.Dirs.FS_MAPS)
				if err != nil {
					return nil
				}
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					var progID uint32
					if n, _ := fmt.Sscanf(entry.Name(), "%d", &progID); n != 1 {
						continue
					}
					if !f.DBProgIDs[progID] {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "fs-vs-db",
							Description: fmt.Sprintf("Orphan map pin directory: %s", filepath.Join(f.Dirs.FS_MAPS, entry.Name())),
						})
					}
				}
				return out
			},
		},
		{
			Name: "D13: dispatcher directory has DB record",
			Eval: dispatcherOrphanDirRule,
		},

		// Derived state consistency.
		{
			Name: "D14: dispatcher link count matches filesystem",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for _, d := range f.DBDispatchers {
					dbCount, err := f.CountLinks(d.KernelID)
					if err != nil {
						continue
					}
					revDir := dispatcher.DispatcherRevisionDir(f.Dirs.FS, d.Type, d.Nsid, d.Ifindex, d.Revision)
					fsCount := 0
					entries, err := os.ReadDir(revDir)
					if err != nil {
						continue
					}
					for _, entry := range entries {
						if strings.HasPrefix(entry.Name(), "link_") {
							fsCount++
						}
					}
					if dbCount != fsCount {
						out = append(out, Violation{
							Severity:    SeverityWarning,
							Category:    "consistency",
							Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: DB link count (%d) != filesystem link count (%d)", d.Type, d.Nsid, d.Ifindex, dbCount, fsCount),
						})
					}
				}
				return out
			},
		},
	}
}

// GCRules returns rules that can repair inconsistencies. Each
// violation carries a Cleanup closure that GC executes.
func GCRules() []Rule {
	return []Rule{
		// G5/G6/G7: Stale dispatchers with zero extension links.
		{
			Name: "G5-G7: stale dispatcher with no extensions",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				for _, d := range f.DBDispatchers {
					linkCount, err := f.CountLinks(d.KernelID)
					if err != nil || linkCount > 0 {
						continue
					}
					revDir := dispatcher.DispatcherRevisionDir(f.Dirs.FS, d.Type, d.Nsid, d.Ifindex, d.Revision)
					progPin := dispatcher.DispatcherProgPath(revDir)

					stale := false
					if _, err := os.Stat(progPin); os.IsNotExist(err) {
						stale = true
					} else if d.Type == dispatcher.DispatcherTypeTCIngress || d.Type == dispatcher.DispatcherTypeTCEgress {
						parent := tcParent(d.Type)
						if _, err := f.FindTCFilter(int(d.Ifindex), parent, d.Priority); err != nil {
							stale = true
						}
					}
					if !stale {
						continue
					}

					// Capture for closure.
					cd, cr, cp := d, revDir, progPin
					out = append(out, Violation{
						Severity:    SeverityWarning,
						Category:    "gc-dispatcher",
						Description: fmt.Sprintf("Stale dispatcher %s nsid=%d ifindex=%d: no extensions, functionally dead", d.Type, d.Nsid, d.Ifindex),
						Cleanup: func() error {
							os.Remove(cp)
							os.Remove(cr)
							if cd.Type == dispatcher.DispatcherTypeXDP {
								linkPin := dispatcher.DispatcherLinkPath(f.Dirs.FS, cd.Type, cd.Nsid, cd.Ifindex)
								os.Remove(linkPin)
							}
							return f.DeleteDispatcher(string(cd.Type), cd.Nsid, cd.Ifindex)
						},
					})
				}
				return out
			},
		},

		// G8: Orphan prog pins (no DB record, kernel object gone).
		{
			Name: "G8: orphan prog pin",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				entries, err := os.ReadDir(f.Dirs.FS)
				if err != nil {
					return nil
				}
				for _, entry := range entries {
					name := entry.Name()
					if !strings.HasPrefix(name, "prog_") {
						continue
					}
					pinPath := filepath.Join(f.Dirs.FS, name)
					if f.DBProgPins[pinPath] {
						continue
					}
					var kernelID uint32
					if n, _ := fmt.Sscanf(name, "prog_%d", &kernelID); n != 1 {
						continue
					}
					if f.KernelPrograms[kernelID] {
						continue
					}
					out = append(out, Violation{
						Severity:    SeverityWarning,
						Category:    "gc-orphan-pin",
						Description: fmt.Sprintf("Orphan program pin: %s", pinPath),
						Cleanup: func() error {
							return os.Remove(pinPath)
						},
					})
				}
				return out
			},
		},

		// G9: Orphan link pin directories.
		{
			Name: "G9: orphan link pin directory",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				entries, err := os.ReadDir(f.Dirs.FS_LINKS)
				if err != nil {
					return nil
				}
				for _, entry := range entries {
					var progID uint32
					if n, _ := fmt.Sscanf(entry.Name(), "%d", &progID); n != 1 {
						continue
					}
					if f.DBProgIDs[progID] || f.KernelPrograms[progID] {
						continue
					}
					dirPath := filepath.Join(f.Dirs.FS_LINKS, entry.Name())
					out = append(out, Violation{
						Severity:    SeverityWarning,
						Category:    "gc-orphan-pin",
						Description: fmt.Sprintf("Orphan link pin directory: %s", dirPath),
						Cleanup: func() error {
							return os.RemoveAll(dirPath)
						},
					})
				}
				return out
			},
		},

		// G10: Orphan map pin directories.
		{
			Name: "G10: orphan map pin directory",
			Eval: func(f *FactSet) []Violation {
				var out []Violation
				entries, err := os.ReadDir(f.Dirs.FS_MAPS)
				if err != nil {
					return nil
				}
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					var progID uint32
					if n, _ := fmt.Sscanf(entry.Name(), "%d", &progID); n != 1 {
						continue
					}
					if f.DBProgIDs[progID] || f.KernelPrograms[progID] {
						continue
					}
					dirPath := filepath.Join(f.Dirs.FS_MAPS, entry.Name())
					out = append(out, Violation{
						Severity:    SeverityWarning,
						Category:    "gc-orphan-pin",
						Description: fmt.Sprintf("Orphan map pin directory: %s", dirPath),
						Cleanup: func() error {
							return os.RemoveAll(dirPath)
						},
					})
				}
				return out
			},
		},

		// G11/G12: Orphan dispatcher directories and link pins.
		{
			Name: "G11-G12: orphan dispatcher filesystem entries",
			Eval: dispatcherOrphanFSRule,
		},
	}
}

// dispatcherOrphanDirRule checks for dispatcher directories on the
// filesystem that have no corresponding DB record. Used by both
// doctor (D13) and as the detection half of GC (G11).
func dispatcherOrphanDirRule(f *FactSet) []Violation {
	var out []Violation
	dispTypes := []dispatcher.DispatcherType{
		dispatcher.DispatcherTypeXDP,
		dispatcher.DispatcherTypeTCIngress,
		dispatcher.DispatcherTypeTCEgress,
	}
	for _, dt := range dispTypes {
		typeDir := dispatcher.TypeDir(f.Dirs.FS, dt)
		entries, err := os.ReadDir(typeDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasPrefix(name, "dispatcher_") {
				continue
			}
			var nsid uint64
			var ifindex, revision uint32
			if n, _ := fmt.Sscanf(name, "dispatcher_%d_%d_%d", &nsid, &ifindex, &revision); n != 3 {
				continue
			}
			key := fmt.Sprintf("%s/%d/%d", dt, nsid, ifindex)
			if !f.DBDispatcherKeys[key] {
				out = append(out, Violation{
					Severity:    SeverityWarning,
					Category:    "fs-vs-db",
					Description: fmt.Sprintf("Orphan dispatcher directory: %s", filepath.Join(typeDir, name)),
				})
			}
		}
	}
	return out
}

// dispatcherOrphanFSRule is the GC variant of the dispatcher orphan
// check. It includes cleanup closures for both revision directories
// and link pin files.
func dispatcherOrphanFSRule(f *FactSet) []Violation {
	var out []Violation
	dispTypes := []dispatcher.DispatcherType{
		dispatcher.DispatcherTypeXDP,
		dispatcher.DispatcherTypeTCIngress,
		dispatcher.DispatcherTypeTCEgress,
	}
	for _, dt := range dispTypes {
		typeDir := dispatcher.TypeDir(f.Dirs.FS, dt)
		entries, err := os.ReadDir(typeDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() {
				if !strings.HasPrefix(name, "dispatcher_") {
					continue
				}
				var nsid uint64
				var ifindex, revision uint32
				if n, _ := fmt.Sscanf(name, "dispatcher_%d_%d_%d", &nsid, &ifindex, &revision); n != 3 {
					continue
				}
				key := fmt.Sprintf("%s/%d/%d", dt, nsid, ifindex)
				if f.DBDispatcherKeys[key] {
					continue
				}
				dirPath := filepath.Join(typeDir, name)
				out = append(out, Violation{
					Severity:    SeverityWarning,
					Category:    "gc-orphan-pin",
					Description: fmt.Sprintf("Orphan dispatcher directory: %s", dirPath),
					Cleanup: func() error {
						return os.RemoveAll(dirPath)
					},
				})
			} else {
				// Dispatcher link pin files.
				if !strings.HasPrefix(name, "dispatcher_") || !strings.HasSuffix(name, "_link") {
					continue
				}
				var nsid uint64
				var ifindex uint32
				if n, _ := fmt.Sscanf(name, "dispatcher_%d_%d_link", &nsid, &ifindex); n != 2 {
					continue
				}
				key := fmt.Sprintf("%s/%d/%d", dt, nsid, ifindex)
				if f.DBDispatcherKeys[key] {
					continue
				}
				linkPinPath := filepath.Join(typeDir, name)
				out = append(out, Violation{
					Severity:    SeverityWarning,
					Category:    "gc-orphan-pin",
					Description: fmt.Sprintf("Orphan dispatcher link pin: %s", linkPinPath),
					Cleanup: func() error {
						return os.Remove(linkPinPath)
					},
				})
			}
		}
	}
	return out
}

// Doctor2 is the rule-engine variant of Doctor. It gathers facts once
// and evaluates all coherency rules against them.
func (m *Manager) Doctor2(ctx context.Context) (DoctorReport, error) {
	facts, err := GatherFacts(ctx, m.store, m.kernel, m.dirs)
	if err != nil {
		return DoctorReport{}, fmt.Errorf("gather facts: %w", err)
	}

	violations := Evaluate(facts, CoherencyRules())

	var report DoctorReport
	for _, v := range violations {
		report.Findings = append(report.Findings, v.Finding())
	}
	return report, nil
}

// GC2 is the rule-engine variant of the post-store GC phases. It
// runs after store.GC and handles dispatcher cleanup (G5-G7) and
// orphan filesystem cleanup (G8-G12) using declarative rules.
//
// It returns the number of items cleaned up across all GC rules.
func (m *Manager) GC2(ctx context.Context) (int, error) {
	facts, err := GatherFacts(ctx, m.store, m.kernel, m.dirs)
	if err != nil {
		return 0, fmt.Errorf("gather facts: %w", err)
	}

	violations := Evaluate(facts, GCRules())

	cleaned := 0
	for _, v := range violations {
		if v.Cleanup == nil {
			continue
		}
		if err := v.Cleanup(); err != nil {
			m.logger.Warn("gc rule cleanup failed",
				"category", v.Category,
				"description", v.Description,
				"error", err)
			continue
		}
		m.logger.Info("gc rule applied",
			"category", v.Category,
			"description", v.Description)
		cleaned++
	}
	return cleaned, nil
}
