package manager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/dispatcher"
)

// Severity indicates the severity of a doctor finding.
type Severity int

const (
	SeverityOK Severity = iota
	SeverityWarning
	SeverityError
)

// String returns a human-readable label for the severity.
func (s Severity) String() string {
	switch s {
	case SeverityOK:
		return "OK"
	case SeverityWarning:
		return "WARNING"
	case SeverityError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Finding describes a single coherency check result.
type Finding struct {
	Severity    Severity
	Category    string
	Description string
}

// DoctorReport contains the results of a coherency check.
type DoctorReport struct {
	Findings []Finding
}

// HasErrors returns true if any finding has error severity.
func (r DoctorReport) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// HasWarnings returns true if any finding has warning severity.
func (r DoctorReport) HasWarnings() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityWarning {
			return true
		}
	}
	return false
}

// Doctor performs a read-only coherency check across database, kernel,
// and filesystem state.
func (m *Manager) Doctor(ctx context.Context) (DoctorReport, error) {
	var report DoctorReport

	// Phase 1: Gather state.

	dbPrograms, err := m.store.List(ctx)
	if err != nil {
		return report, fmt.Errorf("list programs: %w", err)
	}

	dbLinks, err := m.store.ListLinks(ctx)
	if err != nil {
		return report, fmt.Errorf("list links: %w", err)
	}

	dbDispatchers, err := m.store.ListDispatchers(ctx)
	if err != nil {
		return report, fmt.Errorf("list dispatchers: %w", err)
	}

	kernelProgIDs := make(map[uint32]bool)
	for kp, err := range m.kernel.Programs(ctx) {
		if err != nil {
			m.logger.Warn("error iterating kernel programs", "error", err)
			continue
		}
		kernelProgIDs[kp.ID] = true
	}

	kernelLinkIDs := make(map[uint32]bool)
	for kl, err := range m.kernel.Links(ctx) {
		if err != nil {
			m.logger.Warn("error iterating kernel links", "error", err)
			continue
		}
		kernelLinkIDs[kl.ID] = true
	}

	// Phase 2: DB vs kernel.

	for kernelID, prog := range dbPrograms {
		if !kernelProgIDs[kernelID] {
			report.Findings = append(report.Findings, Finding{
				Severity:    SeverityError,
				Category:    "db-vs-kernel",
				Description: fmt.Sprintf("Program %d in DB not found in kernel (pin: %s)", kernelID, prog.PinPath),
			})
		}
	}

	for _, link := range dbLinks {
		if bpfman.IsSyntheticLinkID(link.KernelLinkID) {
			continue
		}
		if !kernelLinkIDs[link.KernelLinkID] {
			report.Findings = append(report.Findings, Finding{
				Severity:    SeverityError,
				Category:    "db-vs-kernel",
				Description: fmt.Sprintf("Link %d in DB not found in kernel (program: %d)", link.KernelLinkID, link.KernelProgramID),
			})
		}
	}

	for _, d := range dbDispatchers {
		if !kernelProgIDs[d.KernelID] {
			report.Findings = append(report.Findings, Finding{
				Severity:    SeverityError,
				Category:    "db-vs-kernel",
				Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: program %d not found in kernel", d.Type, d.Nsid, d.Ifindex, d.KernelID),
			})
		}
		if d.Type == dispatcher.DispatcherTypeXDP && d.LinkID != 0 {
			if !kernelLinkIDs[d.LinkID] {
				report.Findings = append(report.Findings, Finding{
					Severity:    SeverityError,
					Category:    "db-vs-kernel",
					Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: link %d not found in kernel", d.Type, d.Nsid, d.Ifindex, d.LinkID),
				})
			}
		}
		if d.Type == dispatcher.DispatcherTypeTCIngress || d.Type == dispatcher.DispatcherTypeTCEgress {
			if d.Priority > 0 {
				parent := tcParent(d.Type)
				_, err := m.kernel.FindTCFilterHandle(int(d.Ifindex), parent, d.Priority)
				if err != nil {
					report.Findings = append(report.Findings, Finding{
						Severity:    SeverityError,
						Category:    "db-vs-kernel",
						Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: TC filter not found (priority %d): %v", d.Type, d.Nsid, d.Ifindex, d.Priority, err),
					})
				}
			}
		}
	}

	// Phase 3: DB vs filesystem.

	bpffsRoot := m.dirs.FS

	for kernelID, prog := range dbPrograms {
		if prog.PinPath != "" {
			if _, err := os.Stat(prog.PinPath); os.IsNotExist(err) {
				report.Findings = append(report.Findings, Finding{
					Severity:    SeverityWarning,
					Category:    "db-vs-fs",
					Description: fmt.Sprintf("Program %d: pin path missing: %s", kernelID, prog.PinPath),
				})
			}
		}
	}

	for _, link := range dbLinks {
		if bpfman.IsSyntheticLinkID(link.KernelLinkID) {
			continue
		}
		if link.PinPath != "" {
			if _, err := os.Stat(link.PinPath); os.IsNotExist(err) {
				report.Findings = append(report.Findings, Finding{
					Severity:    SeverityWarning,
					Category:    "db-vs-fs",
					Description: fmt.Sprintf("Link %d: pin path missing: %s", link.KernelLinkID, link.PinPath),
				})
			}
		}
	}

	for _, d := range dbDispatchers {
		revDir := dispatcher.DispatcherRevisionDir(bpffsRoot, d.Type, d.Nsid, d.Ifindex, d.Revision)
		progPin := dispatcher.DispatcherProgPath(revDir)
		if _, err := os.Stat(progPin); os.IsNotExist(err) {
			report.Findings = append(report.Findings, Finding{
				Severity:    SeverityWarning,
				Category:    "db-vs-fs",
				Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: prog pin missing: %s", d.Type, d.Nsid, d.Ifindex, progPin),
			})
		}
		if d.Type == dispatcher.DispatcherTypeXDP {
			linkPin := dispatcher.DispatcherLinkPath(bpffsRoot, d.Type, d.Nsid, d.Ifindex)
			if _, err := os.Stat(linkPin); os.IsNotExist(err) {
				report.Findings = append(report.Findings, Finding{
					Severity:    SeverityWarning,
					Category:    "db-vs-fs",
					Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: link pin missing: %s", d.Type, d.Nsid, d.Ifindex, linkPin),
				})
			}
		}
	}

	// Phase 4: Filesystem vs DB (orphans).

	// Build DB lookup sets for reverse checks.
	dbProgPinSet := make(map[string]bool)
	for _, prog := range dbPrograms {
		if prog.PinPath != "" {
			dbProgPinSet[prog.PinPath] = true
		}
	}

	dbMapProgIDSet := make(map[uint32]bool)
	for kernelID := range dbPrograms {
		dbMapProgIDSet[kernelID] = true
	}

	dbDispatcherSet := make(map[string]bool)
	for _, d := range dbDispatchers {
		key := fmt.Sprintf("%s/%d/%d", d.Type, d.Nsid, d.Ifindex)
		dbDispatcherSet[key] = true
	}

	// Scan prog_* pins in bpffs root.
	if entries, err := os.ReadDir(bpffsRoot); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, "prog_") {
				continue
			}
			pinPath := filepath.Join(bpffsRoot, name)
			if !dbProgPinSet[pinPath] {
				report.Findings = append(report.Findings, Finding{
					Severity:    SeverityWarning,
					Category:    "fs-vs-db",
					Description: fmt.Sprintf("Orphan program pin: %s", pinPath),
				})
			}
		}
	} else if !os.IsNotExist(err) {
		m.logger.Warn("error reading bpffs root", "path", bpffsRoot, "error", err)
	}

	// Scan link pin directories. The links directory contains
	// subdirectories named by program kernel ID, not link ID.
	if entries, err := os.ReadDir(m.dirs.FS_LINKS); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			var progID uint32
			if n, _ := fmt.Sscanf(name, "%d", &progID); n != 1 {
				continue
			}
			if !dbMapProgIDSet[progID] {
				report.Findings = append(report.Findings, Finding{
					Severity:    SeverityWarning,
					Category:    "fs-vs-db",
					Description: fmt.Sprintf("Orphan link pin directory: %s", filepath.Join(m.dirs.FS_LINKS, name)),
				})
			}
		}
	} else if !os.IsNotExist(err) {
		m.logger.Warn("error reading links directory", "path", m.dirs.FS_LINKS, "error", err)
	}

	// Scan map pin directories.
	if entries, err := os.ReadDir(m.dirs.FS_MAPS); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			var progID uint32
			if n, _ := fmt.Sscanf(name, "%d", &progID); n != 1 {
				continue
			}
			if !dbMapProgIDSet[progID] {
				report.Findings = append(report.Findings, Finding{
					Severity:    SeverityWarning,
					Category:    "fs-vs-db",
					Description: fmt.Sprintf("Orphan map pin directory: %s", filepath.Join(m.dirs.FS_MAPS, name)),
				})
			}
		}
	} else if !os.IsNotExist(err) {
		m.logger.Warn("error reading maps directory", "path", m.dirs.FS_MAPS, "error", err)
	}

	// Scan dispatcher type directories for orphan revision dirs.
	dispTypes := []dispatcher.DispatcherType{
		dispatcher.DispatcherTypeXDP,
		dispatcher.DispatcherTypeTCIngress,
		dispatcher.DispatcherTypeTCEgress,
	}

	for _, dt := range dispTypes {
		typeDir := dispatcher.TypeDir(bpffsRoot, dt)
		entries, err := os.ReadDir(typeDir)
		if err != nil {
			if !os.IsNotExist(err) {
				m.logger.Warn("error reading dispatcher directory", "path", typeDir, "error", err)
			}
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
			// Parse dispatcher_{nsid}_{ifindex}_{revision}
			var nsid uint64
			var ifindex, revision uint32
			n, _ := fmt.Sscanf(name, "dispatcher_%d_%d_%d", &nsid, &ifindex, &revision)
			if n != 3 {
				continue
			}
			key := fmt.Sprintf("%s/%d/%d", dt, nsid, ifindex)
			if !dbDispatcherSet[key] {
				report.Findings = append(report.Findings, Finding{
					Severity:    SeverityWarning,
					Category:    "fs-vs-db",
					Description: fmt.Sprintf("Orphan dispatcher directory: %s", filepath.Join(typeDir, name)),
				})
			}
		}
	}

	// Phase 5: Derived state consistency.

	for _, d := range dbDispatchers {
		dbCount, err := m.store.CountDispatcherLinks(ctx, d.KernelID)
		if err != nil {
			m.logger.Warn("error counting dispatcher links", "kernel_id", d.KernelID, "error", err)
			continue
		}

		revDir := dispatcher.DispatcherRevisionDir(bpffsRoot, d.Type, d.Nsid, d.Ifindex, d.Revision)
		fsCount := 0
		entries, err := os.ReadDir(revDir)
		if err != nil {
			if !os.IsNotExist(err) {
				m.logger.Warn("error reading revision directory", "path", revDir, "error", err)
			}
			continue
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "link_") {
				fsCount++
			}
		}

		if dbCount != fsCount {
			report.Findings = append(report.Findings, Finding{
				Severity:    SeverityWarning,
				Category:    "consistency",
				Description: fmt.Sprintf("Dispatcher %s nsid=%d ifindex=%d: DB link count (%d) != filesystem link count (%d)", d.Type, d.Nsid, d.Ifindex, dbCount, fsCount),
			})
		}
	}

	return report, nil
}

// tcParent returns the TC parent handle for ingress or egress.
func tcParent(dt dispatcher.DispatcherType) uint32 {
	if dt == dispatcher.DispatcherTypeTCIngress {
		return 0xFFFFFFF1 // TC_H_CLSACT | TC_H_MIN_INGRESS
	}
	return 0xFFFFFFF3 // TC_H_CLSACT | TC_H_MIN_EGRESS
}
