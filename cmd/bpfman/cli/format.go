package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"k8s.io/client-go/util/jsonpath"

	"github.com/frobware/go-bpfman/bpfman"
	"github.com/frobware/go-bpfman/managed"
	"github.com/frobware/go-bpfman/manager"
)

// FormatProgramInfo formats a ProgramInfo according to the specified output flags.
func FormatProgramInfo(info manager.ProgramInfo, flags *OutputFlags) (string, error) {
	switch flags.Format() {
	case OutputFormatJSON:
		return formatProgramInfoJSON(info)
	case OutputFormatTree:
		return formatProgramInfoTree(info), nil
	case OutputFormatTable:
		return formatProgramInfoTable(info), nil
	case OutputFormatJSONPath:
		return formatProgramInfoJSONPath(info, flags.JSONPathExpr())
	default:
		return formatProgramInfoTable(info), nil
	}
}

func formatProgramInfoJSON(info manager.ProgramInfo) (string, error) {
	output, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}
	return string(output) + "\n", nil
}

func formatProgramInfoJSONPath(info manager.ProgramInfo, expr string) (string, error) {
	// Parse the JSONPath expression
	jp := jsonpath.New("output")
	if err := jp.Parse(expr); err != nil {
		return "", fmt.Errorf("invalid jsonpath expression %q: %w", expr, err)
	}

	// Convert to generic interface for jsonpath
	jsonBytes, err := json.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("failed to marshal: %w", err)
	}

	var data interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return "", fmt.Errorf("failed to unmarshal: %w", err)
	}

	// Execute the JSONPath expression
	var buf bytes.Buffer
	if err := jp.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("jsonpath execution failed: %w", err)
	}

	return buf.String() + "\n", nil
}

func formatProgramInfoTree(info manager.ProgramInfo) string {
	var b strings.Builder

	// Header
	if info.Kernel != nil && info.Kernel.Program != nil {
		p := info.Kernel.Program
		fmt.Fprintf(&b, "Program %d: %s (%s)\n", p.ID, p.Name, p.ProgramType)
	}

	// Kernel state
	b.WriteString("├─ Kernel State\n")
	if info.Kernel != nil && info.Kernel.Program != nil {
		p := info.Kernel.Program
		fmt.Fprintf(&b, "│  ├─ tag:        %s\n", p.Tag)
		if !p.LoadedAt.IsZero() {
			fmt.Fprintf(&b, "│  ├─ loaded_at:  %s\n", p.LoadedAt.Format("2006-01-02T15:04:05Z"))
		}
		if p.BTFId != 0 {
			fmt.Fprintf(&b, "│  ├─ btf_id:     %d\n", p.BTFId)
		}
		if p.JitedSize != 0 {
			fmt.Fprintf(&b, "│  ├─ jited:      %d bytes\n", p.JitedSize)
		}
		if p.XlatedSize != 0 {
			fmt.Fprintf(&b, "│  ├─ xlated:     %d bytes\n", p.XlatedSize)
		}

		// Maps
		if len(info.Kernel.Maps) > 0 {
			fmt.Fprintf(&b, "│  ├─ Maps (%d)\n", len(info.Kernel.Maps))
			for i, m := range info.Kernel.Maps {
				prefix := "│  │  ├─"
				if i == len(info.Kernel.Maps)-1 {
					prefix = "│  │  └─"
				}
				fmt.Fprintf(&b, "%s [%d] %s (%s)\n", prefix, m.ID, m.Name, m.MapType)
				detailPrefix := "│  │  │ "
				if i == len(info.Kernel.Maps)-1 {
					detailPrefix = "│  │    "
				}
				fmt.Fprintf(&b, "%s        keys: %dB, values: %dB, max: %d\n",
					detailPrefix, m.KeySize, m.ValueSize, m.MaxEntries)
			}
		} else {
			b.WriteString("│  ├─ Maps: none\n")
		}

		// Links
		if len(info.Kernel.Links) > 0 {
			fmt.Fprintf(&b, "│  └─ Links (%d)\n", len(info.Kernel.Links))
			for i, l := range info.Kernel.Links {
				prefix := "│     ├─"
				if i == len(info.Kernel.Links)-1 {
					prefix = "│     └─"
				}
				fmt.Fprintf(&b, "%s [%d] %s\n", prefix, l.ID, l.LinkType)
			}
		} else {
			b.WriteString("│  └─ Links: none\n")
		}
	}

	// Managed state
	b.WriteString("│\n")
	b.WriteString("└─ Managed State\n")
	if info.Bpfman != nil && info.Bpfman.Program != nil {
		p := info.Bpfman.Program
		if !p.CreatedAt.IsZero() {
			fmt.Fprintf(&b, "   ├─ created:    %s\n", p.CreatedAt.Format("2006-01-02T15:04:05Z"))
		}
		fmt.Fprintf(&b, "   ├─ source:     %s\n", p.LoadSpec.ObjectPath)
		fmt.Fprintf(&b, "   └─ pin_path:   %s\n", p.LoadSpec.PinPath)
	}

	return b.String()
}

func formatProgramInfoTable(info manager.ProgramInfo) string {
	var b strings.Builder

	// Header line
	if info.Kernel != nil && info.Kernel.Program != nil {
		p := info.Kernel.Program
		fmt.Fprintf(&b, "PROGRAM  %d  %s  %s\n", p.ID, p.Name, p.ProgramType)
	}

	// Details
	if info.Bpfman != nil && info.Bpfman.Program != nil {
		p := info.Bpfman.Program
		if info.Kernel != nil && info.Kernel.Program != nil {
			fmt.Fprintf(&b, "  tag    %s\n", info.Kernel.Program.Tag)
		}
		fmt.Fprintf(&b, "  source %s\n", p.LoadSpec.ObjectPath)
		fmt.Fprintf(&b, "  pin    %s\n", p.LoadSpec.PinPath)
	}

	// Maps table
	b.WriteString("\n  MAPS\n")
	if info.Kernel != nil && len(info.Kernel.Maps) > 0 {
		fmt.Fprintf(&b, "  %-6s %-20s %-10s %-6s %-8s %s\n", "ID", "NAME", "TYPE", "KEYS", "VALUES", "MAX")
		for _, m := range info.Kernel.Maps {
			fmt.Fprintf(&b, "  %-6d %-20s %-10s %-6d %-8d %d\n",
				m.ID, m.Name, m.MapType, m.KeySize, m.ValueSize, m.MaxEntries)
		}
	} else {
		b.WriteString("  (none)\n")
	}

	// Links table - prefer bpfman stored info for attach details
	b.WriteString("\n  LINKS\n")
	if info.Bpfman != nil && len(info.Bpfman.Links) > 0 {
		fmt.Fprintf(&b, "  %-6s %-15s %s\n", "ID", "TYPE", "ATTACH")
		for _, l := range info.Bpfman.Links {
			attachInfo := formatAttachDetails(l.Details)
			fmt.Fprintf(&b, "  %-6d %-15s %s\n", l.Summary.KernelLinkID, l.Summary.LinkType, attachInfo)
		}
	} else if info.Kernel != nil && len(info.Kernel.Links) > 0 {
		// Fallback to kernel info if no bpfman links
		fmt.Fprintf(&b, "  %-6s %-15s %s\n", "ID", "TYPE", "ATTACH")
		for _, l := range info.Kernel.Links {
			fmt.Fprintf(&b, "  %-6d %-15s %s\n", l.ID, l.LinkType, l.AttachType)
		}
	} else {
		b.WriteString("  (none)\n")
	}

	return b.String()
}

// FormatProgramList formats a list of ManagedProgram according to the specified output flags.
func FormatProgramList(programs []manager.ManagedProgram, flags *OutputFlags) (string, error) {
	switch flags.Format() {
	case OutputFormatJSON:
		return formatProgramListJSON(programs)
	case OutputFormatTable:
		return formatProgramListTable(programs), nil
	case OutputFormatJSONPath:
		return formatProgramListJSONPath(programs, flags.JSONPathExpr())
	default:
		return formatProgramListTable(programs), nil
	}
}

func formatProgramListJSON(programs []manager.ManagedProgram) (string, error) {
	output, err := json.MarshalIndent(programs, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}
	return string(output) + "\n", nil
}

func formatProgramListJSONPath(programs []manager.ManagedProgram, expr string) (string, error) {
	jp := jsonpath.New("output")
	if err := jp.Parse(expr); err != nil {
		return "", fmt.Errorf("invalid jsonpath expression %q: %w", expr, err)
	}

	jsonBytes, err := json.Marshal(programs)
	if err != nil {
		return "", fmt.Errorf("failed to marshal: %w", err)
	}

	var data interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return "", fmt.Errorf("failed to unmarshal: %w", err)
	}

	var buf bytes.Buffer
	if err := jp.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("jsonpath execution failed: %w", err)
	}

	return buf.String() + "\n", nil
}

func formatProgramListTable(programs []manager.ManagedProgram) string {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "KERNEL ID\tTYPE\tNAME\tSOURCE")

	for _, p := range programs {
		id := p.KernelProgram.ID
		name := p.KernelProgram.Name
		progType := p.KernelProgram.ProgramType
		source := ""

		// Prefer full name from metadata over kernel-truncated name
		if p.Metadata != nil {
			if p.Metadata.LoadSpec.ProgramName != "" {
				name = p.Metadata.LoadSpec.ProgramName
			}
			source = p.Metadata.LoadSpec.ObjectPath
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", id, progType, name, source)
	}

	w.Flush()
	return b.String()
}

// formatAttachDetails formats type-specific link details for display.
func formatAttachDetails(details managed.LinkDetails) string {
	if details == nil {
		return ""
	}
	switch d := details.(type) {
	case managed.TracepointDetails:
		return d.Group + "/" + d.Name
	case managed.KprobeDetails:
		if d.Retprobe {
			return "kretprobe:" + d.FnName
		}
		return d.FnName
	case managed.UprobeDetails:
		if d.Retprobe {
			return fmt.Sprintf("uretprobe:%s:%s", d.Target, d.FnName)
		}
		return fmt.Sprintf("%s:%s", d.Target, d.FnName)
	case managed.FentryDetails:
		return d.FnName
	case managed.FexitDetails:
		return d.FnName
	case managed.XDPDetails:
		return fmt.Sprintf("%s (ifindex=%d, pos=%d)", d.Interface, d.Ifindex, d.Position)
	case managed.TCDetails:
		return fmt.Sprintf("%s/%s (ifindex=%d, pos=%d)", d.Interface, d.Direction, d.Ifindex, d.Position)
	case managed.TCXDetails:
		return fmt.Sprintf("%s/%s (ifindex=%d)", d.Interface, d.Direction, d.Ifindex)
	default:
		return ""
	}
}

// FormatLoadedPrograms formats a list of loaded ManagedProgram according to the specified output flags.
func FormatLoadedPrograms(programs []bpfman.ManagedProgram, flags *OutputFlags) (string, error) {
	switch flags.Format() {
	case OutputFormatJSON:
		return formatLoadedProgramsJSON(programs)
	case OutputFormatTable:
		return formatLoadedProgramsTable(programs), nil
	case OutputFormatJSONPath:
		return formatLoadedProgramsJSONPath(programs, flags.JSONPathExpr())
	default:
		return formatLoadedProgramsTable(programs), nil
	}
}

func formatLoadedProgramsJSON(programs []bpfman.ManagedProgram) (string, error) {
	output, err := json.MarshalIndent(programs, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}
	return string(output) + "\n", nil
}

func formatLoadedProgramsJSONPath(programs []bpfman.ManagedProgram, expr string) (string, error) {
	jp := jsonpath.New("output")
	if err := jp.Parse(expr); err != nil {
		return "", fmt.Errorf("invalid jsonpath expression %q: %w", expr, err)
	}

	jsonBytes, err := json.Marshal(programs)
	if err != nil {
		return "", fmt.Errorf("failed to marshal: %w", err)
	}

	var data interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return "", fmt.Errorf("failed to unmarshal: %w", err)
	}

	var buf bytes.Buffer
	if err := jp.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("jsonpath execution failed: %w", err)
	}

	return buf.String() + "\n", nil
}

func formatLoadedProgramsTable(programs []bpfman.ManagedProgram) string {
	var b strings.Builder

	for i, p := range programs {
		if i > 0 {
			b.WriteString("\n")
		}

		// Bpfman State section
		b.WriteString(" Bpfman State\n")
		bw := tabwriter.NewWriter(&b, 0, 0, 1, ' ', 0)
		fmt.Fprintf(bw, " BPF Function:\t%s\n", p.Managed.Name())
		fmt.Fprintf(bw, " Program Type:\t%s\n", p.Managed.ProgramType())
		fmt.Fprintf(bw, " Path:\t%s\n", p.Managed.ObjectPath())
		fmt.Fprintf(bw, " Global:\t%s\n", "TODO / FIX ME")
		fmt.Fprintf(bw, " Metadata:\t%s\n", "TODO / FIX ME")
		fmt.Fprintf(bw, " Map Pin Path:\t%s\n", p.Managed.PinDir())
		fmt.Fprintf(bw, " Map Owner ID:\t%s\n", "TODO / FIX ME")
		if mapIDs := p.Kernel.MapIDs(); len(mapIDs) > 0 {
			fmt.Fprintf(bw, " Owned Maps:\t%v\n", mapIDs)
		} else {
			fmt.Fprintf(bw, " Owned Maps:\t%s\n", "None")
		}
		fmt.Fprintf(bw, " Links:\t%s\n", "TODO / FIX ME")
		bw.Flush()

		b.WriteString("\n")

		// Kernel State section
		b.WriteString(" Kernel State\n")
		kw := tabwriter.NewWriter(&b, 0, 0, 1, ' ', 0)
		fmt.Fprintf(kw, " Program ID:\t%d\n", p.Kernel.ID())
		fmt.Fprintf(kw, " BPF Function:\t%s\n", p.Kernel.Name())
		fmt.Fprintf(kw, " Kernel Type:\t%s\n", p.Kernel.Type())
		if !p.Kernel.LoadedAt().IsZero() {
			fmt.Fprintf(kw, " Loaded At:\t%s\n", p.Kernel.LoadedAt().Format("2006-01-02T15:04:05-0700"))
		}
		fmt.Fprintf(kw, " Tag:\t%s\n", p.Kernel.Tag())
		fmt.Fprintf(kw, " GPL Compatible:\t%s\n", "TODO / FIX ME")
		if mapIDs := p.Kernel.MapIDs(); len(mapIDs) > 0 {
			fmt.Fprintf(kw, " Map IDs:\t%v\n", mapIDs)
		}
		if btfID := p.Kernel.BTFId(); btfID != 0 {
			fmt.Fprintf(kw, " BTF ID:\t%d\n", btfID)
		}
		fmt.Fprintf(kw, " Size Translated (bytes):\t%d\n", p.Kernel.BytesXlated())
		fmt.Fprintf(kw, " JITted:\t%t\n", p.Kernel.BytesJited() > 0)
		fmt.Fprintf(kw, " Size JITted:\t%d\n", p.Kernel.BytesJited())
		if memLocked := p.Kernel.MemoryLocked(); memLocked != 0 {
			fmt.Fprintf(kw, " Kernel Allocated Memory (bytes):\t%d\n", memLocked)
		}
		fmt.Fprintf(kw, " Verified Instruction Count:\t%d\n", p.Kernel.VerifiedInstructions())
		kw.Flush()
	}

	return b.String()
}
