package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/client-go/util/jsonpath"

	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
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
		fmt.Fprintf(&b, "   ├─ uuid:       %s\n", p.UUID)
		fmt.Fprintf(&b, "   ├─ state:      %s\n", p.State)
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
		state := "unknown"
		if info.Bpfman != nil && info.Bpfman.Program != nil {
			state = string(info.Bpfman.Program.State)
		}
		fmt.Fprintf(&b, "PROGRAM  %d  %s  %s  %s\n", p.ID, p.Name, p.ProgramType, state)
	}

	// Details
	if info.Bpfman != nil && info.Bpfman.Program != nil {
		p := info.Bpfman.Program
		fmt.Fprintf(&b, "  uuid   %s\n", p.UUID)
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
