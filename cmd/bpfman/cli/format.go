package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"k8s.io/client-go/util/jsonpath"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/manager"
)

// toKernelType converts a bpfman program type to its underlying kernel type.
// TCX and TC both use the kernel's sched_cls type.
// Fentry and fexit use the kernel's tracing type.
func toKernelType(t bpfman.ProgramType) string {
	switch t {
	case bpfman.ProgramTypeTCX:
		return "tc"
	case bpfman.ProgramTypeFentry, bpfman.ProgramTypeFexit:
		return "tracing"
	default:
		return t.String()
	}
}

// executeJSONPath parses and executes a JSONPath expression against the given data.
// The data is marshalled to JSON and back to ensure consistent field access.
func executeJSONPath(data any, expr string) (string, error) {
	jp := jsonpath.New("output")
	if err := jp.Parse(expr); err != nil {
		return "", fmt.Errorf("invalid jsonpath expression %q: %w", expr, err)
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal: %w", err)
	}

	var generic any
	if err := json.Unmarshal(jsonBytes, &generic); err != nil {
		return "", fmt.Errorf("failed to unmarshal: %w", err)
	}

	var buf bytes.Buffer
	if err := jp.Execute(&buf, generic); err != nil {
		return "", fmt.Errorf("jsonpath execution failed: %w", err)
	}

	return buf.String() + "\n", nil
}

// FormatProgramInfo formats a ProgramInfo according to the specified output flags.
func FormatProgramInfo(info manager.ProgramInfo, flags *OutputFlags) (string, error) {
	format, err := flags.Format()
	if err != nil {
		return "", err
	}
	switch format {
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
	return executeJSONPath(info, expr)
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
			fmt.Fprintf(&b, "│  ├─ loaded_at:  %s\n", p.LoadedAt.Format(time.RFC3339))
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
			fmt.Fprintf(&b, "   ├─ created:    %s\n", p.CreatedAt.Format(time.RFC3339))
		}
		fmt.Fprintf(&b, "   ├─ source:     %s\n", p.ObjectPath)
		fmt.Fprintf(&b, "   └─ pin_path:   %s\n", p.PinPath)
	}

	return b.String()
}

func formatProgramInfoTable(info manager.ProgramInfo) string {
	var b strings.Builder

	// Bpfman State section (only if managed by bpfman)
	if info.Bpfman != nil && info.Bpfman.Program != nil {
		p := info.Bpfman.Program
		b.WriteString(" Bpfman State\n")
		bw := tabwriter.NewWriter(&b, 0, 0, 1, ' ', 0)
		fmt.Fprintf(bw, " BPF Function:\t%s\n", p.ProgramName)
		fmt.Fprintf(bw, " Program Type:\t%s\n", p.ProgramType)
		fmt.Fprintf(bw, " Path:\t%s\n", p.ObjectPath)
		fmt.Fprintf(bw, " Global:\tNone\n")
		fmt.Fprintf(bw, " Metadata:\tNone\n")
		fmt.Fprintf(bw, " Map Pin Path:\t%s\n", p.PinPath)
		fmt.Fprintf(bw, " Map Owner ID:\tNone\n")
		fmt.Fprintf(bw, " Maps Used By:\tNone\n")

		// Links
		if len(info.Bpfman.Links) > 0 {
			for i, l := range info.Bpfman.Links {
				var linkStr string
				if l.Details != nil {
					attachInfo := formatAttachDetails(l.Details)
					linkStr = fmt.Sprintf("%d (%s)", l.Summary.KernelLinkID, attachInfo)
				} else {
					// No details available, just show the link ID
					linkStr = fmt.Sprintf("%d", l.Summary.KernelLinkID)
				}
				if i == 0 {
					fmt.Fprintf(bw, " Links:\t%s\n", linkStr)
				} else {
					fmt.Fprintf(bw, " \t%s\n", linkStr)
				}
			}
		} else if info.Kernel != nil && len(info.Kernel.Links) > 0 {
			for i, l := range info.Kernel.Links {
				linkStr := fmt.Sprintf("%d (%s)", l.ID, l.AttachType)
				if i == 0 {
					fmt.Fprintf(bw, " Links:\t%s\n", linkStr)
				} else {
					fmt.Fprintf(bw, " \t%s\n", linkStr)
				}
			}
		} else {
			fmt.Fprintf(bw, " Links:\tNone\n")
		}
		bw.Flush()
		b.WriteString("\n")
	}

	// Kernel State section
	if info.Kernel != nil && info.Kernel.Program != nil {
		p := info.Kernel.Program
		b.WriteString(" Kernel State\n")
		kw := tabwriter.NewWriter(&b, 0, 0, 1, ' ', 0)
		fmt.Fprintf(kw, " Program ID:\t%d\n", p.ID)
		fmt.Fprintf(kw, " BPF Function:\t%s\n", p.Name)

		// Convert program type to kernel type
		progType, _ := bpfman.ParseProgramType(p.ProgramType)
		fmt.Fprintf(kw, " Kernel Type:\t%s\n", toKernelType(progType))

		if !p.LoadedAt.IsZero() {
			fmt.Fprintf(kw, " Loaded At:\t%s\n", p.LoadedAt.Format(time.RFC3339))
		}
		fmt.Fprintf(kw, " Tag:\t%s\n", p.Tag)
		// FIXME: This code path uses manager.ProgramInfo.Kernel.Program which is
		// *kernel.Program struct - it doesn't have GPL info. The kernel.Program
		// struct is populated by querying the kernel directly, but the kernel
		// doesn't expose GPL compatibility after a program is loaded (it's only
		// checked at load time).
		//
		// In contrast, formatLoadedProgramsTable uses bpfman.ManagedProgram.Kernel
		// which is the KernelProgramInfo interface that HAS GPLCompatible() because
		// it's populated at load time from the ELF license section.
		//
		// To properly fix this would require:
		// 1. Adding GPLCompatible to bpfman.Program (database model)
		// 2. Storing it at load time
		// 3. Schema migration
		// 4. Retrieving it in manager.Get()
		fmt.Fprintf(kw, " GPL Compatible:\tFIXME\n")
		if len(p.MapIDs) > 0 {
			fmt.Fprintf(kw, " Map IDs:\t%v\n", p.MapIDs)
		}
		if p.BTFId != 0 {
			fmt.Fprintf(kw, " BTF ID:\t%d\n", p.BTFId)
		}
		fmt.Fprintf(kw, " Size Translated (bytes):\t%d\n", p.XlatedSize)
		fmt.Fprintf(kw, " JITted:\t%t\n", p.JitedSize > 0)
		fmt.Fprintf(kw, " Size JITted:\t%d\n", p.JitedSize)
		kw.Flush()
	}

	return b.String() + "\n"
}

// FormatProgramList formats a list of ManagedProgram according to the specified output flags.
func FormatProgramList(programs []manager.ManagedProgram, flags *OutputFlags) (string, error) {
	format, err := flags.Format()
	if err != nil {
		return "", err
	}
	switch format {
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
	return executeJSONPath(programs, expr)
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
			if p.Metadata.ProgramName != "" {
				name = p.Metadata.ProgramName
			}
			source = p.Metadata.ObjectPath
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", id, progType, name, source)
	}

	w.Flush()
	return b.String()
}

// FormatLinkList formats a list of LinkSummary according to the specified output flags.
func FormatLinkList(links []bpfman.LinkSummary, flags *OutputFlags) (string, error) {
	format, err := flags.Format()
	if err != nil {
		return "", err
	}
	switch format {
	case OutputFormatJSON:
		return formatLinkListJSON(links)
	case OutputFormatTable:
		return formatLinkListTable(links), nil
	case OutputFormatJSONPath:
		return formatLinkListJSONPath(links, flags.JSONPathExpr())
	default:
		return formatLinkListTable(links), nil
	}
}

func formatLinkListJSON(links []bpfman.LinkSummary) (string, error) {
	output, err := json.MarshalIndent(links, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}
	return string(output) + "\n", nil
}

func formatLinkListJSONPath(links []bpfman.LinkSummary, expr string) (string, error) {
	return executeJSONPath(links, expr)
}

func formatLinkListTable(links []bpfman.LinkSummary) string {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "LINK ID\tTYPE\tPROGRAM ID\tPIN PATH")

	for _, l := range links {
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\n", l.KernelLinkID, l.LinkType, l.KernelProgramID, l.PinPath)
	}

	w.Flush()
	return b.String()
}

// FormatLinkResult formats a link result (from attach command) according to
// the specified output flags. The bpfFunction is the name of the BPF function.
func FormatLinkResult(bpfFunction string, summary bpfman.LinkSummary, details bpfman.LinkDetails, flags *OutputFlags) (string, error) {
	format, err := flags.Format()
	if err != nil {
		return "", err
	}
	switch format {
	case OutputFormatJSON:
		return formatLinkResultJSON(bpfFunction, summary, details)
	case OutputFormatTable:
		return formatLinkResultTable(bpfFunction, summary, details), nil
	case OutputFormatJSONPath:
		return formatLinkResultJSONPath(bpfFunction, summary, details, flags.JSONPathExpr())
	default:
		return formatLinkResultTable(bpfFunction, summary, details), nil
	}
}

// linkResultData combines summary, details, and bpf function for JSON serialisation.
type linkResultData struct {
	BPFFunction string             `json:"bpf_function,omitempty"`
	Summary     bpfman.LinkSummary `json:"summary"`
	Details     bpfman.LinkDetails `json:"details"`
}

func formatLinkResultJSON(bpfFunction string, summary bpfman.LinkSummary, details bpfman.LinkDetails) (string, error) {
	data := linkResultData{
		BPFFunction: bpfFunction,
		Summary:     summary,
		Details:     details,
	}
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}
	return string(output) + "\n", nil
}

func formatLinkResultJSONPath(bpfFunction string, summary bpfman.LinkSummary, details bpfman.LinkDetails, expr string) (string, error) {
	data := linkResultData{
		BPFFunction: bpfFunction,
		Summary:     summary,
		Details:     details,
	}
	return executeJSONPath(data, expr)
}

func formatLinkResultTable(bpfFunction string, summary bpfman.LinkSummary, details bpfman.LinkDetails) string {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 1, ' ', 0)

	// Header
	fmt.Fprintln(w, " Bpfman State")

	// Common fields
	fmt.Fprintf(w, " BPF Function:\t%s\n", bpfFunction)
	fmt.Fprintf(w, " Link Type:\t%s\n", summary.LinkType)
	fmt.Fprintf(w, " Program ID:\t%d\n", summary.KernelProgramID)
	fmt.Fprintf(w, " Link ID:\t%d\n", summary.KernelLinkID)

	// Type-specific fields
	switch d := details.(type) {
	case bpfman.TCDetails:
		fmt.Fprintf(w, " Interface:\t%s\n", d.Interface)
		fmt.Fprintf(w, " Direction:\t%s\n", d.Direction)
		fmt.Fprintf(w, " Priority:\t%d\n", d.Priority)
		fmt.Fprintf(w, " Position:\t%d\n", d.Position)
		fmt.Fprintf(w, " Proceed On:\t%s\n", TCActionsToString(d.ProceedOn))
		if d.Netns != "" {
			fmt.Fprintf(w, " Network Namespace:\t%s\n", d.Netns)
		} else {
			fmt.Fprintf(w, " Network Namespace:\tNone\n")
		}
	case bpfman.XDPDetails:
		fmt.Fprintf(w, " Interface:\t%s\n", d.Interface)
		fmt.Fprintf(w, " Priority:\t%d\n", d.Priority)
		fmt.Fprintf(w, " Position:\t%d\n", d.Position)
		fmt.Fprintf(w, " Proceed On:\t%s\n", formatXDPProceedOn(d.ProceedOn))
		if d.Netns != "" {
			fmt.Fprintf(w, " Network Namespace:\t%s\n", d.Netns)
		} else {
			fmt.Fprintf(w, " Network Namespace:\tNone\n")
		}
	case bpfman.TracepointDetails:
		fmt.Fprintf(w, " Tracepoint:\t%s/%s\n", d.Group, d.Name)
	case bpfman.KprobeDetails:
		if d.Retprobe {
			fmt.Fprintf(w, " Attach Type:\tkretprobe\n")
		} else {
			fmt.Fprintf(w, " Attach Type:\tkprobe\n")
		}
		fmt.Fprintf(w, " Function:\t%s\n", d.FnName)
		if d.Offset != 0 {
			fmt.Fprintf(w, " Offset:\t%d\n", d.Offset)
		}
	case bpfman.TCXDetails:
		fmt.Fprintf(w, " Interface:\t%s\n", d.Interface)
		fmt.Fprintf(w, " Direction:\t%s\n", d.Direction)
		fmt.Fprintf(w, " Priority:\t%d\n", d.Priority)
		if d.Netns != "" {
			fmt.Fprintf(w, " Network Namespace:\t%s\n", d.Netns)
		} else {
			fmt.Fprintf(w, " Network Namespace:\tNone\n")
		}
	case bpfman.UprobeDetails:
		if d.Retprobe {
			fmt.Fprintf(w, " Attach Type:\turetprobe\n")
		} else {
			fmt.Fprintf(w, " Attach Type:\tuprobe\n")
		}
		fmt.Fprintf(w, " Target:\t%s\n", d.Target)
		fmt.Fprintf(w, " Function:\t%s\n", d.FnName)
		if d.Offset != 0 {
			fmt.Fprintf(w, " Offset:\t%d\n", d.Offset)
		}
		if d.PID != 0 {
			fmt.Fprintf(w, " PID:\t%d\n", d.PID)
		} else {
			fmt.Fprintf(w, " PID:\tNone\n")
		}
	case bpfman.FentryDetails:
		fmt.Fprintf(w, " Attach Function:\t%s\n", d.FnName)
	case bpfman.FexitDetails:
		fmt.Fprintf(w, " Attach Function:\t%s\n", d.FnName)
	}

	// Metadata placeholder
	fmt.Fprintf(w, " Metadata:\tNone\n")

	w.Flush()
	return b.String()
}

// LinkInfo combines summary and details for JSON output.
type LinkInfo struct {
	Summary any `json:"summary"`
	Details any `json:"details"`
}

// FormatLinkInfo formats link info for the get link command according to the specified output flags.
func FormatLinkInfo(bpfFunction string, summary bpfman.LinkSummary, details bpfman.LinkDetails, flags *OutputFlags) (string, error) {
	format, err := flags.Format()
	if err != nil {
		return "", err
	}
	switch format {
	case OutputFormatJSON:
		return formatLinkInfoJSON(bpfFunction, summary, details)
	case OutputFormatTable:
		return formatLinkInfoTable(bpfFunction, summary, details), nil
	case OutputFormatJSONPath:
		return formatLinkInfoJSONPath(bpfFunction, summary, details, flags.JSONPathExpr())
	default:
		return formatLinkInfoTable(bpfFunction, summary, details), nil
	}
}

func formatLinkInfoJSON(bpfFunction string, summary bpfman.LinkSummary, details bpfman.LinkDetails) (string, error) {
	data := struct {
		BPFFunction string             `json:"bpf_function,omitempty"`
		Summary     bpfman.LinkSummary `json:"summary"`
		Details     bpfman.LinkDetails `json:"details,omitempty"`
	}{
		BPFFunction: bpfFunction,
		Summary:     summary,
		Details:     details,
	}
	output, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}
	return string(output) + "\n", nil
}

func formatLinkInfoJSONPath(bpfFunction string, summary bpfman.LinkSummary, details bpfman.LinkDetails, expr string) (string, error) {
	data := struct {
		BPFFunction string             `json:"bpf_function,omitempty"`
		Summary     bpfman.LinkSummary `json:"summary"`
		Details     bpfman.LinkDetails `json:"details,omitempty"`
	}{
		BPFFunction: bpfFunction,
		Summary:     summary,
		Details:     details,
	}
	return executeJSONPath(data, expr)
}

func formatLinkInfoTable(bpfFunction string, summary bpfman.LinkSummary, details bpfman.LinkDetails) string {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 1, ' ', 0)

	// Bpfman State header
	fmt.Fprintln(w, " Bpfman State")

	// Common fields - use link type as program type display
	if bpfFunction != "" {
		fmt.Fprintf(w, " BPF Function:\t%s\n", bpfFunction)
	} else {
		fmt.Fprintf(w, " BPF Function:\tNone\n")
	}
	fmt.Fprintf(w, " Link Type:\t%s\n", summary.LinkType)
	fmt.Fprintf(w, " Program ID:\t%d\n", summary.KernelProgramID)
	fmt.Fprintf(w, " Link ID:\t%d\n", summary.KernelLinkID)

	// Type-specific fields
	switch d := details.(type) {
	case bpfman.TracepointDetails:
		fmt.Fprintf(w, " Tracepoint:\t%s/%s\n", d.Group, d.Name)
	case bpfman.KprobeDetails:
		fmt.Fprintf(w, " Attach Function:\t%s\n", d.FnName)
		fmt.Fprintf(w, " Offset:\t%d\n", d.Offset)
		fmt.Fprintf(w, " Container PID:\tNone\n")
	case bpfman.UprobeDetails:
		fmt.Fprintf(w, " Target:\t%s\n", d.Target)
		if d.FnName != "" {
			fmt.Fprintf(w, " Attach Function:\t%s\n", d.FnName)
		} else {
			fmt.Fprintf(w, " Attach Function:\tNone\n")
		}
		fmt.Fprintf(w, " Offset:\t%d\n", d.Offset)
		if d.PID != 0 {
			fmt.Fprintf(w, " PID:\t%d\n", d.PID)
		} else {
			fmt.Fprintf(w, " PID:\tNone\n")
		}
		fmt.Fprintf(w, " Container PID:\tNone\n")
	case bpfman.FentryDetails:
		fmt.Fprintf(w, " Attach Function:\t%s\n", d.FnName)
	case bpfman.FexitDetails:
		fmt.Fprintf(w, " Attach Function:\t%s\n", d.FnName)
	case bpfman.TCDetails:
		fmt.Fprintf(w, " Interface:\t%s\n", d.Interface)
		fmt.Fprintf(w, " Direction:\t%s\n", d.Direction)
		fmt.Fprintf(w, " Priority:\t%d\n", d.Priority)
		if d.Position != 0 {
			fmt.Fprintf(w, " Position:\t%d\n", d.Position)
		} else {
			fmt.Fprintf(w, " Position:\tNone\n")
		}
		fmt.Fprintf(w, " Proceed On:\t%s\n", TCActionsToString(d.ProceedOn))
		if d.Netns != "" {
			fmt.Fprintf(w, " Network Namespace:\t%s\n", d.Netns)
		} else {
			fmt.Fprintf(w, " Network Namespace:\tNone\n")
		}
	case bpfman.TCXDetails:
		fmt.Fprintf(w, " Interface:\t%s\n", d.Interface)
		fmt.Fprintf(w, " Direction:\t%s\n", d.Direction)
		fmt.Fprintf(w, " Priority:\t%d\n", d.Priority)
		fmt.Fprintf(w, " Position:\tNone\n") // TCX uses native kernel multi-prog, no position tracking
		if d.Netns != "" {
			fmt.Fprintf(w, " Network Namespace:\t%s\n", d.Netns)
		} else {
			fmt.Fprintf(w, " Network Namespace:\tNone\n")
		}
	case bpfman.XDPDetails:
		fmt.Fprintf(w, " Interface:\t%s\n", d.Interface)
		fmt.Fprintf(w, " Priority:\t%d\n", d.Priority)
		if d.Position != 0 {
			fmt.Fprintf(w, " Position:\t%d\n", d.Position)
		} else {
			fmt.Fprintf(w, " Position:\tNone\n")
		}
		fmt.Fprintf(w, " Proceed On:\t%s\n", formatXDPProceedOn(d.ProceedOn))
		if d.Netns != "" {
			fmt.Fprintf(w, " Network Namespace:\t%s\n", d.Netns)
		} else {
			fmt.Fprintf(w, " Network Namespace:\tNone\n")
		}
	}

	// Metadata
	fmt.Fprintf(w, " Metadata:\tNone\n")

	w.Flush()
	return b.String() + "\n"
}

// formatXDPProceedOn converts XDP proceed-on values to a human-readable string.
func formatXDPProceedOn(actions []int32) string {
	if len(actions) == 0 {
		return "None"
	}
	// XDP actions: 0=aborted, 1=drop, 2=pass, 3=tx, 4=redirect, 31=dispatcher_return
	xdpNames := map[int32]string{
		0:  "aborted",
		1:  "drop",
		2:  "pass",
		3:  "tx",
		4:  "redirect",
		31: "dispatcher_return",
	}
	names := make([]string, len(actions))
	for i, a := range actions {
		if name, ok := xdpNames[a]; ok {
			names[i] = name
		} else {
			names[i] = fmt.Sprintf("unknown(%d)", a)
		}
	}
	return strings.Join(names, ", ")
}

// formatAttachDetails formats type-specific link details for display.
func formatAttachDetails(details bpfman.LinkDetails) string {
	if details == nil {
		return ""
	}
	switch d := details.(type) {
	case bpfman.TracepointDetails:
		return d.Group + "/" + d.Name
	case bpfman.KprobeDetails:
		if d.Retprobe {
			return "kretprobe:" + d.FnName
		}
		return d.FnName
	case bpfman.UprobeDetails:
		if d.Retprobe {
			return fmt.Sprintf("uretprobe:%s:%s", d.Target, d.FnName)
		}
		return fmt.Sprintf("%s:%s", d.Target, d.FnName)
	case bpfman.FentryDetails:
		return d.FnName
	case bpfman.FexitDetails:
		return d.FnName
	case bpfman.XDPDetails:
		return fmt.Sprintf("%s (ifindex=%d, pos=%d)", d.Interface, d.Ifindex, d.Position)
	case bpfman.TCDetails:
		return fmt.Sprintf("%s/%s (ifindex=%d, pos=%d)", d.Interface, d.Direction, d.Ifindex, d.Position)
	case bpfman.TCXDetails:
		return fmt.Sprintf("%s/%s (ifindex=%d)", d.Interface, d.Direction, d.Ifindex)
	default:
		return ""
	}
}

// FormatLoadedPrograms formats a list of loaded ManagedProgram according to the specified output flags.
func FormatLoadedPrograms(programs []bpfman.ManagedProgram, flags *OutputFlags) (string, error) {
	format, err := flags.Format()
	if err != nil {
		return "", err
	}
	switch format {
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
	return executeJSONPath(programs, expr)
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
		fmt.Fprintf(bw, " BPF Function:\t%s\n", p.Managed.Name)
		fmt.Fprintf(bw, " Program Type:\t%s\n", p.Managed.Type)
		fmt.Fprintf(bw, " Path:\t%s\n", p.Managed.ObjectPath)
		fmt.Fprintf(bw, " Global:\t%s\n", "TODO / FIX ME")
		fmt.Fprintf(bw, " Metadata:\t%s\n", "TODO / FIX ME")
		fmt.Fprintf(bw, " Map Pin Path:\t%s\n", p.Managed.PinDir)
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
		fmt.Fprintf(kw, " Kernel Type:\t%s\n", toKernelType(p.Kernel.Type()))
		if !p.Kernel.LoadedAt().IsZero() {
			fmt.Fprintf(kw, " Loaded At:\t%s\n", p.Kernel.LoadedAt().Format(time.RFC3339))
		}
		fmt.Fprintf(kw, " Tag:\t%s\n", p.Kernel.Tag())
		fmt.Fprintf(kw, " GPL Compatible:\t%t\n", p.Kernel.GPLCompatible())
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
