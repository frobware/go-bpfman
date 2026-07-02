package cliformat

import (
	"strings"
	"testing"

	"github.com/bpfman/bpfman"
	"github.com/bpfman/bpfman/kernel"
)

// The Links and Maps sub-sections render after the scalar status fields,
// not wedged among them in alphabetical position.
func TestFormatProgramTable_SubsectionsAfterScalars(t *testing.T) {
	t.Parallel()

	prog := bpfman.Program{
		Record: bpfman.ProgramRecord{ProgramID: 42, Meta: bpfman.ProgramMeta{Name: "p"}},
		Status: bpfman.ProgramStatus{
			Kernel: &kernel.Program{},
			Links:  []bpfman.Link{{Record: bpfman.LinkRecord{ID: 8, Kind: bpfman.LinkKindXDP}}},
			Maps:   []bpfman.MapStatus{{Map: kernel.Map{}}},
		},
	}

	out := formatProgramTable(prog)
	instructions := strings.Index(out, "Instructions:")
	links := strings.Index(out, "Links:")
	maps := strings.Index(out, "Maps:")
	if instructions < 0 || links < 0 || maps < 0 {
		t.Fatalf("missing expected sections in:\n%s", out)
	}
	if !(instructions < links && links < maps) {
		t.Errorf("want a scalar (Instructions) before Links before Maps; got offsets %d, %d, %d:\n%s", instructions, links, maps, out)
	}
}

// The Spec Path row shows the caller's load operand when the record
// preserved one, falling back to bpfman's stored bytecode copy for
// image loads and records that predate source-path recording. The
// stored copy always remains visible as the Status Bytecode row.
func TestFormatProgramTable_PathPrefersSourcePath(t *testing.T) {
	t.Parallel()

	withSource := bpfman.Program{
		Record: bpfman.ProgramRecord{
			ProgramID: 42,
			Load:      bpfman.LoadSpec{}.WithObjectPath("/run/bpfman/programs/42/bytecode.o").WithSourcePath("e2e/testdata/bpf/xdp_pass.bpf.o"),
		},
	}
	if out := formatProgramTable(withSource); !strings.Contains(out, "Path:           e2e/testdata/bpf/xdp_pass.bpf.o\n") {
		t.Errorf("Path row should show the source path, got:\n%s", out)
	}

	withoutSource := bpfman.Program{
		Record: bpfman.ProgramRecord{
			ProgramID: 42,
			Load:      bpfman.LoadSpec{}.WithObjectPath("/run/bpfman/programs/42/bytecode.o"),
		},
	}
	if out := formatProgramTable(withoutSource); !strings.Contains(out, "Path:           /run/bpfman/programs/42/bytecode.o\n") {
		t.Errorf("Path row should fall back to the object path, got:\n%s", out)
	}
}

