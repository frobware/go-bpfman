package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/frobware/go-bpfman/pkg/bpfman"
)

func TestParseProgramSpec_ValidInputs(t *testing.T) {
	tests := []struct {
		input        string
		expectedType bpfman.ProgramType
		expectedName string
	}{
		{"xdp:my_prog", bpfman.ProgramTypeXDP, "my_prog"},
		{"tc:tc_ingress", bpfman.ProgramTypeTC, "tc_ingress"},
		{"tcx:tcx_prog", bpfman.ProgramTypeTCX, "tcx_prog"},
		{"tracepoint:count_switches", bpfman.ProgramTypeTracepoint, "count_switches"},
		{"kprobe:probe_func", bpfman.ProgramTypeKprobe, "probe_func"},
		{"kretprobe:ret_probe", bpfman.ProgramTypeKretprobe, "ret_probe"},
		{"uprobe:user_probe", bpfman.ProgramTypeUprobe, "user_probe"},
		{"uretprobe:user_ret", bpfman.ProgramTypeUretprobe, "user_ret"},
		{"fentry:entry_func", bpfman.ProgramTypeFentry, "entry_func"},
		{"fexit:exit_func", bpfman.ProgramTypeFexit, "exit_func"},
		// With whitespace
		{"  xdp:my_prog  ", bpfman.ProgramTypeXDP, "my_prog"},
		{"xdp:  my_prog", bpfman.ProgramTypeXDP, "my_prog"},
		{"  xdp  :  my_prog  ", bpfman.ProgramTypeXDP, "my_prog"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			spec, err := ParseProgramSpec(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedType, spec.Type)
			assert.Equal(t, tt.expectedName, spec.Name)
		})
	}
}

func TestParseProgramSpec_InvalidInputs(t *testing.T) {
	tests := []struct {
		input       string
		errContains string
	}{
		{"", "cannot be empty"},
		{"  ", "cannot be empty"},
		{"xdp", "expected TYPE:NAME format"},
		{"my_prog", "expected TYPE:NAME format"},
		{":my_prog", "expected TYPE:NAME format"},
		{"xdp:", "name cannot be empty"},
		{":", "expected TYPE:NAME format"},
		{"invalid:my_prog", "unknown type \"invalid\""},
		{"INVALID:my_prog", "unknown type \"INVALID\""},
		{"XDP:my_prog", "unknown type \"XDP\""}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := ParseProgramSpec(tt.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}
