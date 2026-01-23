package cli_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/cmd/bpfman/cli"
)

func TestParseProgramSpec_ValidInputs(t *testing.T) {
	tests := []struct {
		input              string
		expectedType       bpfman.ProgramType
		expectedName       string
		expectedAttachFunc string
	}{
		{"xdp:my_prog", bpfman.ProgramTypeXDP, "my_prog", ""},
		{"tc:tc_ingress", bpfman.ProgramTypeTC, "tc_ingress", ""},
		{"tcx:tcx_prog", bpfman.ProgramTypeTCX, "tcx_prog", ""},
		{"tracepoint:count_switches", bpfman.ProgramTypeTracepoint, "count_switches", ""},
		{"kprobe:probe_func", bpfman.ProgramTypeKprobe, "probe_func", ""},
		{"kretprobe:ret_probe", bpfman.ProgramTypeKretprobe, "ret_probe", ""},
		{"uprobe:user_probe", bpfman.ProgramTypeUprobe, "user_probe", ""},
		{"uretprobe:user_ret", bpfman.ProgramTypeUretprobe, "user_ret", ""},
		// fentry/fexit require attach function (TYPE:NAME:ATTACH_FUNC)
		{"fentry:entry_func:do_unlinkat", bpfman.ProgramTypeFentry, "entry_func", "do_unlinkat"},
		{"fexit:exit_func:do_unlinkat", bpfman.ProgramTypeFexit, "exit_func", "do_unlinkat"},
		// With whitespace
		{"  xdp:my_prog  ", bpfman.ProgramTypeXDP, "my_prog", ""},
		{"xdp:  my_prog", bpfman.ProgramTypeXDP, "my_prog", ""},
		{"  xdp  :  my_prog  ", bpfman.ProgramTypeXDP, "my_prog", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			spec, err := cli.ParseProgramSpec(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedType, spec.Type)
			assert.Equal(t, tt.expectedName, spec.Name)
			assert.Equal(t, tt.expectedAttachFunc, spec.AttachFunc)
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
		{":my_prog", "type cannot be empty"},
		{"xdp:", "name cannot be empty"},
		{":", "type cannot be empty"},
		{"invalid:my_prog", "unknown type \"invalid\""},
		{"INVALID:my_prog", "unknown type \"INVALID\""},
		{"XDP:my_prog", "unknown type \"XDP\""}, // case sensitive
		// fentry/fexit require attach function
		{"fentry:entry_func", "fentry requires attach function"},
		{"fexit:exit_func", "fexit requires attach function"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := cli.ParseProgramSpec(tt.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}
