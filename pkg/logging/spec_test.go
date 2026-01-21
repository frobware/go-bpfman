package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSpec(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantBase   Level
		wantComps  map[string]Level
		wantErr    bool
		errContain string
	}{
		{
			name:     "empty string defaults to info",
			input:    "",
			wantBase: LevelInfo,
		},
		{
			name:     "base level only",
			input:    "debug",
			wantBase: LevelDebug,
		},
		{
			name:      "single component override",
			input:     "info,manager=debug",
			wantBase:  LevelInfo,
			wantComps: map[string]Level{"manager": LevelDebug},
		},
		{
			name:      "multiple component overrides",
			input:     "warn,manager=debug,store=trace",
			wantBase:  LevelWarn,
			wantComps: map[string]Level{"manager": LevelDebug, "store": LevelTrace},
		},
		{
			name:      "with whitespace",
			input:     "  info , manager = debug , store = trace  ",
			wantBase:  LevelInfo,
			wantComps: map[string]Level{"manager": LevelDebug, "store": LevelTrace},
		},
		{
			name:      "component only (no base level specified)",
			input:     "manager=debug",
			wantBase:  LevelInfo,
			wantComps: map[string]Level{"manager": LevelDebug},
		},
		{
			name:       "invalid base level",
			input:      "invalid",
			wantErr:    true,
			errContain: "unknown log level",
		},
		{
			name:       "invalid component level",
			input:      "info,manager=invalid",
			wantErr:    true,
			errContain: "invalid level for component",
		},
		{
			name:       "base level not first",
			input:      "manager=debug,info",
			wantErr:    true,
			errContain: "must be first",
		},
		{
			name:       "empty component name",
			input:      "info,=debug",
			wantErr:    true,
			errContain: "empty component name",
		},
		{
			name:      "empty parts are skipped",
			input:     "info,,manager=debug,",
			wantBase:  LevelInfo,
			wantComps: map[string]Level{"manager": LevelDebug},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSpec(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantBase, got.BaseLevel)

			if tt.wantComps == nil {
				assert.Empty(t, got.Components)
			} else {
				assert.Equal(t, tt.wantComps, got.Components)
			}
		})
	}
}

func TestSpec_LevelFor(t *testing.T) {
	spec := Spec{
		BaseLevel: LevelWarn,
		Components: map[string]Level{
			"manager": LevelDebug,
			"store":   LevelTrace,
		},
	}

	tests := []struct {
		component string
		want      Level
	}{
		{"manager", LevelDebug},
		{"store", LevelTrace},
		{"server", LevelWarn},  // falls back to base
		{"", LevelWarn},        // empty falls back to base
		{"unknown", LevelWarn}, // unknown falls back to base
	}

	for _, tt := range tests {
		t.Run(tt.component, func(t *testing.T) {
			assert.Equal(t, tt.want, spec.LevelFor(tt.component))
		})
	}
}

func TestSpec_String(t *testing.T) {
	spec := Spec{
		BaseLevel:  LevelInfo,
		Components: map[string]Level{},
	}
	assert.Equal(t, "info", spec.String())

	// With components - order may vary due to map iteration
	spec.Components["manager"] = LevelDebug
	s := spec.String()
	assert.Contains(t, s, "info")
	assert.Contains(t, s, "manager=debug")
}
