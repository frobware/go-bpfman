package logging

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Level
		wantErr bool
	}{
		{name: "trace", input: "trace", want: LevelTrace},
		{name: "debug", input: "debug", want: LevelDebug},
		{name: "info", input: "info", want: LevelInfo},
		{name: "warn", input: "warn", want: LevelWarn},
		{name: "warning", input: "warning", want: LevelWarn},
		{name: "error", input: "error", want: LevelError},
		{name: "err", input: "err", want: LevelError},
		{name: "uppercase", input: "DEBUG", want: LevelDebug},
		{name: "mixed case", input: "Info", want: LevelInfo},
		{name: "with spaces", input: "  warn  ", want: LevelWarn},
		{name: "invalid", input: "invalid", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLevel(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLevel_ToSlog(t *testing.T) {
	tests := []struct {
		level Level
		want  slog.Level
	}{
		{LevelTrace, slog.Level(-8)},
		{LevelDebug, slog.LevelDebug},
		{LevelInfo, slog.LevelInfo},
		{LevelWarn, slog.LevelWarn},
		{LevelError, slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			assert.Equal(t, tt.want, tt.level.ToSlog())
		})
	}
}

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{LevelTrace, "trace"},
		{LevelDebug, "debug"},
		{LevelInfo, "info"},
		{LevelWarn, "warn"},
		{LevelError, "error"},
		{Level(99), "Level(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.level.String())
		})
	}
}
