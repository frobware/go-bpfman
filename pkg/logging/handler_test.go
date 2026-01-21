package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilteringHandler_Enabled(t *testing.T) {
	spec := &Spec{
		BaseLevel: LevelWarn,
		Components: map[string]Level{
			"manager": LevelDebug,
			"store":   LevelTrace,
		},
	}

	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: LevelTrace.ToSlog()})
	handler := NewFilteringHandler(inner, spec)

	// Base handler (no component) uses warn level
	assert.False(t, handler.Enabled(context.Background(), slog.LevelDebug))
	assert.False(t, handler.Enabled(context.Background(), slog.LevelInfo))
	assert.True(t, handler.Enabled(context.Background(), slog.LevelWarn))
	assert.True(t, handler.Enabled(context.Background(), slog.LevelError))

	// Manager component uses debug level
	managerHandler := handler.WithAttrs([]slog.Attr{slog.String("component", "manager")})
	assert.True(t, managerHandler.Enabled(context.Background(), slog.LevelDebug))
	assert.True(t, managerHandler.Enabled(context.Background(), slog.LevelInfo))
	assert.True(t, managerHandler.Enabled(context.Background(), slog.LevelWarn))
	assert.False(t, managerHandler.Enabled(context.Background(), LevelTrace.ToSlog()))

	// Store component uses trace level
	storeHandler := handler.WithAttrs([]slog.Attr{slog.String("component", "store")})
	assert.True(t, storeHandler.Enabled(context.Background(), LevelTrace.ToSlog()))
	assert.True(t, storeHandler.Enabled(context.Background(), slog.LevelDebug))
}

func TestFilteringHandler_Handle(t *testing.T) {
	spec := &Spec{
		BaseLevel: LevelWarn,
		Components: map[string]Level{
			"manager": LevelDebug,
		},
	}

	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: LevelTrace.ToSlog()})
	handler := NewFilteringHandler(inner, spec)

	ctx := context.Background()

	// Debug message without component should be filtered
	buf.Reset()
	r := slog.NewRecord(testTime(), slog.LevelDebug, "debug message", 0)
	err := handler.Handle(ctx, r)
	require.NoError(t, err)
	assert.Empty(t, buf.String())

	// Warn message without component should pass
	buf.Reset()
	r = slog.NewRecord(testTime(), slog.LevelWarn, "warn message", 0)
	err = handler.Handle(ctx, r)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "warn message")

	// Debug message with manager component should pass
	managerHandler := handler.WithAttrs([]slog.Attr{slog.String("component", "manager")})
	buf.Reset()
	r = slog.NewRecord(testTime(), slog.LevelDebug, "manager debug", 0)
	err = managerHandler.Handle(ctx, r)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "manager debug")
}

func TestFilteringHandler_WithGroup(t *testing.T) {
	spec := &Spec{
		BaseLevel: LevelInfo,
		Components: map[string]Level{
			"manager": LevelDebug,
		},
	}

	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: LevelTrace.ToSlog()})
	handler := NewFilteringHandler(inner, spec)

	// WithGroup should preserve the component
	managerHandler := handler.WithAttrs([]slog.Attr{slog.String("component", "manager")})
	groupHandler := managerHandler.WithGroup("request")

	// Should still use manager's debug level
	assert.True(t, groupHandler.Enabled(context.Background(), slog.LevelDebug))
}

func TestFilteringHandler_Integration(t *testing.T) {
	spec, err := ParseSpec("warn,manager=debug,store=trace")
	require.NoError(t, err)

	var buf bytes.Buffer
	logger, err := New(Options{
		CLISpec: spec.String(),
		Output:  &buf,
	})
	require.NoError(t, err)

	// Root logger uses warn level
	buf.Reset()
	logger.Debug("root debug")
	assert.Empty(t, buf.String())

	buf.Reset()
	logger.Warn("root warn")
	assert.Contains(t, buf.String(), "root warn")

	// Manager logger uses debug level
	managerLogger := logger.With("component", "manager")

	buf.Reset()
	managerLogger.Debug("manager debug")
	assert.Contains(t, buf.String(), "manager debug")

	buf.Reset()
	managerLogger.Info("manager info")
	assert.Contains(t, buf.String(), "manager info")

	// Store logger uses trace level
	storeLogger := logger.With("component", "store")

	buf.Reset()
	storeLogger.Log(context.Background(), LevelTrace.ToSlog(), "store trace")
	assert.Contains(t, buf.String(), "store trace")

	// Server logger (not in spec) falls back to warn
	serverLogger := logger.With("component", "server")

	buf.Reset()
	serverLogger.Debug("server debug")
	assert.Empty(t, buf.String())

	buf.Reset()
	serverLogger.Warn("server warn")
	assert.Contains(t, buf.String(), "server warn")
}

func TestNew_Precedence(t *testing.T) {
	tests := []struct {
		name      string
		opts      Options
		wantLevel Level
	}{
		{
			name:      "cli takes precedence over env",
			opts:      Options{CLISpec: "error", EnvSpec: "debug", ConfigSpec: "info"},
			wantLevel: LevelError,
		},
		{
			name:      "env takes precedence over config",
			opts:      Options{EnvSpec: "debug", ConfigSpec: "info"},
			wantLevel: LevelDebug,
		},
		{
			name:      "config used when nothing else specified",
			opts:      Options{ConfigSpec: "warn"},
			wantLevel: LevelWarn,
		},
		{
			name:      "default is warn",
			opts:      Options{},
			wantLevel: LevelWarn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			tt.opts.Output = &buf

			logger, err := New(tt.opts)
			require.NoError(t, err)

			// Check that the expected level is enabled
			ctx := context.Background()

			buf.Reset()
			logger.Log(ctx, tt.wantLevel.ToSlog(), "test message")
			assert.NotEmpty(t, buf.String(), "expected level %s should be logged", tt.wantLevel)

			// Check that the level below is not enabled
			if tt.wantLevel > LevelTrace {
				belowLevel := Level(int(tt.wantLevel) - 4)
				buf.Reset()
				logger.Log(ctx, belowLevel.ToSlog(), "test message below")
				assert.Empty(t, buf.String(), "level %s below %s should not be logged", belowLevel, tt.wantLevel)
			}
		})
	}
}

func TestNew_InvalidSpec(t *testing.T) {
	_, err := New(Options{CLISpec: "invalid"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid log spec")
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input   string
		want    Format
		wantErr bool
	}{
		{"text", FormatText, false},
		{"json", FormatJSON, false},
		{"TEXT", FormatText, false},
		{"JSON", FormatJSON, false},
		{"", FormatText, false},
		{"invalid", FormatText, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseFormat(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNew_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(Options{
		CLISpec: "info",
		Format:  FormatJSON,
		Output:  &buf,
	})
	require.NoError(t, err)

	logger.Info("test message", "key", "value")
	output := buf.String()

	// JSON output should contain these elements
	assert.True(t, strings.HasPrefix(output, "{"))
	assert.Contains(t, output, `"msg":"test message"`)
	assert.Contains(t, output, `"key":"value"`)
}

func testTime() time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
}
