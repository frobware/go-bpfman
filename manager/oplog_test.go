package manager

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestOpIDHandler(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewTextHandler(&buf, nil)
	logger := slog.New(opIDHandler{baseHandler})

	// Without op_id in context, should not include op_id
	buf.Reset()
	logger.InfoContext(context.Background(), "test message")
	if strings.Contains(buf.String(), "op_id") {
		t.Errorf("expected no op_id without context, got: %s", buf.String())
	}

	// With op_id in context, should include op_id
	buf.Reset()
	ctx := ContextWithOpID(context.Background(), 42)
	logger.InfoContext(ctx, "test message")
	output := buf.String()
	if !strings.Contains(output, "op_id=42") {
		t.Errorf("expected op_id=42 in output, got: %s", output)
	}
}

func TestWithOpIDHandler(t *testing.T) {
	var buf bytes.Buffer
	baseLogger := slog.New(slog.NewTextHandler(&buf, nil))
	logger := WithOpIDHandler(baseLogger)

	ctx := ContextWithOpID(context.Background(), 123)
	logger.InfoContext(ctx, "wrapped logger test")
	output := buf.String()
	if !strings.Contains(output, "op_id=123") {
		t.Errorf("expected op_id=123 in output, got: %s", output)
	}
}

func TestOpIDHandler_WithAttrs(t *testing.T) {
	// Verify op_id works after calling logger.With() which uses WithAttrs
	var buf bytes.Buffer
	baseLogger := slog.New(slog.NewTextHandler(&buf, nil))
	logger := WithOpIDHandler(baseLogger)

	// Add attributes like the server/manager do
	logger = logger.With("component", "test")

	ctx := ContextWithOpID(context.Background(), 456)
	logger.InfoContext(ctx, "with attrs test")
	output := buf.String()
	if !strings.Contains(output, "op_id=456") {
		t.Errorf("expected op_id=456 in output after With(), got: %s", output)
	}
	if !strings.Contains(output, "component=test") {
		t.Errorf("expected component=test in output, got: %s", output)
	}
}
