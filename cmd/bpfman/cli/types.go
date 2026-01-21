// Package cli provides the Kong-based command-line interface for bpfman.
package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// ProgramID wraps a uint32 kernel program ID with hex support.
type ProgramID struct {
	Value uint32
}

// ParseProgramID parses a program ID from string, supporting hex (0x) prefix.
func ParseProgramID(s string) (ProgramID, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ProgramID{}, fmt.Errorf("program ID cannot be empty")
	}

	var val uint64
	var err error

	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, err = strconv.ParseUint(s[2:], 16, 32)
	} else {
		val, err = strconv.ParseUint(s, 10, 32)
	}

	if err != nil {
		return ProgramID{}, fmt.Errorf("invalid program ID %q: %w", s, err)
	}

	return ProgramID{Value: uint32(val)}, nil
}

// LinkID wraps a uint32 kernel link ID with hex support.
type LinkID struct {
	Value uint32
}

// ParseLinkID parses a link ID from string, supporting hex (0x) prefix.
func ParseLinkID(s string) (LinkID, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return LinkID{}, fmt.Errorf("link ID cannot be empty")
	}

	var val uint64
	var err error

	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, err = strconv.ParseUint(s[2:], 16, 32)
	} else {
		val, err = strconv.ParseUint(s, 10, 32)
	}

	if err != nil {
		return LinkID{}, fmt.Errorf("invalid link ID %q: %w", s, err)
	}

	return LinkID{Value: uint32(val)}, nil
}

// LinkUUID wraps a UUID string for link identification.
type LinkUUID struct {
	Value string
}

// ParseLinkUUID parses and validates a link UUID.
func ParseLinkUUID(s string) (LinkUUID, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return LinkUUID{}, fmt.Errorf("link UUID cannot be empty")
	}

	if _, err := uuid.Parse(s); err != nil {
		return LinkUUID{}, fmt.Errorf("invalid UUID %q: %w", s, err)
	}

	return LinkUUID{Value: s}, nil
}

// KeyValue represents a KEY=VALUE metadata pair.
type KeyValue struct {
	Key   string
	Value string
}

// ParseKeyValue parses a KEY=VALUE string.
func ParseKeyValue(s string) (KeyValue, error) {
	idx := strings.Index(s, "=")
	if idx <= 0 {
		return KeyValue{}, fmt.Errorf("invalid format %q: expected KEY=VALUE", s)
	}

	key := strings.TrimSpace(s[:idx])
	if key == "" {
		return KeyValue{}, fmt.Errorf("invalid format %q: key cannot be empty", s)
	}

	return KeyValue{
		Key:   key,
		Value: s[idx+1:],
	}, nil
}

// GlobalData represents a NAME=HEX global data pair.
type GlobalData struct {
	Name string
	Data []byte
}

// ParseGlobalData parses a NAME=HEX string.
func ParseGlobalData(s string) (GlobalData, error) {
	idx := strings.Index(s, "=")
	if idx <= 0 {
		return GlobalData{}, fmt.Errorf("invalid format %q: expected NAME=HEX", s)
	}

	name := strings.TrimSpace(s[:idx])
	if name == "" {
		return GlobalData{}, fmt.Errorf("invalid format %q: name cannot be empty", s)
	}

	hexStr := strings.TrimSpace(s[idx+1:])
	// Remove optional 0x prefix
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return GlobalData{}, fmt.Errorf("invalid hex data for %q: %w", name, err)
	}

	return GlobalData{
		Name: name,
		Data: data,
	}, nil
}

// ObjectPath wraps a path to a BPF object file, validated for existence.
type ObjectPath struct {
	Path string
}

// ParseObjectPath parses and validates that the file exists.
func ParseObjectPath(s string) (ObjectPath, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ObjectPath{}, fmt.Errorf("object path cannot be empty")
	}

	info, err := os.Stat(s)
	if err != nil {
		if os.IsNotExist(err) {
			return ObjectPath{}, fmt.Errorf("object file %q does not exist", s)
		}
		return ObjectPath{}, fmt.Errorf("cannot access object file %q: %w", s, err)
	}

	if info.IsDir() {
		return ObjectPath{}, fmt.Errorf("object path %q is a directory, not a file", s)
	}

	return ObjectPath{Path: s}, nil
}

// DBPath wraps a path to the SQLite database with tilde expansion.
type DBPath struct {
	Path string
}

// ParseDBPath parses a database path with tilde expansion.
func ParseDBPath(s string) (DBPath, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return DBPath{}, fmt.Errorf("database path cannot be empty")
	}

	// Expand ~ to home directory
	if strings.HasPrefix(s, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return DBPath{}, fmt.Errorf("cannot expand ~: %w", err)
		}
		s = home + s[1:]
	}

	return DBPath{Path: s}, nil
}

// MetadataMap converts a slice of KeyValue to a map.
func MetadataMap(kvs []KeyValue) map[string]string {
	if len(kvs) == 0 {
		return nil
	}
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		m[kv.Key] = kv.Value
	}
	return m
}

// GlobalDataMap converts a slice of GlobalData to a map.
func GlobalDataMap(gds []GlobalData) map[string][]byte {
	if len(gds) == 0 {
		return nil
	}
	m := make(map[string][]byte, len(gds))
	for _, gd := range gds {
		m[gd.Name] = gd.Data
	}
	return m
}

// ProgramSpec represents a TYPE:NAME program specification for image loading.
type ProgramSpec struct {
	Type string // Program type (e.g., "xdp", "tc", "tracepoint")
	Name string // Program name within the ELF
}

// ParseProgramSpec parses a TYPE:NAME string (e.g., "xdp:xdp_pass").
func ParseProgramSpec(s string) (ProgramSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ProgramSpec{}, fmt.Errorf("program spec cannot be empty")
	}

	idx := strings.Index(s, ":")
	if idx <= 0 {
		return ProgramSpec{}, fmt.Errorf("invalid program spec %q: expected TYPE:NAME format (e.g., xdp:my_prog)", s)
	}

	progType := strings.TrimSpace(s[:idx])
	progName := strings.TrimSpace(s[idx+1:])

	if progType == "" {
		return ProgramSpec{}, fmt.Errorf("invalid program spec %q: type cannot be empty", s)
	}
	if progName == "" {
		return ProgramSpec{}, fmt.Errorf("invalid program spec %q: name cannot be empty", s)
	}

	return ProgramSpec{
		Type: progType,
		Name: progName,
	}, nil
}

// ImagePullPolicy represents a CLI-friendly pull policy string.
type ImagePullPolicy struct {
	Value string
}

// ParseImagePullPolicy parses a pull policy string.
func ParseImagePullPolicy(s string) (ImagePullPolicy, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ImagePullPolicy{Value: "IfNotPresent"}, nil
	}

	switch strings.ToLower(s) {
	case "always", "ifnotpresent", "never":
		return ImagePullPolicy{Value: s}, nil
	default:
		return ImagePullPolicy{}, fmt.Errorf("invalid pull policy %q: must be Always, IfNotPresent, or Never", s)
	}
}
