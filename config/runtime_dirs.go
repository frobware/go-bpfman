package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/frobware/go-bpfman/bpffs"
)

// RuntimeDirs holds all runtime directory paths for bpfman.
//
// These paths mirror upstream Rust bpfman's directory structure:
//
//	{base}/              - runtime root
//	{base}/fs/           - bpffs mount
//	{base}/fs/xdp/       - XDP dispatcher pins
//	{base}/fs/tc-*/      - TC dispatcher pins
//	{base}/fs/maps/      - map pins
//	{base}/fs/links/     - link pins
//	{base}/db/           - database directory
//	{base}/csi/          - CSI socket directory
//	{base}/csi/fs/       - CSI per-pod mounts
//	{base}-sock/         - gRPC socket directory
//
// RuntimeDirs is immutable after construction. Use NewRuntimeDirs to create.
// Fields are unexported to prevent construction of invalid instances.
type RuntimeDirs struct {
	base        string // runtime root (e.g., /run/bpfman)
	fs          string // bpffs mount point
	fsXDP       string // XDP dispatcher pins
	fsTCIngress string // TC ingress dispatcher pins
	fsTCEgress  string // TC egress dispatcher pins
	fsMaps      string // map pins
	fsLinks     string // link pins
	db          string // database directory
	csi         string // CSI socket directory
	csiFS       string // CSI per-pod mounts
	sock        string // gRPC socket directory
	lock        string // global writer lock file
}

// DefaultRuntimeDirs returns RuntimeDirs with production defaults.
// Panics if the default path is somehow invalid (should never happen).
func DefaultRuntimeDirs() RuntimeDirs {
	dirs, err := NewRuntimeDirs("/run/bpfman")
	if err != nil {
		panic(fmt.Sprintf("DefaultRuntimeDirs: %v", err))
	}
	return dirs
}

// NewRuntimeDirs creates RuntimeDirs rooted at the given base path.
// All subdirectories are derived from the base.
//
// The socket directory is {base}-sock (e.g., /run/bpfman-sock) to allow
// separate volume mounts in Kubernetes.
//
// Returns an error if base is empty or not an absolute path.
func NewRuntimeDirs(base string) (RuntimeDirs, error) {
	if base == "" {
		return RuntimeDirs{}, fmt.Errorf("base path cannot be empty")
	}
	if !filepath.IsAbs(base) {
		return RuntimeDirs{}, fmt.Errorf("base path must be absolute, got %q", base)
	}

	fs := filepath.Join(base, "fs")
	return RuntimeDirs{
		base: base,

		fs:          fs,
		fsXDP:       filepath.Join(fs, "xdp"),
		fsTCIngress: filepath.Join(fs, "tc-ingress"),
		fsTCEgress:  filepath.Join(fs, "tc-egress"),
		fsMaps:      filepath.Join(fs, "maps"),
		fsLinks:     filepath.Join(fs, "links"),

		db: filepath.Join(base, "db"),

		csi:   filepath.Join(base, "csi"),
		csiFS: filepath.Join(base, "csi", "fs"),

		sock: base + "-sock",

		lock: filepath.Join(base, ".lock"),
	}, nil
}

// Getter methods for RuntimeDirs fields.

// Base returns the runtime root path (e.g., /run/bpfman).
func (d RuntimeDirs) Base() string { return d.base }

// FS returns the bpffs mount point path.
func (d RuntimeDirs) FS() string { return d.fs }

// FS_XDP returns the XDP dispatcher pins directory.
func (d RuntimeDirs) FS_XDP() string { return d.fsXDP }

// FS_TC_INGRESS returns the TC ingress dispatcher pins directory.
func (d RuntimeDirs) FS_TC_INGRESS() string { return d.fsTCIngress }

// FS_TC_EGRESS returns the TC egress dispatcher pins directory.
func (d RuntimeDirs) FS_TC_EGRESS() string { return d.fsTCEgress }

// FS_MAPS returns the map pins directory.
func (d RuntimeDirs) FS_MAPS() string { return d.fsMaps }

// FS_LINKS returns the link pins directory.
func (d RuntimeDirs) FS_LINKS() string { return d.fsLinks }

// DB returns the database directory path.
func (d RuntimeDirs) DB() string { return d.db }

// CSI returns the CSI socket directory path.
func (d RuntimeDirs) CSI() string { return d.csi }

// CSI_FS returns the CSI per-pod mounts directory path.
func (d RuntimeDirs) CSI_FS() string { return d.csiFS }

// Sock returns the gRPC socket directory path.
func (d RuntimeDirs) Sock() string { return d.sock }

// Lock returns the global writer lock file path.
func (d RuntimeDirs) Lock() string { return d.lock }

// SocketPath returns the full path to the gRPC socket.
func (d RuntimeDirs) SocketPath() string {
	return filepath.Join(d.sock, "bpfman.sock")
}

// CSISocketPath returns the full path to the CSI socket.
func (d RuntimeDirs) CSISocketPath() string {
	return filepath.Join(d.csi, "csi.sock")
}

// DBPath returns the full path to the SQLite database file.
func (d RuntimeDirs) DBPath() string {
	return filepath.Join(d.db, "store.db")
}

// ProgPinPath returns the pin path for a program.
// Format: {base}/fs/prog_{id}
func (d RuntimeDirs) ProgPinPath(kernelID uint32) string {
	return filepath.Join(d.fs, "prog_"+uitoa(kernelID))
}

// MapPinDir returns the directory for a program's map pins.
// Format: {base}/fs/maps/{program_id}/
func (d RuntimeDirs) MapPinDir(programID uint32) string {
	return filepath.Join(d.fsMaps, uitoa(programID))
}

// LinkPinDir returns the directory for a program's link pins.
// Format: {base}/fs/links/{program_id}/
func (d RuntimeDirs) LinkPinDir(programID uint32) string {
	return filepath.Join(d.fsLinks, uitoa(programID))
}

// uitoa converts uint32 to string.
func uitoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// EnsureDirectories creates core runtime directories and ensures bpffs is mounted.
// Call this at startup to fail fast on permission or configuration issues.
//
// Creates these directories (on regular filesystem):
//   - {base}/
//   - {base}/db/
//   - {base}-sock/
//
// Mounts bpffs at {base}/fs/ if not already mounted. This requires
// CAP_SYS_ADMIN; if the mount fails due to permissions, ensure bpffs
// is pre-mounted by the container runtime or systemd unit.
//
// CSI directories are not created here; use EnsureCSIDirectories when
// CSI functionality is enabled.
func (d RuntimeDirs) EnsureDirectories() error {
	// Create core directories. MkdirAll is idempotent.
	// CSI directories are created separately by EnsureCSIDirectories.
	for _, dir := range []string{d.base, d.db, d.sock} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Ensure bpffs is mounted
	if err := bpffs.EnsureMounted(bpffs.DefaultMountInfoPath, d.fs); err != nil {
		return fmt.Errorf("failed to ensure bpffs at %s: %w", d.fs, err)
	}

	return nil
}

// EnsureCSIDirectories creates CSI-specific directories.
// Call this only when CSI functionality is enabled.
//
// Creates these directories:
//   - {base}/csi/
//   - {base}/csi/fs/
func (d RuntimeDirs) EnsureCSIDirectories() error {
	for _, dir := range []string{d.csi, d.csiFS} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

// ScannerDirs returns a bpffs.ScannerDirs for use with bpffs.Scanner.
func (d RuntimeDirs) ScannerDirs() bpffs.ScannerDirs {
	return bpffs.ScannerDirs{
		FS:        d.fs,
		XDP:       d.fsXDP,
		TCIngress: d.fsTCIngress,
		TCEgress:  d.fsTCEgress,
		Maps:      d.fsMaps,
		Links:     d.fsLinks,
	}
}
