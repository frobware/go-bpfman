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
type RuntimeDirs struct {
	// Base is the runtime root (e.g., /run/bpfman).
	Base string

	// FS is the bpffs mount point.
	FS string

	// Dispatcher directories on bpffs.
	FS_XDP        string
	FS_TC_INGRESS string
	FS_TC_EGRESS  string

	// Map and link directories on bpffs.
	FS_MAPS  string
	FS_LINKS string

	// DB is the database directory.
	DB string

	// CSI directories.
	CSI    string
	CSI_FS string

	// Sock is the gRPC socket directory.
	Sock string
}

// DefaultRuntimeDirs returns RuntimeDirs with production defaults.
func DefaultRuntimeDirs() RuntimeDirs {
	return NewRuntimeDirs("/run/bpfman")
}

// NewRuntimeDirs creates RuntimeDirs rooted at the given base path.
// All subdirectories are derived from the base.
//
// The socket directory is {base}-sock (e.g., /run/bpfman-sock) to allow
// separate volume mounts in Kubernetes.
func NewRuntimeDirs(base string) RuntimeDirs {
	fs := filepath.Join(base, "fs")
	return RuntimeDirs{
		Base: base,

		FS:            fs,
		FS_XDP:        filepath.Join(fs, "xdp"),
		FS_TC_INGRESS: filepath.Join(fs, "tc-ingress"),
		FS_TC_EGRESS:  filepath.Join(fs, "tc-egress"),
		FS_MAPS:       filepath.Join(fs, "maps"),
		FS_LINKS:      filepath.Join(fs, "links"),

		DB: filepath.Join(base, "db"),

		CSI:    filepath.Join(base, "csi"),
		CSI_FS: filepath.Join(base, "csi", "fs"),

		Sock: base + "-sock",
	}
}

// SocketPath returns the full path to the gRPC socket.
func (d RuntimeDirs) SocketPath() string {
	return filepath.Join(d.Sock, "bpfman.sock")
}

// CSISocketPath returns the full path to the CSI socket.
func (d RuntimeDirs) CSISocketPath() string {
	return filepath.Join(d.CSI, "csi.sock")
}

// DBPath returns the full path to the SQLite database file.
func (d RuntimeDirs) DBPath() string {
	return filepath.Join(d.DB, "store.db")
}

// ProgPinPath returns the pin path for a program.
// Format: {base}/fs/prog_{id}
func (d RuntimeDirs) ProgPinPath(kernelID uint32) string {
	return filepath.Join(d.FS, "prog_"+uitoa(kernelID))
}

// MapPinDir returns the directory for a program's map pins.
// Format: {base}/fs/maps/{program_id}/
func (d RuntimeDirs) MapPinDir(programID uint32) string {
	return filepath.Join(d.FS_MAPS, uitoa(programID))
}

// LinkPinDir returns the directory for a program's link pins.
// Format: {base}/fs/links/{program_id}/
func (d RuntimeDirs) LinkPinDir(programID uint32) string {
	return filepath.Join(d.FS_LINKS, uitoa(programID))
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
	for _, dir := range []string{d.Base, d.DB, d.Sock} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Ensure bpffs is mounted
	if err := bpffs.EnsureMounted(bpffs.DefaultMountInfoPath, d.FS); err != nil {
		return fmt.Errorf("failed to ensure bpffs at %s: %w", d.FS, err)
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
	for _, dir := range []string{d.CSI, d.CSI_FS} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}
