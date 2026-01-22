package config

import "path/filepath"

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
	return filepath.Join(d.Base, "state.db")
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

// LinkPinPath returns the pin path for a link.
// Format: {base}/fs/links/{link_id}
func (d RuntimeDirs) LinkPinPath(linkID uint32) string {
	return filepath.Join(d.FS_LINKS, uitoa(linkID))
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
