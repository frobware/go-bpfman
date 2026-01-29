package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/frobware/go-bpfman/config"
)

func TestNewRuntimeDirs(t *testing.T) {
	tests := []struct {
		name string
		base string
		want config.RuntimeDirs
	}{
		{
			name: "production default",
			base: "/run/bpfman",
			want: config.RuntimeDirs{
				Base:          "/run/bpfman",
				FS:            "/run/bpfman/fs",
				FS_XDP:        "/run/bpfman/fs/xdp",
				FS_TC_INGRESS: "/run/bpfman/fs/tc-ingress",
				FS_TC_EGRESS:  "/run/bpfman/fs/tc-egress",
				FS_MAPS:       "/run/bpfman/fs/maps",
				FS_LINKS:      "/run/bpfman/fs/links",
				DB:            "/run/bpfman/db",
				CSI:           "/run/bpfman/csi",
				CSI_FS:        "/run/bpfman/csi/fs",
				Sock:          "/run/bpfman-sock",
				Lock:          "/run/bpfman/.lock",
			},
		},
		{
			name: "go variant for parallel testing",
			base: "/run/bpfman-go",
			want: config.RuntimeDirs{
				Base:          "/run/bpfman-go",
				FS:            "/run/bpfman-go/fs",
				FS_XDP:        "/run/bpfman-go/fs/xdp",
				FS_TC_INGRESS: "/run/bpfman-go/fs/tc-ingress",
				FS_TC_EGRESS:  "/run/bpfman-go/fs/tc-egress",
				FS_MAPS:       "/run/bpfman-go/fs/maps",
				FS_LINKS:      "/run/bpfman-go/fs/links",
				DB:            "/run/bpfman-go/db",
				CSI:           "/run/bpfman-go/csi",
				CSI_FS:        "/run/bpfman-go/csi/fs",
				Sock:          "/run/bpfman-go-sock",
				Lock:          "/run/bpfman-go/.lock",
			},
		},
		{
			name: "temp dir for unit tests",
			base: "/tmp/bpfman-test-12345",
			want: config.RuntimeDirs{
				Base:          "/tmp/bpfman-test-12345",
				FS:            "/tmp/bpfman-test-12345/fs",
				FS_XDP:        "/tmp/bpfman-test-12345/fs/xdp",
				FS_TC_INGRESS: "/tmp/bpfman-test-12345/fs/tc-ingress",
				FS_TC_EGRESS:  "/tmp/bpfman-test-12345/fs/tc-egress",
				FS_MAPS:       "/tmp/bpfman-test-12345/fs/maps",
				FS_LINKS:      "/tmp/bpfman-test-12345/fs/links",
				DB:            "/tmp/bpfman-test-12345/db",
				CSI:           "/tmp/bpfman-test-12345/csi",
				CSI_FS:        "/tmp/bpfman-test-12345/csi/fs",
				Sock:          "/tmp/bpfman-test-12345-sock",
				Lock:          "/tmp/bpfman-test-12345/.lock",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.NewRuntimeDirs(tt.base)
			if got != tt.want {
				t.Errorf("NewRuntimeDirs(%q) =\n%+v\nwant\n%+v", tt.base, got, tt.want)
			}
		})
	}
}

func TestRuntimeDirs_Paths(t *testing.T) {
	d := config.NewRuntimeDirs("/run/bpfman")

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"SocketPath", d.SocketPath(), "/run/bpfman-sock/bpfman.sock"},
		{"CSISocketPath", d.CSISocketPath(), "/run/bpfman/csi/csi.sock"},
		{"DBPath", d.DBPath(), "/run/bpfman/db/store.db"},
		{"ProgPinPath(42)", d.ProgPinPath(42), "/run/bpfman/fs/prog_42"},
		{"ProgPinPath(0)", d.ProgPinPath(0), "/run/bpfman/fs/prog_0"},
		{"MapPinDir(123)", d.MapPinDir(123), "/run/bpfman/fs/maps/123"},
		{"LinkPinDir(456)", d.LinkPinDir(456), "/run/bpfman/fs/links/456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestDefaultRuntimeDirs(t *testing.T) {
	d := config.DefaultRuntimeDirs()
	if d.Base != "/run/bpfman" {
		t.Errorf("DefaultRuntimeDirs().Base = %q, want /run/bpfman", d.Base)
	}
}

func TestEnsureDirectories_CreatesDirs(t *testing.T) {
	base := t.TempDir()
	d := config.NewRuntimeDirs(base)

	// EnsureDirectories will fail trying to mount bpffs (no CAP_SYS_ADMIN),
	// but should create the core directories first.
	err := d.EnsureDirectories()
	if err == nil {
		t.Fatal("expected error due to mount failure (no CAP_SYS_ADMIN)")
	}

	// Verify core directories were created before the bpffs mount failed.
	// CSI directories are not created by EnsureDirectories.
	for _, dir := range []string{d.Base, d.DB, d.Sock} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("directory %s was not created", dir)
		}
	}

	// CSI directories should NOT be created by EnsureDirectories
	for _, dir := range []string{d.CSI, d.CSI_FS} {
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("CSI directory %s should not be created by EnsureDirectories", dir)
		}
	}
}

func TestEnsureCSIDirectories_CreatesDirs(t *testing.T) {
	base := t.TempDir()
	d := config.NewRuntimeDirs(base)

	err := d.EnsureCSIDirectories()
	if err != nil {
		t.Fatalf("EnsureCSIDirectories failed: %v", err)
	}

	for _, dir := range []string{d.CSI, d.CSI_FS} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("directory %s was not created", dir)
		}
	}
}

func TestEnsureDirectories_FailsWithoutCAP_SYS_ADMIN(t *testing.T) {
	base := t.TempDir()
	d := config.NewRuntimeDirs(base)

	// Without CAP_SYS_ADMIN, mounting bpffs should fail
	err := d.EnsureDirectories()
	if err == nil {
		t.Fatal("expected error due to mount failure")
	}

	// The error should mention the mount failure
	if !strings.Contains(err.Error(), "bpffs") {
		t.Errorf("expected error about bpffs, got: %v", err)
	}
}
