package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/frobware/go-bpfman/config"
)

func TestNewRuntimeDirs(t *testing.T) {
	tests := []struct {
		name          string
		base          string
		wantBase      string
		wantFS        string
		wantFS_XDP    string
		wantFS_TC_ING string
		wantFS_TC_EGR string
		wantFS_MAPS   string
		wantFS_LINKS  string
		wantDB        string
		wantCSI       string
		wantCSI_FS    string
		wantSock      string
		wantLock      string
	}{
		{
			name:          "production default",
			base:          "/run/bpfman",
			wantBase:      "/run/bpfman",
			wantFS:        "/run/bpfman/fs",
			wantFS_XDP:    "/run/bpfman/fs/xdp",
			wantFS_TC_ING: "/run/bpfman/fs/tc-ingress",
			wantFS_TC_EGR: "/run/bpfman/fs/tc-egress",
			wantFS_MAPS:   "/run/bpfman/fs/maps",
			wantFS_LINKS:  "/run/bpfman/fs/links",
			wantDB:        "/run/bpfman/db",
			wantCSI:       "/run/bpfman/csi",
			wantCSI_FS:    "/run/bpfman/csi/fs",
			wantSock:      "/run/bpfman-sock",
			wantLock:      "/run/bpfman/.lock",
		},
		{
			name:          "go variant for parallel testing",
			base:          "/run/bpfman-go",
			wantBase:      "/run/bpfman-go",
			wantFS:        "/run/bpfman-go/fs",
			wantFS_XDP:    "/run/bpfman-go/fs/xdp",
			wantFS_TC_ING: "/run/bpfman-go/fs/tc-ingress",
			wantFS_TC_EGR: "/run/bpfman-go/fs/tc-egress",
			wantFS_MAPS:   "/run/bpfman-go/fs/maps",
			wantFS_LINKS:  "/run/bpfman-go/fs/links",
			wantDB:        "/run/bpfman-go/db",
			wantCSI:       "/run/bpfman-go/csi",
			wantCSI_FS:    "/run/bpfman-go/csi/fs",
			wantSock:      "/run/bpfman-go-sock",
			wantLock:      "/run/bpfman-go/.lock",
		},
		{
			name:          "temp dir for unit tests",
			base:          "/tmp/bpfman-test-12345",
			wantBase:      "/tmp/bpfman-test-12345",
			wantFS:        "/tmp/bpfman-test-12345/fs",
			wantFS_XDP:    "/tmp/bpfman-test-12345/fs/xdp",
			wantFS_TC_ING: "/tmp/bpfman-test-12345/fs/tc-ingress",
			wantFS_TC_EGR: "/tmp/bpfman-test-12345/fs/tc-egress",
			wantFS_MAPS:   "/tmp/bpfman-test-12345/fs/maps",
			wantFS_LINKS:  "/tmp/bpfman-test-12345/fs/links",
			wantDB:        "/tmp/bpfman-test-12345/db",
			wantCSI:       "/tmp/bpfman-test-12345/csi",
			wantCSI_FS:    "/tmp/bpfman-test-12345/csi/fs",
			wantSock:      "/tmp/bpfman-test-12345-sock",
			wantLock:      "/tmp/bpfman-test-12345/.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := config.NewRuntimeDirs(tt.base)
			if err != nil {
				t.Fatalf("NewRuntimeDirs(%q) error: %v", tt.base, err)
			}
			if got.Base() != tt.wantBase {
				t.Errorf("Base() = %q, want %q", got.Base(), tt.wantBase)
			}
			if got.FS() != tt.wantFS {
				t.Errorf("FS() = %q, want %q", got.FS(), tt.wantFS)
			}
			if got.FS_XDP() != tt.wantFS_XDP {
				t.Errorf("FS_XDP() = %q, want %q", got.FS_XDP(), tt.wantFS_XDP)
			}
			if got.FS_TC_INGRESS() != tt.wantFS_TC_ING {
				t.Errorf("FS_TC_INGRESS() = %q, want %q", got.FS_TC_INGRESS(), tt.wantFS_TC_ING)
			}
			if got.FS_TC_EGRESS() != tt.wantFS_TC_EGR {
				t.Errorf("FS_TC_EGRESS() = %q, want %q", got.FS_TC_EGRESS(), tt.wantFS_TC_EGR)
			}
			if got.FS_MAPS() != tt.wantFS_MAPS {
				t.Errorf("FS_MAPS() = %q, want %q", got.FS_MAPS(), tt.wantFS_MAPS)
			}
			if got.FS_LINKS() != tt.wantFS_LINKS {
				t.Errorf("FS_LINKS() = %q, want %q", got.FS_LINKS(), tt.wantFS_LINKS)
			}
			if got.DB() != tt.wantDB {
				t.Errorf("DB() = %q, want %q", got.DB(), tt.wantDB)
			}
			if got.CSI() != tt.wantCSI {
				t.Errorf("CSI() = %q, want %q", got.CSI(), tt.wantCSI)
			}
			if got.CSI_FS() != tt.wantCSI_FS {
				t.Errorf("CSI_FS() = %q, want %q", got.CSI_FS(), tt.wantCSI_FS)
			}
			if got.Sock() != tt.wantSock {
				t.Errorf("Sock() = %q, want %q", got.Sock(), tt.wantSock)
			}
			if got.Lock() != tt.wantLock {
				t.Errorf("Lock() = %q, want %q", got.Lock(), tt.wantLock)
			}
		})
	}
}

func TestRuntimeDirs_Paths(t *testing.T) {
	d, err := config.NewRuntimeDirs("/run/bpfman")
	if err != nil {
		t.Fatalf("NewRuntimeDirs: %v", err)
	}

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
	if d.Base() != "/run/bpfman" {
		t.Errorf("DefaultRuntimeDirs().Base() = %q, want /run/bpfman", d.Base())
	}
}

func TestNewRuntimeDirs_Validation(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		wantErr bool
	}{
		{"empty base", "", true},
		{"relative path", "relative/path", true},
		{"absolute path", "/absolute/path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.NewRuntimeDirs(tt.base)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRuntimeDirs(%q) error = %v, wantErr %v", tt.base, err, tt.wantErr)
			}
		})
	}
}

func TestEnsureDirectories_CreatesDirs(t *testing.T) {
	base := t.TempDir()
	d, err := config.NewRuntimeDirs(base)
	if err != nil {
		t.Fatalf("NewRuntimeDirs: %v", err)
	}

	// EnsureDirectories will fail trying to mount bpffs (no CAP_SYS_ADMIN),
	// but should create the core directories first.
	err = d.EnsureDirectories()
	if err == nil {
		t.Fatal("expected error due to mount failure (no CAP_SYS_ADMIN)")
	}

	// Verify core directories were created before the bpffs mount failed.
	// CSI directories are not created by EnsureDirectories.
	for _, dir := range []string{d.Base(), d.DB(), d.Sock()} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("directory %s was not created", dir)
		}
	}

	// CSI directories should NOT be created by EnsureDirectories
	for _, dir := range []string{d.CSI(), d.CSI_FS()} {
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("CSI directory %s should not be created by EnsureDirectories", dir)
		}
	}
}

func TestEnsureCSIDirectories_CreatesDirs(t *testing.T) {
	base := t.TempDir()
	d, err := config.NewRuntimeDirs(base)
	if err != nil {
		t.Fatalf("NewRuntimeDirs: %v", err)
	}

	err = d.EnsureCSIDirectories()
	if err != nil {
		t.Fatalf("EnsureCSIDirectories failed: %v", err)
	}

	for _, dir := range []string{d.CSI(), d.CSI_FS()} {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("directory %s was not created", dir)
		}
	}
}

func TestEnsureDirectories_FailsWithoutCAP_SYS_ADMIN(t *testing.T) {
	base := t.TempDir()
	d, err := config.NewRuntimeDirs(base)
	if err != nil {
		t.Fatalf("NewRuntimeDirs: %v", err)
	}

	// Without CAP_SYS_ADMIN, mounting bpffs should fail
	err = d.EnsureDirectories()
	if err == nil {
		t.Fatal("expected error due to mount failure")
	}

	// The error should mention the mount failure
	if !strings.Contains(err.Error(), "bpffs") {
		t.Errorf("expected error about bpffs, got: %v", err)
	}
}
