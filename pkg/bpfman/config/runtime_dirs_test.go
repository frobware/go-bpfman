package config

import "testing"

func TestNewRuntimeDirs(t *testing.T) {
	tests := []struct {
		name string
		base string
		want RuntimeDirs
	}{
		{
			name: "production default",
			base: "/run/bpfman",
			want: RuntimeDirs{
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
			},
		},
		{
			name: "go variant for parallel testing",
			base: "/run/bpfman-go",
			want: RuntimeDirs{
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
			},
		},
		{
			name: "temp dir for unit tests",
			base: "/tmp/bpfman-test-12345",
			want: RuntimeDirs{
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
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewRuntimeDirs(tt.base)
			if got != tt.want {
				t.Errorf("NewRuntimeDirs(%q) =\n%+v\nwant\n%+v", tt.base, got, tt.want)
			}
		})
	}
}

func TestRuntimeDirs_Paths(t *testing.T) {
	d := NewRuntimeDirs("/run/bpfman")

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"SocketPath", d.SocketPath(), "/run/bpfman-sock/bpfman.sock"},
		{"CSISocketPath", d.CSISocketPath(), "/run/bpfman/csi/csi.sock"},
		{"DBPath", d.DBPath(), "/run/bpfman/state.db"},
		{"ProgPinPath(42)", d.ProgPinPath(42), "/run/bpfman/fs/prog_42"},
		{"ProgPinPath(0)", d.ProgPinPath(0), "/run/bpfman/fs/prog_0"},
		{"MapPinDir(123)", d.MapPinDir(123), "/run/bpfman/fs/maps/123"},
		{"LinkPinPath(456)", d.LinkPinPath(456), "/run/bpfman/fs/links/456"},
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
	d := DefaultRuntimeDirs()
	if d.Base != "/run/bpfman" {
		t.Errorf("DefaultRuntimeDirs().Base = %q, want /run/bpfman", d.Base)
	}
}
