package dispatcher_test

import (
	"testing"

	"github.com/frobware/go-bpfman/internal/dispatcher"
)

const testBpffsRoot = "/sys/fs/bpf/bpfman"

func TestDispatcherLinkPath(t *testing.T) {
	tests := []struct {
		name      string
		bpffsRoot string
		dispType  dispatcher.DispatcherType
		nsid      uint64
		ifindex   uint32
		want      string
	}{
		{
			name:      "xdp loopback",
			bpffsRoot: testBpffsRoot,
			dispType:  dispatcher.DispatcherTypeXDP,
			nsid:      4026531840,
			ifindex:   1,
			want:      "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_link",
		},
		{
			name:      "xdp eth0",
			bpffsRoot: testBpffsRoot,
			dispType:  dispatcher.DispatcherTypeXDP,
			nsid:      4026531840,
			ifindex:   2,
			want:      "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_2_link",
		},
		{
			name:      "tc-ingress",
			bpffsRoot: testBpffsRoot,
			dispType:  dispatcher.DispatcherTypeTCIngress,
			nsid:      4026531999,
			ifindex:   3,
			want:      "/sys/fs/bpf/bpfman/tc-ingress/dispatcher_4026531999_3_link",
		},
		{
			name:      "tc-egress",
			bpffsRoot: testBpffsRoot,
			dispType:  dispatcher.DispatcherTypeTCEgress,
			nsid:      1234567890,
			ifindex:   10,
			want:      "/sys/fs/bpf/bpfman/tc-egress/dispatcher_1234567890_10_link",
		},
		{
			name:      "custom bpffs root",
			bpffsRoot: "/run/bpfman/fs",
			dispType:  dispatcher.DispatcherTypeXDP,
			nsid:      4026531840,
			ifindex:   1,
			want:      "/run/bpfman/fs/xdp/dispatcher_4026531840_1_link",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dispatcher.DispatcherLinkPath(tt.bpffsRoot, tt.dispType, tt.nsid, tt.ifindex)
			if got != tt.want {
				t.Errorf("DispatcherLinkPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDispatcherRevisionDir(t *testing.T) {
	tests := []struct {
		name      string
		bpffsRoot string
		dispType  dispatcher.DispatcherType
		nsid      uint64
		ifindex   uint32
		revision  uint32
		want      string
	}{
		{
			name:      "xdp revision 1",
			bpffsRoot: testBpffsRoot,
			dispType:  dispatcher.DispatcherTypeXDP,
			nsid:      4026531840,
			ifindex:   1,
			revision:  1,
			want:      "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1",
		},
		{
			name:      "xdp revision 42",
			bpffsRoot: testBpffsRoot,
			dispType:  dispatcher.DispatcherTypeXDP,
			nsid:      4026531840,
			ifindex:   1,
			revision:  42,
			want:      "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_42",
		},
		{
			name:      "tc-ingress revision 5",
			bpffsRoot: testBpffsRoot,
			dispType:  dispatcher.DispatcherTypeTCIngress,
			nsid:      4026531999,
			ifindex:   3,
			revision:  5,
			want:      "/sys/fs/bpf/bpfman/tc-ingress/dispatcher_4026531999_3_5",
		},
		{
			name:      "custom bpffs root",
			bpffsRoot: "/run/bpfman/fs",
			dispType:  dispatcher.DispatcherTypeXDP,
			nsid:      4026531840,
			ifindex:   1,
			revision:  1,
			want:      "/run/bpfman/fs/xdp/dispatcher_4026531840_1_1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dispatcher.DispatcherRevisionDir(tt.bpffsRoot, tt.dispType, tt.nsid, tt.ifindex, tt.revision)
			if got != tt.want {
				t.Errorf("DispatcherRevisionDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDispatcherProgPath(t *testing.T) {
	tests := []struct {
		name        string
		revisionDir string
		want        string
	}{
		{
			name:        "xdp revision 1",
			revisionDir: "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1",
			want:        "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/dispatcher",
		},
		{
			name:        "tc-ingress",
			revisionDir: "/sys/fs/bpf/bpfman/tc-ingress/dispatcher_4026531999_3_5",
			want:        "/sys/fs/bpf/bpfman/tc-ingress/dispatcher_4026531999_3_5/dispatcher",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dispatcher.DispatcherProgPath(tt.revisionDir)
			if got != tt.want {
				t.Errorf("DispatcherProgPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtensionLinkPath(t *testing.T) {
	tests := []struct {
		name        string
		revisionDir string
		position    int
		want        string
	}{
		{
			name:        "position 0",
			revisionDir: "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1",
			position:    0,
			want:        "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/link_0",
		},
		{
			name:        "position 5",
			revisionDir: "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1",
			position:    5,
			want:        "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/link_5",
		},
		{
			name:        "position 9",
			revisionDir: "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1",
			position:    9,
			want:        "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/link_9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dispatcher.ExtensionLinkPath(tt.revisionDir, tt.position)
			if got != tt.want {
				t.Errorf("ExtensionLinkPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTypeDir(t *testing.T) {
	tests := []struct {
		name      string
		bpffsRoot string
		dispType  dispatcher.DispatcherType
		want      string
	}{
		{
			name:      "xdp",
			bpffsRoot: testBpffsRoot,
			dispType:  dispatcher.DispatcherTypeXDP,
			want:      "/sys/fs/bpf/bpfman/xdp",
		},
		{
			name:      "tc-ingress",
			bpffsRoot: testBpffsRoot,
			dispType:  dispatcher.DispatcherTypeTCIngress,
			want:      "/sys/fs/bpf/bpfman/tc-ingress",
		},
		{
			name:      "tc-egress",
			bpffsRoot: testBpffsRoot,
			dispType:  dispatcher.DispatcherTypeTCEgress,
			want:      "/sys/fs/bpf/bpfman/tc-egress",
		},
		{
			name:      "custom bpffs root",
			bpffsRoot: "/run/bpfman/fs",
			dispType:  dispatcher.DispatcherTypeXDP,
			want:      "/run/bpfman/fs/xdp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dispatcher.TypeDir(tt.bpffsRoot, tt.dispType)
			if got != tt.want {
				t.Errorf("TypeDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPathsEndToEnd tests the full path composition workflow
func TestPathsEndToEnd(t *testing.T) {
	bpffsRoot := testBpffsRoot
	nsid := uint64(4026531840)
	ifindex := uint32(1)
	revision := uint32(1)

	// Get the stable link path
	linkPath := dispatcher.DispatcherLinkPath(bpffsRoot, dispatcher.DispatcherTypeXDP, nsid, ifindex)
	if linkPath != "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_link" {
		t.Errorf("unexpected link path: %s", linkPath)
	}

	// Get the revision directory
	revDir := dispatcher.DispatcherRevisionDir(bpffsRoot, dispatcher.DispatcherTypeXDP, nsid, ifindex, revision)
	if revDir != "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1" {
		t.Errorf("unexpected revision dir: %s", revDir)
	}

	// Get the dispatcher program path within the revision
	progPath := dispatcher.DispatcherProgPath(revDir)
	if progPath != "/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/dispatcher" {
		t.Errorf("unexpected prog path: %s", progPath)
	}

	// Get extension link paths for positions 0-2
	expectedExtPaths := []string{
		"/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/link_0",
		"/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/link_1",
		"/sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/link_2",
	}
	for pos := 0; pos < 3; pos++ {
		extPath := dispatcher.ExtensionLinkPath(revDir, pos)
		if extPath != expectedExtPaths[pos] {
			t.Errorf("position %d: got %s, want %s", pos, extPath, expectedExtPaths[pos])
		}
	}
}

// TestPathsEndToEndCustomRoot tests path composition with a custom bpffs root
func TestPathsEndToEndCustomRoot(t *testing.T) {
	bpffsRoot := "/run/bpfman/fs"
	nsid := uint64(4026531840)
	ifindex := uint32(1)
	revision := uint32(1)

	// Get the stable link path
	linkPath := dispatcher.DispatcherLinkPath(bpffsRoot, dispatcher.DispatcherTypeXDP, nsid, ifindex)
	if linkPath != "/run/bpfman/fs/xdp/dispatcher_4026531840_1_link" {
		t.Errorf("unexpected link path: %s", linkPath)
	}

	// Get the revision directory
	revDir := dispatcher.DispatcherRevisionDir(bpffsRoot, dispatcher.DispatcherTypeXDP, nsid, ifindex, revision)
	if revDir != "/run/bpfman/fs/xdp/dispatcher_4026531840_1_1" {
		t.Errorf("unexpected revision dir: %s", revDir)
	}

	// Get the dispatcher program path within the revision
	progPath := dispatcher.DispatcherProgPath(revDir)
	if progPath != "/run/bpfman/fs/xdp/dispatcher_4026531840_1_1/dispatcher" {
		t.Errorf("unexpected prog path: %s", progPath)
	}

	// Get extension link paths for positions 0-2
	expectedExtPaths := []string{
		"/run/bpfman/fs/xdp/dispatcher_4026531840_1_1/link_0",
		"/run/bpfman/fs/xdp/dispatcher_4026531840_1_1/link_1",
		"/run/bpfman/fs/xdp/dispatcher_4026531840_1_1/link_2",
	}
	for pos := 0; pos < 3; pos++ {
		extPath := dispatcher.ExtensionLinkPath(revDir, pos)
		if extPath != expectedExtPaths[pos] {
			t.Errorf("position %d: got %s, want %s", pos, extPath, expectedExtPaths[pos])
		}
	}
}
