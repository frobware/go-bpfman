package bpffs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDirs(t *testing.T) ScannerDirs {
	base := t.TempDir()
	return ScannerDirs{
		FS:        base,
		XDP:       filepath.Join(base, "xdp"),
		TCIngress: filepath.Join(base, "tc-ingress"),
		TCEgress:  filepath.Join(base, "tc-egress"),
		Maps:      filepath.Join(base, "maps"),
		Links:     filepath.Join(base, "links"),
	}
}

func TestScanner_ProgPins(t *testing.T) {
	dirs := testDirs(t)

	// Create prog pins
	require.NoError(t, os.WriteFile(filepath.Join(dirs.FS, "prog_123"), nil, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dirs.FS, "prog_456"), nil, 0644))
	// Create non-prog files (should be ignored)
	require.NoError(t, os.WriteFile(filepath.Join(dirs.FS, "other_file"), nil, 0644))

	scanner := NewScanner(dirs)

	var pins []ProgPin
	for pin, err := range scanner.ProgPins(context.Background()) {
		require.NoError(t, err)
		pins = append(pins, pin)
	}

	assert.Len(t, pins, 2)
	assert.Contains(t, pins, ProgPin{Path: filepath.Join(dirs.FS, "prog_123"), KernelID: 123})
	assert.Contains(t, pins, ProgPin{Path: filepath.Join(dirs.FS, "prog_456"), KernelID: 456})
}

func TestScanner_ProgPins_EmptyDir(t *testing.T) {
	dirs := testDirs(t)
	scanner := NewScanner(dirs)

	var pins []ProgPin
	for pin, err := range scanner.ProgPins(context.Background()) {
		require.NoError(t, err)
		pins = append(pins, pin)
	}

	assert.Empty(t, pins)
}

func TestScanner_ProgPins_MalformedSkipped(t *testing.T) {
	dirs := testDirs(t)

	// Create valid and malformed pins
	require.NoError(t, os.WriteFile(filepath.Join(dirs.FS, "prog_123"), nil, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dirs.FS, "prog_notanumber"), nil, 0644))

	var malformed []string
	scanner := NewScanner(dirs).WithOnMalformed(func(path string, err error) {
		malformed = append(malformed, path)
	})

	var pins []ProgPin
	for pin, err := range scanner.ProgPins(context.Background()) {
		require.NoError(t, err)
		pins = append(pins, pin)
	}

	assert.Len(t, pins, 1)
	assert.Equal(t, uint32(123), pins[0].KernelID)
	assert.Len(t, malformed, 1)
	assert.Contains(t, malformed[0], "prog_notanumber")
}

func TestScanner_LinkDirs(t *testing.T) {
	dirs := testDirs(t)
	require.NoError(t, os.MkdirAll(dirs.Links, 0755))

	// Create link directories
	require.NoError(t, os.Mkdir(filepath.Join(dirs.Links, "100"), 0755))
	require.NoError(t, os.Mkdir(filepath.Join(dirs.Links, "200"), 0755))
	// Create a file (should be ignored, only dirs count)
	require.NoError(t, os.WriteFile(filepath.Join(dirs.Links, "300"), nil, 0644))

	scanner := NewScanner(dirs)

	var linkDirs []LinkDir
	for dir, err := range scanner.LinkDirs(context.Background()) {
		require.NoError(t, err)
		linkDirs = append(linkDirs, dir)
	}

	assert.Len(t, linkDirs, 2)
	assert.Contains(t, linkDirs, LinkDir{Path: filepath.Join(dirs.Links, "100"), ProgramID: 100})
	assert.Contains(t, linkDirs, LinkDir{Path: filepath.Join(dirs.Links, "200"), ProgramID: 200})
}

func TestScanner_MapDirs(t *testing.T) {
	dirs := testDirs(t)
	require.NoError(t, os.MkdirAll(dirs.Maps, 0755))

	// Create map directories
	require.NoError(t, os.Mkdir(filepath.Join(dirs.Maps, "500"), 0755))
	require.NoError(t, os.Mkdir(filepath.Join(dirs.Maps, "600"), 0755))

	scanner := NewScanner(dirs)

	var mapDirs []MapDir
	for dir, err := range scanner.MapDirs(context.Background()) {
		require.NoError(t, err)
		mapDirs = append(mapDirs, dir)
	}

	assert.Len(t, mapDirs, 2)
	assert.Contains(t, mapDirs, MapDir{Path: filepath.Join(dirs.Maps, "500"), ProgramID: 500})
	assert.Contains(t, mapDirs, MapDir{Path: filepath.Join(dirs.Maps, "600"), ProgramID: 600})
}

func TestScanner_DispatcherDirs(t *testing.T) {
	dirs := testDirs(t)
	require.NoError(t, os.MkdirAll(dirs.XDP, 0755))
	require.NoError(t, os.MkdirAll(dirs.TCIngress, 0755))

	// Create XDP dispatcher directory with link files
	xdpDir := filepath.Join(dirs.XDP, "dispatcher_4026531840_1_5")
	require.NoError(t, os.Mkdir(xdpDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(xdpDir, "dispatcher"), nil, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(xdpDir, "link_0"), nil, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(xdpDir, "link_1"), nil, 0644))

	// Create TC ingress dispatcher directory
	tcDir := filepath.Join(dirs.TCIngress, "dispatcher_4026531840_2_1")
	require.NoError(t, os.Mkdir(tcDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tcDir, "dispatcher"), nil, 0644))

	scanner := NewScanner(dirs)

	var dispDirs []DispatcherDir
	for dir, err := range scanner.DispatcherDirs(context.Background()) {
		require.NoError(t, err)
		dispDirs = append(dispDirs, dir)
	}

	assert.Len(t, dispDirs, 2)

	// Find XDP dispatcher
	var xdpDisp *DispatcherDir
	for i := range dispDirs {
		if dispDirs[i].DispType == "xdp" {
			xdpDisp = &dispDirs[i]
			break
		}
	}
	require.NotNil(t, xdpDisp)
	assert.Equal(t, uint64(4026531840), xdpDisp.Nsid)
	assert.Equal(t, uint32(1), xdpDisp.Ifindex)
	assert.Equal(t, uint32(5), xdpDisp.Revision)
	assert.Equal(t, 2, xdpDisp.LinkCount)

	// Find TC dispatcher
	var tcDisp *DispatcherDir
	for i := range dispDirs {
		if dispDirs[i].DispType == "tc-ingress" {
			tcDisp = &dispDirs[i]
			break
		}
	}
	require.NotNil(t, tcDisp)
	assert.Equal(t, uint64(4026531840), tcDisp.Nsid)
	assert.Equal(t, uint32(2), tcDisp.Ifindex)
	assert.Equal(t, uint32(1), tcDisp.Revision)
	assert.Equal(t, 0, tcDisp.LinkCount)
}

func TestScanner_DispatcherLinkPins(t *testing.T) {
	dirs := testDirs(t)
	require.NoError(t, os.MkdirAll(dirs.XDP, 0755))

	// Create dispatcher link pin
	require.NoError(t, os.WriteFile(filepath.Join(dirs.XDP, "dispatcher_4026531840_1_link"), nil, 0644))

	scanner := NewScanner(dirs)

	var linkPins []DispatcherLinkPin
	for pin, err := range scanner.DispatcherLinkPins(context.Background()) {
		require.NoError(t, err)
		linkPins = append(linkPins, pin)
	}

	assert.Len(t, linkPins, 1)
	assert.Equal(t, "xdp", linkPins[0].DispType)
	assert.Equal(t, uint64(4026531840), linkPins[0].Nsid)
	assert.Equal(t, uint32(1), linkPins[0].Ifindex)
}

func TestScanner_PathExists(t *testing.T) {
	dirs := testDirs(t)
	scanner := NewScanner(dirs)

	existingPath := filepath.Join(dirs.FS, "exists")
	require.NoError(t, os.WriteFile(existingPath, nil, 0644))

	assert.True(t, scanner.PathExists(existingPath))
	assert.False(t, scanner.PathExists(filepath.Join(dirs.FS, "doesnotexist")))
}

func TestScanner_Scan(t *testing.T) {
	dirs := testDirs(t)
	require.NoError(t, os.MkdirAll(dirs.Links, 0755))
	require.NoError(t, os.MkdirAll(dirs.Maps, 0755))
	require.NoError(t, os.MkdirAll(dirs.XDP, 0755))

	// Create various entries
	require.NoError(t, os.WriteFile(filepath.Join(dirs.FS, "prog_100"), nil, 0644))
	require.NoError(t, os.Mkdir(filepath.Join(dirs.Links, "100"), 0755))
	require.NoError(t, os.Mkdir(filepath.Join(dirs.Maps, "100"), 0755))

	xdpDir := filepath.Join(dirs.XDP, "dispatcher_1_1_1")
	require.NoError(t, os.Mkdir(xdpDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dirs.XDP, "dispatcher_1_1_link"), nil, 0644))

	scanner := NewScanner(dirs)
	state, err := scanner.Scan(context.Background())
	require.NoError(t, err)

	assert.Len(t, state.ProgPins, 1)
	assert.Len(t, state.LinkDirs, 1)
	assert.Len(t, state.MapDirs, 1)
	assert.Len(t, state.DispatcherDirs, 1)
	assert.Len(t, state.DispatcherLinkPins, 1)
}

func TestScanner_ContextCancellation(t *testing.T) {
	dirs := testDirs(t)

	// Create many prog pins
	for i := range 100 {
		require.NoError(t, os.WriteFile(filepath.Join(dirs.FS, "prog_"+string(rune('0'+i%10))+string(rune('0'+i/10))), nil, 0644))
	}

	scanner := NewScanner(dirs)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	var pins []ProgPin
	var gotErr error
	for pin, err := range scanner.ProgPins(ctx) {
		if err != nil {
			gotErr = err
			break
		}
		pins = append(pins, pin)
	}

	// Should get context error
	assert.ErrorIs(t, gotErr, context.Canceled)
}
