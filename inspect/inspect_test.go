package inspect

import (
	"context"
	"errors"
	"iter"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/bpffs"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/kernel"
)

// fakeStore implements StoreLister for testing.
type fakeStore struct {
	programs    map[uint32]bpfman.ProgramRecord
	links       []bpfman.LinkSummary
	linkDetails map[uint32]bpfman.LinkDetails // kernelLinkID -> details
	dispatchers []dispatcher.State
}

func (s *fakeStore) List(ctx context.Context) (map[uint32]bpfman.ProgramRecord, error) {
	return s.programs, nil
}

func (s *fakeStore) Get(ctx context.Context, kernelID uint32) (bpfman.ProgramRecord, error) {
	if p, ok := s.programs[kernelID]; ok {
		return p, nil
	}
	return bpfman.ProgramRecord{}, store.ErrNotFound
}

func (s *fakeStore) ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error) {
	return s.links, nil
}

func (s *fakeStore) GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error) {
	for _, l := range s.links {
		if l.KernelLinkID == kernelLinkID {
			details := s.linkDetails[kernelLinkID]
			return l, details, nil
		}
	}
	return bpfman.LinkSummary{}, nil, store.ErrNotFound
}

func (s *fakeStore) ListDispatchers(ctx context.Context) ([]dispatcher.State, error) {
	return s.dispatchers, nil
}

func (s *fakeStore) GetDispatcher(ctx context.Context, dispType string, nsid uint64, ifindex uint32) (dispatcher.State, error) {
	for _, d := range s.dispatchers {
		if string(d.Type) == dispType && d.Nsid == nsid && d.Ifindex == ifindex {
			return d, nil
		}
	}
	return dispatcher.State{}, store.ErrNotFound
}

// fakeKernelSource implements KernelLister for testing.
type fakeKernelSource struct {
	programs []kernel.Program
	links    []kernel.Link
}

func (k *fakeKernelSource) Programs(ctx context.Context) iter.Seq2[kernel.Program, error] {
	return func(yield func(kernel.Program, error) bool) {
		for _, p := range k.programs {
			if !yield(p, nil) {
				return
			}
		}
	}
}

func (k *fakeKernelSource) GetProgramByID(ctx context.Context, id uint32) (kernel.Program, error) {
	for _, p := range k.programs {
		if p.ID == id {
			return p, nil
		}
	}
	return kernel.Program{}, errors.New("program not found")
}

func (k *fakeKernelSource) Links(ctx context.Context) iter.Seq2[kernel.Link, error] {
	return func(yield func(kernel.Link, error) bool) {
		for _, l := range k.links {
			if !yield(l, nil) {
				return
			}
		}
	}
}

func (k *fakeKernelSource) GetLinkByID(ctx context.Context, id uint32) (kernel.Link, error) {
	for _, l := range k.links {
		if l.ID == id {
			return l, nil
		}
	}
	return kernel.Link{}, errors.New("link not found")
}

func testScannerDirs(t *testing.T) bpffs.ScannerDirs {
	base := t.TempDir()
	return bpffs.ScannerDirs{
		FS:        base,
		XDP:       filepath.Join(base, "xdp"),
		TCIngress: filepath.Join(base, "tc-ingress"),
		TCEgress:  filepath.Join(base, "tc-egress"),
		Maps:      filepath.Join(base, "maps"),
		Links:     filepath.Join(base, "links"),
	}
}

func TestSnapshot_ManagedPrograms(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{
		programs: map[uint32]bpfman.ProgramRecord{
			100: {Name: "xdp_pass", ProgramType: bpfman.ProgramTypeXDP, PinPath: "/run/bpfman/fs/prog_100"},
			200: {Name: "tc_filter", ProgramType: bpfman.ProgramTypeTC, PinPath: "/run/bpfman/fs/prog_200"},
		},
	}

	kern := &fakeKernelSource{
		programs: []kernel.Program{
			{ID: 100},
			{ID: 200},
		},
	}

	w, err := Snapshot(context.Background(), store, kern, scanner)
	require.NoError(t, err)

	managed := w.ManagedPrograms()
	assert.Len(t, managed, 2)

	// Verify all managed programs are in store
	for _, p := range managed {
		assert.True(t, p.Presence.InStore)
		assert.True(t, p.Presence.InKernel)
	}
}

func TestSnapshot_KernelOnlyPrograms(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{
		programs: map[uint32]bpfman.ProgramRecord{
			100: {Name: "managed", ProgramType: bpfman.ProgramTypeXDP},
		},
	}

	kern := &fakeKernelSource{
		programs: []kernel.Program{
			{ID: 100}, // managed
			{ID: 999}, // kernel-only
		},
	}

	w, err := Snapshot(context.Background(), store, kern, scanner)
	require.NoError(t, err)

	// All programs (managed + kernel-only)
	assert.Len(t, w.Programs, 2)

	// Only managed
	managed := w.ManagedPrograms()
	assert.Len(t, managed, 1)
	assert.Equal(t, uint32(100), managed[0].KernelID)

	// Find kernel-only
	var kernelOnly *ProgramRow
	for i := range w.Programs {
		if w.Programs[i].Presence.KernelOnly() {
			kernelOnly = &w.Programs[i]
			break
		}
	}
	require.NotNil(t, kernelOnly)
	assert.Equal(t, uint32(999), kernelOnly.KernelID)
	assert.False(t, kernelOnly.Presence.InStore)
	assert.True(t, kernelOnly.Presence.InKernel)
}

func TestSnapshot_FSOnlyPrograms(t *testing.T) {
	dirs := testScannerDirs(t)

	// Create an orphan prog pin on FS
	require.NoError(t, os.WriteFile(filepath.Join(dirs.FS, "prog_888"), nil, 0644))

	scanner := bpffs.NewScanner(dirs)
	store := &fakeStore{programs: map[uint32]bpfman.ProgramRecord{}}
	kern := &fakeKernelSource{}

	w, err := Snapshot(context.Background(), store, kern, scanner)
	require.NoError(t, err)

	assert.Len(t, w.Programs, 1)
	assert.Equal(t, uint32(888), w.Programs[0].KernelID)
	assert.True(t, w.Programs[0].Presence.OrphanFS())
	assert.False(t, w.Programs[0].Presence.InStore)
	assert.False(t, w.Programs[0].Presence.InKernel)
	assert.True(t, w.Programs[0].Presence.InFS)
}

func TestSnapshot_Links(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{
		links: []bpfman.LinkSummary{
			{KernelLinkID: 10, KernelProgramID: 100, LinkType: "xdp"},
			{KernelLinkID: 20, KernelProgramID: 200, LinkType: "kprobe"},
		},
	}

	kern := &fakeKernelSource{
		links: []kernel.Link{
			{ID: 10},
			{ID: 20},
			{ID: 999}, // kernel-only link
		},
	}

	w, err := Snapshot(context.Background(), store, kern, scanner)
	require.NoError(t, err)

	assert.Len(t, w.Links, 3)

	managed := w.ManagedLinks()
	assert.Len(t, managed, 2)

	// Check kernel-only link
	var kernelOnly *LinkRow
	for i := range w.Links {
		if w.Links[i].Presence.KernelOnly() {
			kernelOnly = &w.Links[i]
			break
		}
	}
	require.NotNil(t, kernelOnly)
	assert.Equal(t, uint32(999), kernelOnly.KernelLinkID)
}

func TestSnapshot_Dispatchers(t *testing.T) {
	dirs := testScannerDirs(t)
	require.NoError(t, os.MkdirAll(dirs.XDP, 0755))

	// Create dispatcher dir on FS
	dispDir := filepath.Join(dirs.XDP, "dispatcher_1_1_5")
	require.NoError(t, os.Mkdir(dispDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dispDir, "link_0"), nil, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dispDir, "link_1"), nil, 0644))

	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{
		dispatchers: []dispatcher.State{
			{
				Type:     dispatcher.DispatcherTypeXDP,
				Nsid:     1,
				Ifindex:  1,
				Revision: 5,
				KernelID: 500,
				LinkID:   50,
			},
		},
	}

	kern := &fakeKernelSource{
		programs: []kernel.Program{{ID: 500}},
		links:    []kernel.Link{{ID: 50}},
	}

	w, err := Snapshot(context.Background(), store, kern, scanner)
	require.NoError(t, err)

	assert.Len(t, w.Dispatchers, 1)

	d := w.Dispatchers[0]
	assert.Equal(t, "xdp", d.DispType)
	assert.Equal(t, uint64(1), d.Nsid)
	assert.Equal(t, uint32(1), d.Ifindex)
	assert.Equal(t, uint32(5), d.Revision)
	assert.Equal(t, 2, d.FSLinkCount)
	assert.True(t, d.ProgPresence.InStore)
	assert.True(t, d.ProgPresence.InKernel)
	assert.True(t, d.ProgPresence.InFS)
}

func TestSnapshot_OrphanDispatcher(t *testing.T) {
	dirs := testScannerDirs(t)
	require.NoError(t, os.MkdirAll(dirs.XDP, 0755))

	// Create orphan dispatcher dir on FS (not in store)
	dispDir := filepath.Join(dirs.XDP, "dispatcher_99_2_1")
	require.NoError(t, os.Mkdir(dispDir, 0755))

	scanner := bpffs.NewScanner(dirs)
	store := &fakeStore{}
	kern := &fakeKernelSource{}

	w, err := Snapshot(context.Background(), store, kern, scanner)
	require.NoError(t, err)

	assert.Len(t, w.Dispatchers, 1)

	d := w.Dispatchers[0]
	assert.Equal(t, "xdp", d.DispType)
	assert.Equal(t, uint64(99), d.Nsid)
	assert.Equal(t, uint32(2), d.Ifindex)
	assert.False(t, d.ProgPresence.InStore)
	assert.False(t, d.ProgPresence.InKernel)
	assert.True(t, d.ProgPresence.InFS)
}

func TestPresence_Methods(t *testing.T) {
	tests := []struct {
		name       string
		p          Presence
		managed    bool
		orphanFS   bool
		kernelOnly bool
	}{
		{
			name:       "in store only",
			p:          Presence{InStore: true, InKernel: false, InFS: false},
			managed:    true,
			orphanFS:   false,
			kernelOnly: false,
		},
		{
			name:       "fully present",
			p:          Presence{InStore: true, InKernel: true, InFS: true},
			managed:    true,
			orphanFS:   false,
			kernelOnly: false,
		},
		{
			name:       "kernel only",
			p:          Presence{InStore: false, InKernel: true, InFS: false},
			managed:    false,
			orphanFS:   false,
			kernelOnly: true,
		},
		{
			name:       "kernel and fs, not store",
			p:          Presence{InStore: false, InKernel: true, InFS: true},
			managed:    false,
			orphanFS:   false,
			kernelOnly: true,
		},
		{
			name:       "fs only (orphan)",
			p:          Presence{InStore: false, InKernel: false, InFS: true},
			managed:    false,
			orphanFS:   true,
			kernelOnly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.managed, tt.p.Managed())
			assert.Equal(t, tt.orphanFS, tt.p.OrphanFS())
			assert.Equal(t, tt.kernelOnly, tt.p.KernelOnly())
		})
	}
}

func TestGetProgram_FullyPresent(t *testing.T) {
	dirs := testScannerDirs(t)

	// Create a pin file on FS
	pinPath := filepath.Join(dirs.FS, "prog_100")
	require.NoError(t, os.WriteFile(pinPath, nil, 0644))

	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{
		programs: map[uint32]bpfman.ProgramRecord{
			100: {Name: "xdp_pass", ProgramType: bpfman.ProgramTypeXDP, PinPath: pinPath},
		},
	}

	kern := &fakeKernelSource{
		programs: []kernel.Program{{ID: 100, Name: "xdp_pass"}},
	}

	row, err := GetProgram(context.Background(), store, kern, scanner, 100)
	require.NoError(t, err)

	assert.Equal(t, uint32(100), row.KernelID)
	assert.True(t, row.Presence.InStore)
	assert.True(t, row.Presence.InKernel)
	assert.True(t, row.Presence.InFS)
	assert.NotNil(t, row.Managed)
	assert.NotNil(t, row.Kernel)
	assert.Equal(t, "xdp_pass", row.Managed.Name)
	assert.Equal(t, "xdp_pass", row.Kernel.Name)
}

func TestGetProgram_StoreOnly(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{
		programs: map[uint32]bpfman.ProgramRecord{
			100: {Name: "stale_prog", ProgramType: bpfman.ProgramTypeXDP},
		},
	}

	kern := &fakeKernelSource{} // Program not in kernel

	row, err := GetProgram(context.Background(), store, kern, scanner, 100)
	require.NoError(t, err)

	assert.Equal(t, uint32(100), row.KernelID)
	assert.True(t, row.Presence.InStore)
	assert.False(t, row.Presence.InKernel)
	assert.False(t, row.Presence.InFS)
	assert.NotNil(t, row.Managed)
	assert.Nil(t, row.Kernel)
}

func TestGetProgram_KernelOnly(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{programs: map[uint32]bpfman.ProgramRecord{}} // Not in store

	kern := &fakeKernelSource{
		programs: []kernel.Program{{ID: 999, Name: "unmanaged"}},
	}

	row, err := GetProgram(context.Background(), store, kern, scanner, 999)
	require.NoError(t, err)

	assert.Equal(t, uint32(999), row.KernelID)
	assert.False(t, row.Presence.InStore)
	assert.True(t, row.Presence.InKernel)
	assert.False(t, row.Presence.InFS)
	assert.Nil(t, row.Managed)
	assert.NotNil(t, row.Kernel)
	assert.Equal(t, "unmanaged", row.Kernel.Name)
}

func TestGetProgram_NotFound(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{programs: map[uint32]bpfman.ProgramRecord{}}
	kern := &fakeKernelSource{}

	_, err := GetProgram(context.Background(), store, kern, scanner, 12345)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestGetLink_FullyPresent(t *testing.T) {
	dirs := testScannerDirs(t)

	// Create a pin file on FS
	pinPath := filepath.Join(dirs.Links, "100", "link_10")
	require.NoError(t, os.MkdirAll(filepath.Dir(pinPath), 0755))
	require.NoError(t, os.WriteFile(pinPath, nil, 0644))

	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{
		links: []bpfman.LinkSummary{
			{KernelLinkID: 10, KernelProgramID: 100, LinkType: "kprobe", PinPath: pinPath},
		},
		linkDetails: map[uint32]bpfman.LinkDetails{
			10: bpfman.KprobeDetails{FnName: "do_sys_open"},
		},
	}

	kern := &fakeKernelSource{
		links: []kernel.Link{{ID: 10}},
	}

	info, err := GetLink(context.Background(), store, kern, scanner, 10)
	require.NoError(t, err)

	assert.Equal(t, uint32(10), info.Summary.KernelLinkID)
	assert.Equal(t, uint32(100), info.Summary.KernelProgramID)
	assert.True(t, info.Presence.InStore)
	assert.True(t, info.Presence.InKernel)
	assert.True(t, info.Presence.InFS)
	assert.NotNil(t, info.Details)
}

func TestGetLink_StoreOnly(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{
		links: []bpfman.LinkSummary{
			{KernelLinkID: 20, KernelProgramID: 200, LinkType: "tracepoint"},
		},
	}

	kern := &fakeKernelSource{} // Link not in kernel

	info, err := GetLink(context.Background(), store, kern, scanner, 20)
	require.NoError(t, err)

	assert.Equal(t, uint32(20), info.Summary.KernelLinkID)
	assert.True(t, info.Presence.InStore)
	assert.False(t, info.Presence.InKernel)
	assert.False(t, info.Presence.InFS)
}

func TestGetLink_KernelOnly(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{} // Not in store

	kern := &fakeKernelSource{
		links: []kernel.Link{{ID: 999}},
	}

	info, err := GetLink(context.Background(), store, kern, scanner, 999)
	require.NoError(t, err)

	assert.False(t, info.Presence.InStore)
	assert.True(t, info.Presence.InKernel)
	assert.False(t, info.Presence.InFS)
}

func TestGetLink_NotFound(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{}
	kern := &fakeKernelSource{}

	_, err := GetLink(context.Background(), store, kern, scanner, 12345)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestGetDispatcher_FullyPresent(t *testing.T) {
	dirs := testScannerDirs(t)
	require.NoError(t, os.MkdirAll(dirs.XDP, 0755))

	// Create dispatcher dir on FS
	dispDir := filepath.Join(dirs.XDP, "dispatcher_1_2_5")
	require.NoError(t, os.Mkdir(dispDir, 0755))

	// Create dispatcher link pin
	linkPin := filepath.Join(dirs.XDP, "dispatcher_1_2_link")
	require.NoError(t, os.WriteFile(linkPin, nil, 0644))

	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{
		dispatchers: []dispatcher.State{
			{
				Type:     dispatcher.DispatcherTypeXDP,
				Nsid:     1,
				Ifindex:  2,
				Revision: 5,
				KernelID: 500,
				LinkID:   50,
			},
		},
	}

	kern := &fakeKernelSource{
		programs: []kernel.Program{{ID: 500}},
		links:    []kernel.Link{{ID: 50}},
	}

	info, err := GetDispatcher(context.Background(), store, kern, kern, scanner, "xdp", 1, 2)
	require.NoError(t, err)

	assert.Equal(t, uint32(500), info.State.KernelID)
	assert.Equal(t, uint32(50), info.State.LinkID)
	assert.True(t, info.ProgPresence.InStore)
	assert.True(t, info.ProgPresence.InKernel)
	assert.True(t, info.ProgPresence.InFS)
	assert.True(t, info.LinkPresence.InStore)
	assert.True(t, info.LinkPresence.InKernel)
	assert.True(t, info.LinkPresence.InFS)
}

func TestGetDispatcher_StoreOnly(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{
		dispatchers: []dispatcher.State{
			{
				Type:     dispatcher.DispatcherTypeXDP,
				Nsid:     1,
				Ifindex:  2,
				Revision: 3,
				KernelID: 500,
			},
		},
	}

	kern := &fakeKernelSource{} // Not in kernel

	info, err := GetDispatcher(context.Background(), store, kern, kern, scanner, "xdp", 1, 2)
	require.NoError(t, err)

	assert.True(t, info.ProgPresence.InStore)
	assert.False(t, info.ProgPresence.InKernel)
	assert.False(t, info.ProgPresence.InFS)
}

func TestGetDispatcher_NotFound(t *testing.T) {
	dirs := testScannerDirs(t)
	scanner := bpffs.NewScanner(dirs)

	store := &fakeStore{}
	kern := &fakeKernelSource{}

	_, err := GetDispatcher(context.Background(), store, kern, kern, scanner, "xdp", 99, 99)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}
