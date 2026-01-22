package managed

import "github.com/frobware/go-bpfman/pkg/bpfman"

// ProgramInfo is the concrete implementation of bpfman.ManagedProgramInfo.
// It holds what bpfman tracks about a loaded program.
type ProgramInfo struct {
	name        string
	programType bpfman.ProgramType
	objectPath  string
	pinPath     string
	pinDir      string
}

// NewProgramInfo creates a new ProgramInfo.
func NewProgramInfo(name string, programType bpfman.ProgramType, objectPath, pinPath, pinDir string) *ProgramInfo {
	return &ProgramInfo{
		name:        name,
		programType: programType,
		objectPath:  objectPath,
		pinPath:     pinPath,
		pinDir:      pinDir,
	}
}

func (p *ProgramInfo) Name() string                    { return p.name }
func (p *ProgramInfo) ProgramType() bpfman.ProgramType { return p.programType }
func (p *ProgramInfo) ObjectPath() string              { return p.objectPath }
func (p *ProgramInfo) PinPath() string                 { return p.pinPath }
func (p *ProgramInfo) PinDir() string                  { return p.pinDir }

// Verify interface compliance at compile time.
var _ bpfman.ManagedProgramInfo = (*ProgramInfo)(nil)
