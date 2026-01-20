package driver

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CSI volume attribute keys matching upstream Rust bpfman.
const (
	// VolumeAttrProgram specifies the program name to look up.
	// This is matched against the bpfman.io/ProgramName metadata.
	VolumeAttrProgram = "csi.bpfman.io/program"

	// VolumeAttrMaps specifies a comma-separated list of map names to expose.
	VolumeAttrMaps = "csi.bpfman.io/maps"

	// MetadataKeyProgramName is the metadata key used to identify programs.
	MetadataKeyProgramName = "bpfman.io/ProgramName"
)

// NodeGetInfo returns information about this node.
func (d *Driver) NodeGetInfo(ctx context.Context, req *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	d.logger.Debug("NodeGetInfo",
		"method", "Node.NodeGetInfo",
	)

	resp := &csi.NodeGetInfoResponse{
		NodeId: d.nodeID,
	}

	d.logger.Info("NodeGetInfo response",
		"method", "Node.NodeGetInfo",
		"nodeID", resp.NodeId,
	)

	return resp, nil
}

// NodeGetCapabilities returns the capabilities of this node plugin.
func (d *Driver) NodeGetCapabilities(ctx context.Context, req *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	d.logger.Debug("NodeGetCapabilities",
		"method", "Node.NodeGetCapabilities",
	)

	resp := &csi.NodeGetCapabilitiesResponse{
		Capabilities: []*csi.NodeServiceCapability{},
	}

	d.logger.Info("NodeGetCapabilities response",
		"method", "Node.NodeGetCapabilities",
		"capabilities", len(resp.Capabilities),
	)

	return resp, nil
}

// NodePublishVolume mounts BPF maps to the target path.
//
// The driver looks up programs by csi.bpfman.io/program metadata,
// re-pins requested maps to a per-pod bpffs, and bind-mounts
// that bpffs to the container.
func (d *Driver) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	volumeID := req.GetVolumeId()
	targetPath := req.GetTargetPath()
	volumeContext := req.GetVolumeContext()
	readonly := req.GetReadonly()

	d.logger.Info("NodePublishVolume request",
		"method", "Node.NodePublishVolume",
		"volumeID", volumeID,
		"targetPath", targetPath,
		"volumeContext", volumeContext,
		"readonly", readonly,
	)

	if volumeID == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}
	if targetPath == "" {
		return nil, status.Error(codes.InvalidArgument, "target path is required")
	}

	programName := volumeContext[VolumeAttrProgram]
	mapsStr := volumeContext[VolumeAttrMaps]

	if programName == "" || mapsStr == "" {
		return nil, status.Error(codes.InvalidArgument,
			"csi.bpfman.io/program and csi.bpfman.io/maps are required")
	}

	if d.store == nil || d.kernel == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"bpfman integration not configured; store and kernel required")
	}

	// 1. Find program by metadata
	metadata, _, err := d.store.FindProgramByMetadata(ctx, MetadataKeyProgramName, programName)
	if err != nil {
		d.logger.Error("failed to find program",
			"programName", programName,
			"error", err,
		)
		return nil, status.Errorf(codes.NotFound, "program %q not found: %v", programName, err)
	}

	// 2. Get the pin path from the program's LoadSpec
	mapPinPath := metadata.LoadSpec.PinPath
	if mapPinPath == "" {
		return nil, status.Errorf(codes.Internal, "program %q has no pin path", programName)
	}

	d.logger.Info("found program",
		"programName", programName,
		"pinPath", mapPinPath,
	)

	// 3. Create per-pod bpffs directory
	podBpffs := filepath.Join(d.csiFsRoot, volumeID)
	if err := os.MkdirAll(podBpffs, 0750); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create bpffs dir %q: %v", podBpffs, err)
	}

	// 4. Mount bpffs on the per-pod directory
	if err := mountBpffs(podBpffs); err != nil {
		os.RemoveAll(podBpffs)
		return nil, status.Errorf(codes.Internal, "failed to mount bpffs at %q: %v", podBpffs, err)
	}

	// 5. Re-pin each requested map
	mapNames := strings.Split(mapsStr, ",")
	for _, mapName := range mapNames {
		mapName = strings.TrimSpace(mapName)
		if mapName == "" {
			continue
		}

		srcPath := filepath.Join(mapPinPath, mapName)
		dstPath := filepath.Join(podBpffs, mapName)

		d.logger.Debug("re-pinning map",
			"map", mapName,
			"src", srcPath,
			"dst", dstPath,
		)

		if err := d.kernel.RepinMap(srcPath, dstPath); err != nil {
			// Cleanup on failure
			unix.Unmount(podBpffs, 0)
			os.RemoveAll(podBpffs)
			return nil, status.Errorf(codes.Internal, "failed to re-pin map %q: %v", mapName, err)
		}
	}

	// 6. Create target directory and bind-mount
	if err := os.MkdirAll(targetPath, 0755); err != nil {
		unix.Unmount(podBpffs, 0)
		os.RemoveAll(podBpffs)
		return nil, status.Errorf(codes.Internal, "failed to create target path: %v", err)
	}

	flags := uintptr(unix.MS_BIND)
	if readonly {
		flags |= unix.MS_RDONLY
	}

	if err := unix.Mount(podBpffs, targetPath, "", flags, ""); err != nil {
		unix.Unmount(podBpffs, 0)
		os.RemoveAll(podBpffs)
		return nil, status.Errorf(codes.Internal, "failed to bind-mount %q to %q: %v", podBpffs, targetPath, err)
	}

	d.logger.Info("NodePublishVolume succeeded",
		"method", "Node.NodePublishVolume",
		"volumeID", volumeID,
		"programName", programName,
		"maps", mapsStr,
		"podBpffs", podBpffs,
		"targetPath", targetPath,
		"readonly", readonly,
	)

	return &csi.NodePublishVolumeResponse{}, nil
}

// mountBpffs mounts a bpffs filesystem at the given path.
func mountBpffs(path string) error {
	return unix.Mount("bpf", path, "bpf", 0, "")
}

// NodeUnpublishVolume unmounts the volume from the target path.
// It also cleans up the per-pod bpffs.
func (d *Driver) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	volumeID := req.GetVolumeId()
	targetPath := req.GetTargetPath()

	d.logger.Info("NodeUnpublishVolume request",
		"method", "Node.NodeUnpublishVolume",
		"volumeID", volumeID,
		"targetPath", targetPath,
	)

	if volumeID == "" {
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}
	if targetPath == "" {
		return nil, status.Error(codes.InvalidArgument, "target path is required")
	}

	// 1. Unmount the bind-mount from the container
	if err := unix.Unmount(targetPath, 0); err != nil {
		// Ignore "not mounted" errors for idempotency
		if err != unix.EINVAL && err != unix.ENOENT {
			return nil, status.Errorf(codes.Internal, "failed to unmount %q: %v", targetPath, err)
		}
	}

	// 2. Remove the target directory
	if err := os.RemoveAll(targetPath); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove target path: %v", err)
	}

	// 3. Clean up per-pod bpffs
	podBpffs := filepath.Join(d.csiFsRoot, volumeID)
	if _, err := os.Stat(podBpffs); err == nil {
		// Unmount the per-pod bpffs
		if err := unix.Unmount(podBpffs, 0); err != nil {
			// Ignore "not mounted" errors
			if err != unix.EINVAL && err != unix.ENOENT {
				d.logger.Warn("failed to unmount per-pod bpffs",
					"path", podBpffs,
					"error", err,
				)
			}
		}

		// Remove the directory
		if err := os.RemoveAll(podBpffs); err != nil {
			d.logger.Warn("failed to remove per-pod bpffs directory",
				"path", podBpffs,
				"error", err,
			)
		}
	}

	d.logger.Info("NodeUnpublishVolume succeeded",
		"method", "Node.NodeUnpublishVolume",
		"volumeID", volumeID,
		"targetPath", targetPath,
	)

	return &csi.NodeUnpublishVolumeResponse{}, nil
}

// NodeStageVolume is called before NodePublishVolume if staging is advertised.
func (d *Driver) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	d.logger.Warn("NodeStageVolume called but not implemented",
		"method", "Node.NodeStageVolume",
		"volumeID", req.GetVolumeId(),
	)
	return nil, status.Error(codes.Unimplemented, "NodeStageVolume not supported")
}

// NodeUnstageVolume is the counterpart to NodeStageVolume.
func (d *Driver) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	d.logger.Warn("NodeUnstageVolume called but not implemented",
		"method", "Node.NodeUnstageVolume",
		"volumeID", req.GetVolumeId(),
	)
	return nil, status.Error(codes.Unimplemented, "NodeUnstageVolume not supported")
}

// NodeGetVolumeStats returns statistics about a volume.
func (d *Driver) NodeGetVolumeStats(ctx context.Context, req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	d.logger.Warn("NodeGetVolumeStats called but not implemented",
		"method", "Node.NodeGetVolumeStats",
		"volumeID", req.GetVolumeId(),
	)
	return nil, status.Error(codes.Unimplemented, "NodeGetVolumeStats not supported")
}

// NodeExpandVolume expands a volume on the node.
func (d *Driver) NodeExpandVolume(ctx context.Context, req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	d.logger.Warn("NodeExpandVolume called but not implemented",
		"method", "Node.NodeExpandVolume",
		"volumeID", req.GetVolumeId(),
	)
	return nil, status.Error(codes.Unimplemented, "NodeExpandVolume not supported")
}
