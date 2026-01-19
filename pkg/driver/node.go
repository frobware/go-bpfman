package driver

import (
	"context"
	"os"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// NodePublishVolume bind-mounts the BPF path to the target path.
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

	mapPath := volumeContext["mapPath"]
	if mapPath == "" {
		return nil, status.Error(codes.InvalidArgument, "volumeAttributes.mapPath is required")
	}

	// Verify source path exists
	if _, err := os.Stat(mapPath); err != nil {
		return nil, status.Errorf(codes.NotFound, "mapPath %q does not exist: %v", mapPath, err)
	}

	// Create target directory
	if err := os.MkdirAll(targetPath, 0755); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create target path: %v", err)
	}

	// Bind-mount the BPF path
	flags := uintptr(unix.MS_BIND)
	if readonly {
		flags |= unix.MS_RDONLY
	}

	if err := unix.Mount(mapPath, targetPath, "", flags, ""); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to bind-mount %q to %q: %v", mapPath, targetPath, err)
	}

	d.logger.Info("NodePublishVolume succeeded",
		"method", "Node.NodePublishVolume",
		"volumeID", volumeID,
		"mapPath", mapPath,
		"targetPath", targetPath,
		"readonly", readonly,
	)

	return &csi.NodePublishVolumeResponse{}, nil
}

// NodeUnpublishVolume unmounts the volume from the target path.
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

	// Unmount the bind-mount
	if err := unix.Unmount(targetPath, 0); err != nil {
		// Ignore "not mounted" errors for idempotency
		if err != unix.EINVAL && err != unix.ENOENT {
			return nil, status.Errorf(codes.Internal, "failed to unmount %q: %v", targetPath, err)
		}
	}

	// Remove the target directory
	if err := os.RemoveAll(targetPath); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove target path: %v", err)
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
