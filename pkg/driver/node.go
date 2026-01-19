package driver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/container-storage-interface/spec/lib/go/csi"
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

// NodePublishVolume mounts the volume to the target path.
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
		d.logger.Error("NodePublishVolume failed: volume ID required",
			"method", "Node.NodePublishVolume",
		)
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}
	if targetPath == "" {
		d.logger.Error("NodePublishVolume failed: target path required",
			"method", "Node.NodePublishVolume",
		)
		return nil, status.Error(codes.InvalidArgument, "target path is required")
	}

	d.logger.Debug("creating target directory",
		"method", "Node.NodePublishVolume",
		"targetPath", targetPath,
	)

	if err := os.MkdirAll(targetPath, 0755); err != nil {
		d.logger.Error("NodePublishVolume failed: could not create directory",
			"method", "Node.NodePublishVolume",
			"targetPath", targetPath,
			"error", err,
		)
		return nil, status.Errorf(codes.Internal, "failed to create target path: %v", err)
	}

	markerPath := filepath.Join(targetPath, "csi-volume-info.txt")
	content := fmt.Sprintf("CSI Volume ID: %s\nDriver: %s\nNode: %s\n", volumeID, d.name, d.nodeID)

	d.logger.Debug("writing marker file",
		"method", "Node.NodePublishVolume",
		"markerPath", markerPath,
	)

	if err := os.WriteFile(markerPath, []byte(content), 0644); err != nil {
		d.logger.Error("NodePublishVolume failed: could not write marker",
			"method", "Node.NodePublishVolume",
			"markerPath", markerPath,
			"error", err,
		)
		return nil, status.Errorf(codes.Internal, "failed to write marker file: %v", err)
	}

	d.logger.Info("NodePublishVolume succeeded",
		"method", "Node.NodePublishVolume",
		"volumeID", volumeID,
		"targetPath", targetPath,
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
		d.logger.Error("NodeUnpublishVolume failed: volume ID required",
			"method", "Node.NodeUnpublishVolume",
		)
		return nil, status.Error(codes.InvalidArgument, "volume ID is required")
	}
	if targetPath == "" {
		d.logger.Error("NodeUnpublishVolume failed: target path required",
			"method", "Node.NodeUnpublishVolume",
		)
		return nil, status.Error(codes.InvalidArgument, "target path is required")
	}

	d.logger.Debug("removing target directory",
		"method", "Node.NodeUnpublishVolume",
		"targetPath", targetPath,
	)

	if err := os.RemoveAll(targetPath); err != nil {
		d.logger.Error("NodeUnpublishVolume failed: could not remove directory",
			"method", "Node.NodeUnpublishVolume",
			"targetPath", targetPath,
			"error", err,
		)
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
