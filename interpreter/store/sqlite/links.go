package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	bpfman "github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/interpreter/store"
)

// ----------------------------------------------------------------------------
// Link Registry Operations
// ----------------------------------------------------------------------------

// DeleteLink removes link metadata by kernel link ID.
// Due to CASCADE, this also removes the corresponding detail table entry.
func (s *sqliteStore) DeleteLink(ctx context.Context, kernelLinkID uint32) error {
	start := time.Now()
	result, err := s.stmtDeleteLink.ExecContext(ctx, kernelLinkID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "DeleteLink", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to delete link: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	s.logger.Debug("sql", "stmt", "DeleteLink", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)
	if rows == 0 {
		return fmt.Errorf("link %d: %w", kernelLinkID, store.ErrNotFound)
	}

	return nil
}

// GetLink retrieves link metadata by kernel link ID using two-phase lookup.
func (s *sqliteStore) GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error) {
	// Phase 1: Get summary from registry
	start := time.Now()
	row := s.stmtGetLinkRegistry.QueryRowContext(ctx, kernelLinkID)

	summary, err := s.scanLinkSummary(row)
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetLinkRegistry", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.LinkSummary{}, nil, err
	}
	s.logger.Debug("sql", "stmt", "GetLinkRegistry", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)

	// Phase 2: Get details based on link type
	details, err := s.getLinkDetails(ctx, summary.LinkType, kernelLinkID)
	if err != nil {
		return bpfman.LinkSummary{}, nil, err
	}

	return summary, details, nil
}

// ListLinks returns all links (summary only).
func (s *sqliteStore) ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error) {
	start := time.Now()
	rows, err := s.stmtListLinks.QueryContext(ctx)
	if err != nil {
		s.logger.Debug("sql", "stmt", "ListLinks", "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	result, err := s.scanLinkSummaries(rows)
	if err != nil {
		return nil, err
	}
	s.logger.Debug("sql", "stmt", "ListLinks", "duration_ms", msec(time.Since(start)), "rows", len(result))
	return result, nil
}

// ListLinksByProgram returns all links for a given program kernel ID.
func (s *sqliteStore) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]bpfman.LinkSummary, error) {
	start := time.Now()
	rows, err := s.stmtListLinksByProgram.QueryContext(ctx, programKernelID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "ListLinksByProgram", "args", []any{programKernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	result, err := s.scanLinkSummaries(rows)
	if err != nil {
		return nil, err
	}
	s.logger.Debug("sql", "stmt", "ListLinksByProgram", "args", []any{programKernelID}, "duration_ms", msec(time.Since(start)), "rows", len(result))
	return result, nil
}

// ListTCXLinksByInterface returns all TCX links for a given interface/direction/namespace.
// Used for computing attach order based on priority.
func (s *sqliteStore) ListTCXLinksByInterface(ctx context.Context, nsid uint64, ifindex uint32, direction string) ([]bpfman.TCXLinkInfo, error) {
	start := time.Now()
	rows, err := s.stmtListTCXLinksByInterface.QueryContext(ctx, nsid, ifindex, direction)
	if err != nil {
		s.logger.Debug("sql", "stmt", "ListTCXLinksByInterface", "args", []any{nsid, ifindex, direction}, "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	result := make([]bpfman.TCXLinkInfo, 0)
	for rows.Next() {
		var info bpfman.TCXLinkInfo
		if err := rows.Scan(&info.KernelLinkID, &info.KernelProgramID, &info.Priority); err != nil {
			return nil, fmt.Errorf("scan TCX link info: %w", err)
		}
		result = append(result, info)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate TCX links: %w", err)
	}
	s.logger.Debug("sql", "stmt", "ListTCXLinksByInterface", "args", []any{nsid, ifindex, direction}, "duration_ms", msec(time.Since(start)), "rows", len(result))
	return result, nil
}

// ----------------------------------------------------------------------------
// Type-Specific Link Save Methods
// ----------------------------------------------------------------------------

// SaveTracepointLink saves a tracepoint link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveTracepointLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.TracepointDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	start := time.Now()
	_, err := s.stmtSaveTracepointDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Group, details.Name)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveTracepointDetails", "args", []any{summary.KernelLinkID, details.Group, details.Name}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert tracepoint details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveTracepointDetails", "args", []any{summary.KernelLinkID, details.Group, details.Name}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveKprobeLink saves a kprobe/kretprobe link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveKprobeLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.KprobeDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	retprobe := 0
	if details.Retprobe {
		retprobe = 1
	}

	start := time.Now()
	_, err := s.stmtSaveKprobeDetails.ExecContext(ctx,
		summary.KernelLinkID, details.FnName, details.Offset, retprobe)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveKprobeDetails", "args", []any{summary.KernelLinkID, details.FnName, details.Offset, retprobe}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert kprobe details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveKprobeDetails", "args", []any{summary.KernelLinkID, details.FnName, details.Offset, retprobe}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveUprobeLink saves a uprobe/uretprobe link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveUprobeLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.UprobeDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	retprobe := 0
	if details.Retprobe {
		retprobe = 1
	}

	start := time.Now()
	_, err := s.stmtSaveUprobeDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Target, details.FnName, details.Offset, details.PID, retprobe)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveUprobeDetails", "args", []any{summary.KernelLinkID, details.Target, details.FnName, details.Offset, details.PID, retprobe}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert uprobe details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveUprobeDetails", "args", []any{summary.KernelLinkID, details.Target, details.FnName, details.Offset, details.PID, retprobe}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveFentryLink saves a fentry link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveFentryLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.FentryDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	start := time.Now()
	_, err := s.stmtSaveFentryDetails.ExecContext(ctx, summary.KernelLinkID, details.FnName)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveFentryDetails", "args", []any{summary.KernelLinkID, details.FnName}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert fentry details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveFentryDetails", "args", []any{summary.KernelLinkID, details.FnName}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveFexitLink saves a fexit link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveFexitLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.FexitDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	start := time.Now()
	_, err := s.stmtSaveFexitDetails.ExecContext(ctx, summary.KernelLinkID, details.FnName)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveFexitDetails", "args", []any{summary.KernelLinkID, details.FnName}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert fexit details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveFexitDetails", "args", []any{summary.KernelLinkID, details.FnName}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveXDPLink saves an XDP link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveXDPLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.XDPDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	proceedOnJSON, err := json.Marshal(details.ProceedOn)
	if err != nil {
		return fmt.Errorf("failed to marshal proceed_on: %w", err)
	}

	start := time.Now()
	_, err = s.stmtSaveXDPDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Interface, details.Ifindex, details.Priority, details.Position,
		string(proceedOnJSON), details.Netns, details.Nsid, details.DispatcherID, details.Revision)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveXDPDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Priority, details.Position, "(proceed_on)", details.Netns, details.Nsid, details.DispatcherID, details.Revision}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert xdp details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveXDPDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Priority, details.Position, "(proceed_on)", details.Netns, details.Nsid, details.DispatcherID, details.Revision}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveTCLink saves a TC link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveTCLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.TCDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	proceedOnJSON, err := json.Marshal(details.ProceedOn)
	if err != nil {
		return fmt.Errorf("failed to marshal proceed_on: %w", err)
	}

	start := time.Now()
	_, err = s.stmtSaveTCDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Position,
		string(proceedOnJSON), details.Netns, details.Nsid, details.DispatcherID, details.Revision)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveTCDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Position, "(proceed_on)", details.Netns, details.Nsid, details.DispatcherID, details.Revision}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert tc details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveTCDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Position, "(proceed_on)", details.Netns, details.Nsid, details.DispatcherID, details.Revision}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveTCXLink saves a TCX link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveTCXLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.TCXDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	start := time.Now()
	_, err := s.stmtSaveTCXDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Netns, details.Nsid)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveTCXDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Netns, details.Nsid}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert tcx details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveTCXDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Netns, details.Nsid}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

// insertLinkRegistry inserts a record into the link_registry table.
func (s *sqliteStore) insertLinkRegistry(ctx context.Context, summary bpfman.LinkSummary) error {
	start := time.Now()
	_, err := s.stmtInsertLinkRegistry.ExecContext(ctx,
		summary.KernelLinkID, string(summary.LinkType), summary.KernelProgramID,
		summary.PinPath, summary.CreatedAt.Format(time.RFC3339))
	if err != nil {
		s.logger.Debug("sql", "stmt", "InsertLinkRegistry", "args", []any{summary.KernelLinkID, summary.LinkType, summary.KernelProgramID, summary.PinPath, "(timestamp)"}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert link registry: %w", err)
	}
	s.logger.Debug("sql", "stmt", "InsertLinkRegistry", "args", []any{summary.KernelLinkID, summary.LinkType, summary.KernelProgramID, summary.PinPath, "(timestamp)"}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)
	return nil
}

// scanLinkSummary scans a single row into a LinkSummary.
func (s *sqliteStore) scanLinkSummary(row *sql.Row) (bpfman.LinkSummary, error) {
	var summary bpfman.LinkSummary
	var linkType string
	var pinPath sql.NullString
	var createdAtStr string

	err := row.Scan(&summary.KernelLinkID, &linkType, &summary.KernelProgramID, &pinPath, &createdAtStr)
	if err == sql.ErrNoRows {
		return bpfman.LinkSummary{}, fmt.Errorf("link: %w", store.ErrNotFound)
	}
	if err != nil {
		return bpfman.LinkSummary{}, err
	}

	summary.LinkType = bpfman.LinkType(linkType)
	if pinPath.Valid {
		summary.PinPath = pinPath.String
	}
	createdAt, err := time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("invalid created_at timestamp for link %d: %q: %w", summary.KernelLinkID, createdAtStr, err)
	}
	summary.CreatedAt = createdAt

	return summary, nil
}

// scanLinkSummaries scans multiple rows into a slice of LinkSummary.
func (s *sqliteStore) scanLinkSummaries(rows *sql.Rows) ([]bpfman.LinkSummary, error) {
	var result []bpfman.LinkSummary

	for rows.Next() {
		var summary bpfman.LinkSummary
		var linkType string
		var pinPath sql.NullString
		var createdAtStr string

		err := rows.Scan(&summary.KernelLinkID, &linkType, &summary.KernelProgramID, &pinPath, &createdAtStr)
		if err != nil {
			return nil, err
		}

		summary.LinkType = bpfman.LinkType(linkType)
		if pinPath.Valid {
			summary.PinPath = pinPath.String
		}
		createdAt, err := time.Parse(time.RFC3339, createdAtStr)
		if err != nil {
			return nil, fmt.Errorf("invalid created_at timestamp for link %d: %q: %w", summary.KernelLinkID, createdAtStr, err)
		}
		summary.CreatedAt = createdAt

		result = append(result, summary)
	}

	return result, rows.Err()
}

// getLinkDetails retrieves the type-specific details for a link.
func (s *sqliteStore) getLinkDetails(ctx context.Context, linkType bpfman.LinkType, kernelLinkID uint32) (bpfman.LinkDetails, error) {
	switch linkType {
	case bpfman.LinkTypeTracepoint:
		return s.getTracepointDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeKprobe, bpfman.LinkTypeKretprobe:
		return s.getKprobeDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeUprobe, bpfman.LinkTypeUretprobe:
		return s.getUprobeDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeFentry:
		return s.getFentryDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeFexit:
		return s.getFexitDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeXDP:
		return s.getXDPDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeTC:
		return s.getTCDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeTCX:
		return s.getTCXDetails(ctx, kernelLinkID)
	default:
		return nil, fmt.Errorf("unknown link type: %s", linkType)
	}
}

func (s *sqliteStore) getTracepointDetails(ctx context.Context, kernelLinkID uint32) (bpfman.TracepointDetails, error) {
	start := time.Now()
	row := s.stmtGetTracepointDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.TracepointDetails
	err := row.Scan(&details.Group, &details.Name)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetTracepointDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.TracepointDetails{}, fmt.Errorf("tracepoint details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetTracepointDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.TracepointDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetTracepointDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)
	return details, nil
}

func (s *sqliteStore) getKprobeDetails(ctx context.Context, kernelLinkID uint32) (bpfman.KprobeDetails, error) {
	start := time.Now()
	row := s.stmtGetKprobeDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.KprobeDetails
	var retprobe int
	err := row.Scan(&details.FnName, &details.Offset, &retprobe)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetKprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.KprobeDetails{}, fmt.Errorf("kprobe details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetKprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.KprobeDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetKprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)
	details.Retprobe = retprobe == 1
	return details, nil
}

func (s *sqliteStore) getUprobeDetails(ctx context.Context, kernelLinkID uint32) (bpfman.UprobeDetails, error) {
	start := time.Now()
	row := s.stmtGetUprobeDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.UprobeDetails
	var fnName sql.NullString
	var pid sql.NullInt64
	var retprobe int
	err := row.Scan(&details.Target, &fnName, &details.Offset, &pid, &retprobe)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetUprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.UprobeDetails{}, fmt.Errorf("uprobe details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetUprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.UprobeDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetUprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)
	if fnName.Valid {
		details.FnName = fnName.String
	}
	if pid.Valid {
		details.PID = int32(pid.Int64)
	}
	details.Retprobe = retprobe == 1
	return details, nil
}

func (s *sqliteStore) getFentryDetails(ctx context.Context, kernelLinkID uint32) (bpfman.FentryDetails, error) {
	start := time.Now()
	row := s.stmtGetFentryDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.FentryDetails
	err := row.Scan(&details.FnName)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetFentryDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.FentryDetails{}, fmt.Errorf("fentry details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetFentryDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.FentryDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetFentryDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)
	return details, nil
}

func (s *sqliteStore) getFexitDetails(ctx context.Context, kernelLinkID uint32) (bpfman.FexitDetails, error) {
	start := time.Now()
	row := s.stmtGetFexitDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.FexitDetails
	err := row.Scan(&details.FnName)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetFexitDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.FexitDetails{}, fmt.Errorf("fexit details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetFexitDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.FexitDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetFexitDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)
	return details, nil
}

func (s *sqliteStore) getXDPDetails(ctx context.Context, kernelLinkID uint32) (bpfman.XDPDetails, error) {
	start := time.Now()
	row := s.stmtGetXDPDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.XDPDetails
	var proceedOnJSON string
	var netns sql.NullString
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Priority, &details.Position,
		&proceedOnJSON, &netns, &details.Nsid, &details.DispatcherID, &details.Revision)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetXDPDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.XDPDetails{}, fmt.Errorf("xdp details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetXDPDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.XDPDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetXDPDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)

	if err := json.Unmarshal([]byte(proceedOnJSON), &details.ProceedOn); err != nil {
		return bpfman.XDPDetails{}, fmt.Errorf("failed to unmarshal proceed_on: %w", err)
	}
	if netns.Valid {
		details.Netns = netns.String
	}
	return details, nil
}

func (s *sqliteStore) getTCDetails(ctx context.Context, kernelLinkID uint32) (bpfman.TCDetails, error) {
	start := time.Now()
	row := s.stmtGetTCDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.TCDetails
	var proceedOnJSON string
	var netns sql.NullString
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Direction, &details.Priority, &details.Position,
		&proceedOnJSON, &netns, &details.Nsid, &details.DispatcherID, &details.Revision)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetTCDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.TCDetails{}, fmt.Errorf("tc details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetTCDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.TCDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetTCDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)

	if err := json.Unmarshal([]byte(proceedOnJSON), &details.ProceedOn); err != nil {
		return bpfman.TCDetails{}, fmt.Errorf("failed to unmarshal proceed_on: %w", err)
	}
	if netns.Valid {
		details.Netns = netns.String
	}
	return details, nil
}

func (s *sqliteStore) getTCXDetails(ctx context.Context, kernelLinkID uint32) (bpfman.TCXDetails, error) {
	start := time.Now()
	row := s.stmtGetTCXDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.TCXDetails
	var netns sql.NullString
	var nsid sql.NullInt64
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Direction, &details.Priority, &netns, &nsid)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetTCXDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.TCXDetails{}, fmt.Errorf("tcx details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetTCXDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.TCXDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetTCXDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)

	if netns.Valid {
		details.Netns = netns.String
	}
	if nsid.Valid {
		details.Nsid = uint64(nsid.Int64)
	}
	return details, nil
}
