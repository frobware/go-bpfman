package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/interpreter/store"
)

// Get retrieves program metadata by kernel ID.
// Returns store.ErrNotFound if the program does not exist.
func (s *sqliteStore) Get(ctx context.Context, kernelID uint32) (bpfman.Program, error) {
	start := time.Now()
	row := s.stmtGetProgram.QueryRowContext(ctx, kernelID)

	prog, err := s.scanProgram(row)
	if errors.Is(err, sql.ErrNoRows) {
		s.logger.Debug("sql", "stmt", "GetProgram", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.Program{}, fmt.Errorf("program %d: %w", kernelID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetProgram", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.Program{}, err
	}
	s.logger.Debug("sql", "stmt", "GetProgram", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows", 1)

	// Get user metadata (tags are already included via JOIN)
	metadata, err := s.getUserMetadata(ctx, kernelID)
	if err != nil {
		return bpfman.Program{}, err
	}
	prog.UserMetadata = metadata

	return prog, nil
}

// scanProgram scans a single row into a Program struct.
// The row must include the tags column from GROUP_CONCAT.
func (s *sqliteStore) scanProgram(row *sql.Row) (bpfman.Program, error) {
	var programName, programTypeStr, objectPath, pinPath string
	var attachFunc, globalDataJSON, mapPinPath, imageSourceJSON, owner, description, tagsStr sql.NullString
	var mapOwnerID sql.NullInt64
	var createdAtStr string

	err := row.Scan(
		&programName,
		&programTypeStr,
		&objectPath,
		&pinPath,
		&attachFunc,
		&globalDataJSON,
		&mapOwnerID,
		&mapPinPath,
		&imageSourceJSON,
		&owner,
		&description,
		&createdAtStr,
		&tagsStr,
	)
	if err != nil {
		return bpfman.Program{}, err
	}

	// Parse program type
	programType, _ := bpfman.ParseProgramType(programTypeStr)

	// Parse nullable scalar fields
	var attachFuncVal string
	var mapOwnerIDVal uint32
	var mapPinPathVal string
	if attachFunc.Valid {
		attachFuncVal = attachFunc.String
	}
	if mapOwnerID.Valid {
		mapOwnerIDVal = uint32(mapOwnerID.Int64)
	}
	if mapPinPath.Valid {
		mapPinPathVal = mapPinPath.String
	}

	// Parse JSON fields
	var globalData map[string][]byte
	var imageSource *bpfman.ImageSource
	if globalDataJSON.Valid {
		if err := json.Unmarshal([]byte(globalDataJSON.String), &globalData); err != nil {
			return bpfman.Program{}, fmt.Errorf("failed to unmarshal global_data: %w", err)
		}
	}
	if imageSourceJSON.Valid {
		if err := json.Unmarshal([]byte(imageSourceJSON.String), &imageSource); err != nil {
			return bpfman.Program{}, fmt.Errorf("failed to unmarshal image_source: %w", err)
		}
	}

	// Build the Program directly from the stored fields
	prog := bpfman.Program{
		ProgramName: programName,
		ProgramType: programType,
		ObjectPath:  objectPath,
		PinPath:     pinPath,
		GlobalData:  globalData,
		ImageSource: imageSource,
		AttachFunc:  attachFuncVal,
		MapOwnerID:  mapOwnerIDVal,
		MapPinPath:  mapPinPathVal,
	}
	if owner.Valid {
		prog.Owner = owner.String
	}
	if description.Valid {
		prog.Description = description.String
	}

	// Parse tags from GROUP_CONCAT result
	if tagsStr.Valid && tagsStr.String != "" {
		prog.Tags = strings.Split(tagsStr.String, ",")
	}

	// Parse timestamp
	prog.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

	return prog, nil
}

// getUserMetadata retrieves user metadata for a program from the metadata index.
func (s *sqliteStore) getUserMetadata(ctx context.Context, kernelID uint32) (map[string]string, error) {
	// We need a separate query for this since we don't have a prepared statement
	start := time.Now()
	rows, err := s.conn.QueryContext(ctx, "SELECT key, value FROM program_metadata_index WHERE kernel_id = ?", kernelID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetUserMetadata", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	metadata := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		metadata[key] = value
	}
	s.logger.Debug("sql", "stmt", "GetUserMetadata", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows", len(metadata))
	return metadata, rows.Err()
}

// Save stores program metadata.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) Save(ctx context.Context, kernelID uint32, metadata bpfman.Program) error {
	// Marshal only opaque fields to JSON
	var globalDataJSON, imageSourceJSON sql.NullString
	if metadata.GlobalData != nil {
		data, err := json.Marshal(metadata.GlobalData)
		if err != nil {
			return fmt.Errorf("failed to marshal global_data: %w", err)
		}
		globalDataJSON = sql.NullString{String: string(data), Valid: true}
	}
	if metadata.ImageSource != nil {
		data, err := json.Marshal(metadata.ImageSource)
		if err != nil {
			return fmt.Errorf("failed to marshal image_source: %w", err)
		}
		imageSourceJSON = sql.NullString{String: string(data), Valid: true}
	}

	// Handle nullable fields
	var mapOwnerID sql.NullInt64
	if metadata.MapOwnerID != 0 {
		mapOwnerID = sql.NullInt64{Int64: int64(metadata.MapOwnerID), Valid: true}
	}
	var mapPinPath sql.NullString
	if metadata.MapPinPath != "" {
		mapPinPath = sql.NullString{String: metadata.MapPinPath, Valid: true}
	}
	var attachFunc, owner, description sql.NullString
	if metadata.AttachFunc != "" {
		attachFunc = sql.NullString{String: metadata.AttachFunc, Valid: true}
	}
	if metadata.Owner != "" {
		owner = sql.NullString{String: metadata.Owner, Valid: true}
	}
	if metadata.Description != "" {
		description = sql.NullString{String: metadata.Description, Valid: true}
	}

	start := time.Now()
	result, err := s.stmtSaveProgram.ExecContext(ctx,
		kernelID,
		metadata.ProgramName,
		metadata.ProgramType.String(),
		metadata.ObjectPath,
		metadata.PinPath,
		attachFunc,
		globalDataJSON,
		mapOwnerID,
		mapPinPath,
		imageSourceJSON,
		owner,
		description,
		metadata.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveProgram", "args", []any{kernelID, metadata.ProgramName, "(columns)"}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert program: %w", err)
	}
	rows, _ := result.RowsAffected()
	s.logger.Debug("sql", "stmt", "SaveProgram", "args", []any{kernelID, metadata.ProgramName, "(columns)"}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)

	// Clear old tags and insert new ones
	start = time.Now()
	result, err = s.stmtDeleteTags.ExecContext(ctx, kernelID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "DeleteTags", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to clear tags: %w", err)
	}
	rows, _ = result.RowsAffected()
	s.logger.Debug("sql", "stmt", "DeleteTags", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)

	for _, tag := range metadata.Tags {
		start = time.Now()
		_, err = s.stmtInsertTag.ExecContext(ctx, kernelID, tag)
		if err != nil {
			s.logger.Debug("sql", "stmt", "InsertTag", "args", []any{kernelID, tag}, "duration_ms", msec(time.Since(start)), "error", err)
			return fmt.Errorf("failed to insert tag: %w", err)
		}
		s.logger.Debug("sql", "stmt", "InsertTag", "args", []any{kernelID, tag}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)
	}

	// Clear old metadata index entries for this program
	start = time.Now()
	result, err = s.stmtDeleteProgramMetadataIndex.ExecContext(ctx, kernelID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "DeleteProgramMetadataIndex", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to clear metadata index: %w", err)
	}
	rows, _ = result.RowsAffected()
	s.logger.Debug("sql", "stmt", "DeleteProgramMetadataIndex", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)

	// Insert metadata index entries for UserMetadata
	for key, value := range metadata.UserMetadata {
		start = time.Now()
		_, err = s.stmtInsertProgramMetadataIndex.ExecContext(ctx, kernelID, key, value)
		if err != nil {
			s.logger.Debug("sql", "stmt", "InsertProgramMetadataIndex", "args", []any{kernelID, key, value}, "duration_ms", msec(time.Since(start)), "error", err)
			return fmt.Errorf("failed to insert metadata index: %w", err)
		}
		s.logger.Debug("sql", "stmt", "InsertProgramMetadataIndex", "args", []any{kernelID, key, value}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)
	}

	return nil
}

// Delete removes program metadata.
func (s *sqliteStore) Delete(ctx context.Context, kernelID uint32) error {
	start := time.Now()
	result, err := s.stmtDeleteProgram.ExecContext(ctx, kernelID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "DeleteProgram", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return err
	}
	rows, _ := result.RowsAffected()
	s.logger.Debug("sql", "stmt", "DeleteProgram", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)
	return nil
}

// GC removes all stale entries (programs, dispatchers, links) that don't
// exist in the provided kernel state. Handles internal ordering constraints
// (e.g., dependent programs before map owners for FK constraints).
func (s *sqliteStore) GC(ctx context.Context, kernelProgramIDs, kernelLinkIDs map[uint32]bool) (interpreter.GCResult, error) {
	start := time.Now()
	var result interpreter.GCResult

	// 1. GC programs (order: dependents before owners)
	stored, err := s.List(ctx)
	if err != nil {
		return result, fmt.Errorf("list programs: %w", err)
	}

	var dependents, owners []uint32
	for id, prog := range stored {
		if !kernelProgramIDs[id] {
			if prog.MapOwnerID != 0 {
				dependents = append(dependents, id)
			} else {
				owners = append(owners, id)
			}
		}
	}

	for _, id := range dependents {
		if err := s.Delete(ctx, id); err != nil {
			s.logger.Warn("failed to delete dependent program", "kernel_id", id, "error", err)
			continue
		}
		result.ProgramsRemoved++
	}
	for _, id := range owners {
		if err := s.Delete(ctx, id); err != nil {
			s.logger.Warn("failed to delete owner program", "kernel_id", id, "error", err)
			continue
		}
		result.ProgramsRemoved++
	}

	// 2. Reconcile dispatchers (delete those referencing gone programs)
	dispatchers, err := s.ListDispatchers(ctx)
	if err != nil {
		return result, fmt.Errorf("list dispatchers: %w", err)
	}

	for _, disp := range dispatchers {
		if !kernelProgramIDs[disp.KernelID] {
			if err := s.DeleteDispatcher(ctx, string(disp.Type), disp.Nsid, disp.Ifindex); err != nil {
				s.logger.Warn("failed to delete dispatcher", "type", disp.Type, "nsid", disp.Nsid, "ifindex", disp.Ifindex, "error", err)
				continue
			}
			result.DispatchersRemoved++
		}
	}

	// 3. Reconcile links (delete those not in kernel)
	// Skip synthetic link IDs (>= 0x80000000) since they're not real kernel links
	// and cannot be enumerated via the kernel's link iterator. These are used for
	// perf_event-based attachments (e.g., container uprobes) that lack kernel link IDs.
	links, err := s.ListLinks(ctx)
	if err != nil {
		return result, fmt.Errorf("list links: %w", err)
	}

	for _, link := range links {
		// Skip synthetic link IDs - they're not in kernelLinkIDs but are valid
		if bpfman.IsSyntheticLinkID(link.KernelLinkID) {
			continue
		}
		if !kernelLinkIDs[link.KernelLinkID] {
			if err := s.DeleteLink(ctx, link.KernelLinkID); err != nil {
				s.logger.Warn("failed to delete link", "kernel_link_id", link.KernelLinkID, "error", err)
				continue
			}
			result.LinksRemoved++
		}
	}

	// 4. Reconcile dispatchers after link GC: delete any dispatcher
	// that has no remaining extension links so the next attach
	// recreates a fresh dispatcher.
	if result.LinksRemoved > 0 {
		surviving, err := s.ListDispatchers(ctx)
		if err != nil {
			return result, fmt.Errorf("list dispatchers after link GC: %w", err)
		}
		for _, disp := range surviving {
			liveLinks, err := s.CountDispatcherLinks(ctx, disp.KernelID)
			if err != nil {
				s.logger.Warn("failed to count dispatcher links", "kernel_id", disp.KernelID, "error", err)
				continue
			}
			if liveLinks == 0 {
				s.logger.Info("deleting dispatcher with no live extensions",
					"type", disp.Type, "nsid", disp.Nsid, "ifindex", disp.Ifindex,
					"kernel_id", disp.KernelID)
				if err := s.DeleteDispatcher(ctx, string(disp.Type), disp.Nsid, disp.Ifindex); err != nil {
					s.logger.Warn("failed to delete stale dispatcher", "kernel_id", disp.KernelID, "error", err)
					continue
				}
				result.DispatchersRemoved++
			}
		}
	}

	s.logger.Debug("reconcile", "duration_ms", msec(time.Since(start)),
		"programs_removed", result.ProgramsRemoved,
		"dispatchers_removed", result.DispatchersRemoved,
		"links_removed", result.LinksRemoved)

	return result, nil
}

// CountDependentPrograms returns the number of programs that share maps with
// the given program (i.e., programs where map_owner_id = kernelID).
func (s *sqliteStore) CountDependentPrograms(ctx context.Context, kernelID uint32) (int, error) {
	start := time.Now()
	var count int
	err := s.stmtCountDependentPrograms.QueryRowContext(ctx, kernelID).Scan(&count)
	if err != nil {
		s.logger.Debug("sql", "stmt", "CountDependentPrograms", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return 0, err
	}
	s.logger.Debug("sql", "stmt", "CountDependentPrograms", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "count", count)
	return count, nil
}

// List returns all program metadata.
func (s *sqliteStore) List(ctx context.Context) (map[uint32]bpfman.Program, error) {
	start := time.Now()
	rows, err := s.stmtListPrograms.QueryContext(ctx)
	if err != nil {
		s.logger.Debug("sql", "stmt", "ListPrograms", "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	result := make(map[uint32]bpfman.Program)
	for rows.Next() {
		kernelID, prog, err := s.scanProgramFromRows(rows)
		if err != nil {
			return nil, err
		}
		result[kernelID] = prog
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Fetch metadata for each program (tags are already included via JOIN)
	for kernelID, prog := range result {
		metadata, err := s.getUserMetadata(ctx, kernelID)
		if err != nil {
			return nil, err
		}
		prog.UserMetadata = metadata
		result[kernelID] = prog
	}

	s.logger.Debug("sql", "stmt", "ListPrograms", "duration_ms", msec(time.Since(start)), "rows", len(result))
	return result, nil
}

// scanProgramFromRows scans a single row from *sql.Rows into a Program struct.
// The row must include the tags column from GROUP_CONCAT.
func (s *sqliteStore) scanProgramFromRows(rows *sql.Rows) (uint32, bpfman.Program, error) {
	var kernelID uint32
	var programName, programTypeStr, objectPath, pinPath string
	var attachFunc, globalDataJSON, mapPinPath, imageSourceJSON, owner, description, tagsStr sql.NullString
	var mapOwnerID sql.NullInt64
	var createdAtStr string

	err := rows.Scan(
		&kernelID,
		&programName,
		&programTypeStr,
		&objectPath,
		&pinPath,
		&attachFunc,
		&globalDataJSON,
		&mapOwnerID,
		&mapPinPath,
		&imageSourceJSON,
		&owner,
		&description,
		&createdAtStr,
		&tagsStr,
	)
	if err != nil {
		return 0, bpfman.Program{}, err
	}

	// Parse program type
	programType, _ := bpfman.ParseProgramType(programTypeStr)

	// Parse nullable scalar fields
	var attachFuncVal string
	var mapOwnerIDVal uint32
	var mapPinPathVal string
	if attachFunc.Valid {
		attachFuncVal = attachFunc.String
	}
	if mapOwnerID.Valid {
		mapOwnerIDVal = uint32(mapOwnerID.Int64)
	}
	if mapPinPath.Valid {
		mapPinPathVal = mapPinPath.String
	}

	// Parse JSON fields
	var globalData map[string][]byte
	var imageSource *bpfman.ImageSource
	if globalDataJSON.Valid {
		if err := json.Unmarshal([]byte(globalDataJSON.String), &globalData); err != nil {
			return 0, bpfman.Program{}, fmt.Errorf("failed to unmarshal global_data for %d: %w", kernelID, err)
		}
	}
	if imageSourceJSON.Valid {
		if err := json.Unmarshal([]byte(imageSourceJSON.String), &imageSource); err != nil {
			return 0, bpfman.Program{}, fmt.Errorf("failed to unmarshal image_source for %d: %w", kernelID, err)
		}
	}

	// Build the Program directly from the stored fields
	prog := bpfman.Program{
		ProgramName: programName,
		ProgramType: programType,
		ObjectPath:  objectPath,
		PinPath:     pinPath,
		GlobalData:  globalData,
		ImageSource: imageSource,
		AttachFunc:  attachFuncVal,
		MapOwnerID:  mapOwnerIDVal,
		MapPinPath:  mapPinPathVal,
	}
	if owner.Valid {
		prog.Owner = owner.String
	}
	if description.Valid {
		prog.Description = description.String
	}

	// Parse tags from GROUP_CONCAT result
	if tagsStr.Valid && tagsStr.String != "" {
		prog.Tags = strings.Split(tagsStr.String, ",")
	}

	// Parse timestamp
	prog.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

	return kernelID, prog, nil
}

// FindProgramByMetadata finds a program by a specific metadata key/value pair.
// Returns store.ErrNotFound if no program matches.
func (s *sqliteStore) FindProgramByMetadata(ctx context.Context, key, value string) (bpfman.Program, uint32, error) {
	start := time.Now()
	rows, err := s.stmtFindProgramByMetadata.QueryContext(ctx, key, value)
	if err != nil {
		s.logger.Debug("sql", "stmt", "FindProgramByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.Program{}, 0, err
	}

	if !rows.Next() {
		rows.Close()
		s.logger.Debug("sql", "stmt", "FindProgramByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.Program{}, 0, fmt.Errorf("program with %s=%s: %w", key, value, store.ErrNotFound)
	}

	kernelID, prog, err := s.scanProgramFromRows(rows)
	rows.Close() // Close rows before making additional queries
	if err != nil {
		s.logger.Debug("sql", "stmt", "FindProgramByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.Program{}, 0, err
	}
	s.logger.Debug("sql", "stmt", "FindProgramByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "rows", 1)

	// Get user metadata (tags are already included via JOIN)
	metadata, err := s.getUserMetadata(ctx, kernelID)
	if err != nil {
		return bpfman.Program{}, 0, err
	}
	prog.UserMetadata = metadata

	return prog, kernelID, nil
}

// FindAllProgramsByMetadata finds all programs with a specific metadata key/value pair.
func (s *sqliteStore) FindAllProgramsByMetadata(ctx context.Context, key, value string) ([]struct {
	KernelID uint32
	Metadata bpfman.Program
}, error) {
	start := time.Now()
	rows, err := s.stmtFindAllProgramsByMetadata.QueryContext(ctx, key, value)
	if err != nil {
		s.logger.Debug("sql", "stmt", "FindAllProgramsByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	var result []struct {
		KernelID uint32
		Metadata bpfman.Program
	}

	for rows.Next() {
		kernelID, prog, err := s.scanProgramFromRows(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, struct {
			KernelID uint32
			Metadata bpfman.Program
		}{KernelID: kernelID, Metadata: prog})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Fetch metadata for each program (tags are already included via JOIN)
	for i := range result {
		metadata, err := s.getUserMetadata(ctx, result[i].KernelID)
		if err != nil {
			return nil, err
		}
		result[i].Metadata.UserMetadata = metadata
	}

	s.logger.Debug("sql", "stmt", "FindAllProgramsByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "rows", len(result))
	return result, nil
}
