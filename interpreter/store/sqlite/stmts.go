package sqlite

import "fmt"

// prepareProgramStatements prepares all program-related SQL statements.
func (s *sqliteStore) prepareProgramStatements() error {
	var err error

	const sqlGetProgram = `
		SELECT m.program_name, m.program_type, m.object_path, m.pin_path, m.attach_func,
		       m.global_data, m.map_owner_id, m.map_pin_path, m.image_source, m.owner, m.description, m.created_at,
		       GROUP_CONCAT(t.tag) as tags
		FROM managed_programs m
		LEFT JOIN program_tags t ON m.kernel_id = t.kernel_id
		WHERE m.kernel_id = ?
		GROUP BY m.kernel_id`
	if s.stmtGetProgram, err = s.db.Prepare(sqlGetProgram); err != nil {
		return fmt.Errorf("prepare GetProgram: %w", err)
	}

	const sqlSaveProgram = `
		INSERT INTO managed_programs
		(kernel_id, program_name, program_type, object_path, pin_path, attach_func,
		 global_data, map_owner_id, map_pin_path, image_source, owner, description, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(kernel_id) DO UPDATE SET
		  program_name = excluded.program_name,
		  program_type = excluded.program_type,
		  object_path = excluded.object_path,
		  pin_path = excluded.pin_path,
		  attach_func = excluded.attach_func,
		  global_data = excluded.global_data,
		  map_owner_id = excluded.map_owner_id,
		  map_pin_path = excluded.map_pin_path,
		  image_source = excluded.image_source,
		  owner = excluded.owner,
		  description = excluded.description,
		  created_at = excluded.created_at`
	if s.stmtSaveProgram, err = s.db.Prepare(sqlSaveProgram); err != nil {
		return fmt.Errorf("prepare SaveProgram: %w", err)
	}

	const sqlDeleteProgramMetadataIndex = "DELETE FROM program_metadata_index WHERE kernel_id = ?"
	if s.stmtDeleteProgramMetadataIndex, err = s.db.Prepare(sqlDeleteProgramMetadataIndex); err != nil {
		return fmt.Errorf("prepare DeleteProgramMetadataIndex: %w", err)
	}

	const sqlInsertProgramMetadataIndex = "INSERT INTO program_metadata_index (kernel_id, key, value) VALUES (?, ?, ?)"
	if s.stmtInsertProgramMetadataIndex, err = s.db.Prepare(sqlInsertProgramMetadataIndex); err != nil {
		return fmt.Errorf("prepare InsertProgramMetadataIndex: %w", err)
	}

	const sqlDeleteProgram = "DELETE FROM managed_programs WHERE kernel_id = ?"
	if s.stmtDeleteProgram, err = s.db.Prepare(sqlDeleteProgram); err != nil {
		return fmt.Errorf("prepare DeleteProgram: %w", err)
	}

	const sqlListPrograms = `
		SELECT m.kernel_id, m.program_name, m.program_type, m.object_path, m.pin_path, m.attach_func,
		       m.global_data, m.map_owner_id, m.map_pin_path, m.image_source, m.owner, m.description, m.created_at,
		       GROUP_CONCAT(t.tag) as tags
		FROM managed_programs m
		LEFT JOIN program_tags t ON m.kernel_id = t.kernel_id
		GROUP BY m.kernel_id`
	if s.stmtListPrograms, err = s.db.Prepare(sqlListPrograms); err != nil {
		return fmt.Errorf("prepare ListPrograms: %w", err)
	}

	const sqlFindProgramByMetadata = `
		SELECT m.kernel_id, m.program_name, m.program_type, m.object_path, m.pin_path, m.attach_func,
		       m.global_data, m.map_owner_id, m.map_pin_path, m.image_source, m.owner, m.description, m.created_at,
		       GROUP_CONCAT(t.tag) as tags
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		LEFT JOIN program_tags t ON m.kernel_id = t.kernel_id
		WHERE i.key = ? AND i.value = ?
		GROUP BY m.kernel_id
		LIMIT 1`
	if s.stmtFindProgramByMetadata, err = s.db.Prepare(sqlFindProgramByMetadata); err != nil {
		return fmt.Errorf("prepare FindProgramByMetadata: %w", err)
	}

	const sqlFindAllProgramsByMetadata = `
		SELECT m.kernel_id, m.program_name, m.program_type, m.object_path, m.pin_path, m.attach_func,
		       m.global_data, m.map_owner_id, m.map_pin_path, m.image_source, m.owner, m.description, m.created_at,
		       GROUP_CONCAT(t.tag) as tags
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		LEFT JOIN program_tags t ON m.kernel_id = t.kernel_id
		WHERE i.key = ? AND i.value = ?
		GROUP BY m.kernel_id`
	if s.stmtFindAllProgramsByMetadata, err = s.db.Prepare(sqlFindAllProgramsByMetadata); err != nil {
		return fmt.Errorf("prepare FindAllProgramsByMetadata: %w", err)
	}

	const sqlCountDependentPrograms = "SELECT COUNT(*) FROM managed_programs WHERE map_owner_id = ?"
	if s.stmtCountDependentPrograms, err = s.db.Prepare(sqlCountDependentPrograms); err != nil {
		return fmt.Errorf("prepare CountDependentPrograms: %w", err)
	}

	// Tag statements
	const sqlInsertTag = "INSERT INTO program_tags (kernel_id, tag) VALUES (?, ?)"
	if s.stmtInsertTag, err = s.db.Prepare(sqlInsertTag); err != nil {
		return fmt.Errorf("prepare InsertTag: %w", err)
	}

	const sqlDeleteTags = "DELETE FROM program_tags WHERE kernel_id = ?"
	if s.stmtDeleteTags, err = s.db.Prepare(sqlDeleteTags); err != nil {
		return fmt.Errorf("prepare DeleteTags: %w", err)
	}

	const sqlGetUserMetadata = "SELECT key, value FROM program_metadata_index WHERE kernel_id = ?"
	if s.stmtGetUserMetadata, err = s.db.Prepare(sqlGetUserMetadata); err != nil {
		return fmt.Errorf("prepare GetUserMetadata: %w", err)
	}

	return nil
}

// prepareLinkRegistryStatements prepares all link registry SQL statements.
func (s *sqliteStore) prepareLinkRegistryStatements() error {
	var err error

	const sqlDeleteLink = "DELETE FROM link_registry WHERE kernel_link_id = ?"
	if s.stmtDeleteLink, err = s.db.Prepare(sqlDeleteLink); err != nil {
		return fmt.Errorf("prepare DeleteLink: %w", err)
	}

	const sqlGetLinkRegistry = `
		SELECT kernel_link_id, link_type, kernel_program_id, pin_path, created_at
		FROM link_registry WHERE kernel_link_id = ?`
	if s.stmtGetLinkRegistry, err = s.db.Prepare(sqlGetLinkRegistry); err != nil {
		return fmt.Errorf("prepare GetLinkRegistry: %w", err)
	}

	const sqlListLinks = `
		SELECT kernel_link_id, link_type, kernel_program_id, pin_path, created_at
		FROM link_registry`
	if s.stmtListLinks, err = s.db.Prepare(sqlListLinks); err != nil {
		return fmt.Errorf("prepare ListLinks: %w", err)
	}

	const sqlListLinksByProgram = `
		SELECT kernel_link_id, link_type, kernel_program_id, pin_path, created_at
		FROM link_registry WHERE kernel_program_id = ?`
	if s.stmtListLinksByProgram, err = s.db.Prepare(sqlListLinksByProgram); err != nil {
		return fmt.Errorf("prepare ListLinksByProgram: %w", err)
	}

	const sqlInsertLinkRegistry = `
		INSERT INTO link_registry (kernel_link_id, link_type, kernel_program_id, pin_path, created_at)
		VALUES (?, ?, ?, ?, ?)`
	if s.stmtInsertLinkRegistry, err = s.db.Prepare(sqlInsertLinkRegistry); err != nil {
		return fmt.Errorf("prepare InsertLinkRegistry: %w", err)
	}

	const sqlListTCXLinksByInterface = `
		SELECT lr.kernel_link_id, lr.kernel_program_id, td.priority
		FROM link_registry lr
		JOIN tcx_link_details td ON lr.kernel_link_id = td.kernel_link_id
		WHERE td.nsid = ? AND td.ifindex = ? AND td.direction = ?
		ORDER BY td.priority ASC`
	if s.stmtListTCXLinksByInterface, err = s.db.Prepare(sqlListTCXLinksByInterface); err != nil {
		return fmt.Errorf("prepare ListTCXLinksByInterface: %w", err)
	}

	return nil
}

// prepareLinkDetailStatements prepares all link detail SQL statements.
func (s *sqliteStore) prepareLinkDetailStatements() error {
	var err error

	// Get statements
	const sqlGetTracepointDetails = "SELECT tracepoint_group, tracepoint_name FROM tracepoint_link_details WHERE kernel_link_id = ?"
	if s.stmtGetTracepointDetails, err = s.db.Prepare(sqlGetTracepointDetails); err != nil {
		return fmt.Errorf("prepare GetTracepointDetails: %w", err)
	}

	const sqlGetKprobeDetails = "SELECT fn_name, offset, retprobe FROM kprobe_link_details WHERE kernel_link_id = ?"
	if s.stmtGetKprobeDetails, err = s.db.Prepare(sqlGetKprobeDetails); err != nil {
		return fmt.Errorf("prepare GetKprobeDetails: %w", err)
	}

	const sqlGetUprobeDetails = "SELECT target, fn_name, offset, pid, retprobe FROM uprobe_link_details WHERE kernel_link_id = ?"
	if s.stmtGetUprobeDetails, err = s.db.Prepare(sqlGetUprobeDetails); err != nil {
		return fmt.Errorf("prepare GetUprobeDetails: %w", err)
	}

	const sqlGetFentryDetails = "SELECT fn_name FROM fentry_link_details WHERE kernel_link_id = ?"
	if s.stmtGetFentryDetails, err = s.db.Prepare(sqlGetFentryDetails); err != nil {
		return fmt.Errorf("prepare GetFentryDetails: %w", err)
	}

	const sqlGetFexitDetails = "SELECT fn_name FROM fexit_link_details WHERE kernel_link_id = ?"
	if s.stmtGetFexitDetails, err = s.db.Prepare(sqlGetFexitDetails); err != nil {
		return fmt.Errorf("prepare GetFexitDetails: %w", err)
	}

	const sqlGetXDPDetails = `
		SELECT interface, ifindex, priority, position, proceed_on, netns, nsid, dispatcher_id, revision
		FROM xdp_link_details WHERE kernel_link_id = ?`
	if s.stmtGetXDPDetails, err = s.db.Prepare(sqlGetXDPDetails); err != nil {
		return fmt.Errorf("prepare GetXDPDetails: %w", err)
	}

	const sqlGetTCDetails = `
		SELECT interface, ifindex, direction, priority, position, proceed_on, netns, nsid, dispatcher_id, revision
		FROM tc_link_details WHERE kernel_link_id = ?`
	if s.stmtGetTCDetails, err = s.db.Prepare(sqlGetTCDetails); err != nil {
		return fmt.Errorf("prepare GetTCDetails: %w", err)
	}

	const sqlGetTCXDetails = `
		SELECT interface, ifindex, direction, priority, netns, nsid
		FROM tcx_link_details WHERE kernel_link_id = ?`
	if s.stmtGetTCXDetails, err = s.db.Prepare(sqlGetTCXDetails); err != nil {
		return fmt.Errorf("prepare GetTCXDetails: %w", err)
	}

	// Save statements
	const sqlSaveTracepointDetails = `
		INSERT INTO tracepoint_link_details (kernel_link_id, tracepoint_group, tracepoint_name)
		VALUES (?, ?, ?)`
	if s.stmtSaveTracepointDetails, err = s.db.Prepare(sqlSaveTracepointDetails); err != nil {
		return fmt.Errorf("prepare SaveTracepointDetails: %w", err)
	}

	const sqlSaveKprobeDetails = `
		INSERT INTO kprobe_link_details (kernel_link_id, fn_name, offset, retprobe)
		VALUES (?, ?, ?, ?)`
	if s.stmtSaveKprobeDetails, err = s.db.Prepare(sqlSaveKprobeDetails); err != nil {
		return fmt.Errorf("prepare SaveKprobeDetails: %w", err)
	}

	const sqlSaveUprobeDetails = `
		INSERT INTO uprobe_link_details (kernel_link_id, target, fn_name, offset, pid, retprobe)
		VALUES (?, ?, ?, ?, ?, ?)`
	if s.stmtSaveUprobeDetails, err = s.db.Prepare(sqlSaveUprobeDetails); err != nil {
		return fmt.Errorf("prepare SaveUprobeDetails: %w", err)
	}

	const sqlSaveFentryDetails = `
		INSERT INTO fentry_link_details (kernel_link_id, fn_name)
		VALUES (?, ?)`
	if s.stmtSaveFentryDetails, err = s.db.Prepare(sqlSaveFentryDetails); err != nil {
		return fmt.Errorf("prepare SaveFentryDetails: %w", err)
	}

	const sqlSaveFexitDetails = `
		INSERT INTO fexit_link_details (kernel_link_id, fn_name)
		VALUES (?, ?)`
	if s.stmtSaveFexitDetails, err = s.db.Prepare(sqlSaveFexitDetails); err != nil {
		return fmt.Errorf("prepare SaveFexitDetails: %w", err)
	}

	const sqlSaveXDPDetails = `
		INSERT INTO xdp_link_details (kernel_link_id, interface, ifindex, priority, position, proceed_on, netns, nsid, dispatcher_id, revision)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.stmtSaveXDPDetails, err = s.db.Prepare(sqlSaveXDPDetails); err != nil {
		return fmt.Errorf("prepare SaveXDPDetails: %w", err)
	}

	const sqlSaveTCDetails = `
		INSERT INTO tc_link_details (kernel_link_id, interface, ifindex, direction, priority, position, proceed_on, netns, nsid, dispatcher_id, revision)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.stmtSaveTCDetails, err = s.db.Prepare(sqlSaveTCDetails); err != nil {
		return fmt.Errorf("prepare SaveTCDetails: %w", err)
	}

	const sqlSaveTCXDetails = `
		INSERT INTO tcx_link_details (kernel_link_id, interface, ifindex, direction, priority, netns, nsid)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	if s.stmtSaveTCXDetails, err = s.db.Prepare(sqlSaveTCXDetails); err != nil {
		return fmt.Errorf("prepare SaveTCXDetails: %w", err)
	}

	return nil
}

// prepareDispatcherStatements prepares all dispatcher SQL statements.
func (s *sqliteStore) prepareDispatcherStatements() error {
	var err error

	const sqlGetDispatcher = `
		SELECT id, type, nsid, ifindex, revision, kernel_id, link_id, priority
		FROM dispatchers WHERE type = ? AND nsid = ? AND ifindex = ?`
	if s.stmtGetDispatcher, err = s.db.Prepare(sqlGetDispatcher); err != nil {
		return fmt.Errorf("prepare GetDispatcher: %w", err)
	}

	const sqlListDispatchers = `
		SELECT id, type, nsid, ifindex, revision, kernel_id, link_id, priority
		FROM dispatchers`
	if s.stmtListDispatchers, err = s.db.Prepare(sqlListDispatchers); err != nil {
		return fmt.Errorf("prepare ListDispatchers: %w", err)
	}

	const sqlSaveDispatcher = `
		INSERT INTO dispatchers (type, nsid, ifindex, revision, kernel_id, link_id, priority, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(type, nsid, ifindex) DO UPDATE SET
		  revision = excluded.revision,
		  kernel_id = excluded.kernel_id,
		  link_id = excluded.link_id,
		  priority = excluded.priority,
		  updated_at = excluded.updated_at`
	if s.stmtSaveDispatcher, err = s.db.Prepare(sqlSaveDispatcher); err != nil {
		return fmt.Errorf("prepare SaveDispatcher: %w", err)
	}

	const sqlDeleteDispatcher = "DELETE FROM dispatchers WHERE type = ? AND nsid = ? AND ifindex = ?"
	if s.stmtDeleteDispatcher, err = s.db.Prepare(sqlDeleteDispatcher); err != nil {
		return fmt.Errorf("prepare DeleteDispatcher: %w", err)
	}

	const sqlIncrementRevision = `
		UPDATE dispatchers
		SET revision = CASE WHEN revision = 4294967295 THEN 1 ELSE revision + 1 END,
		    updated_at = ?
		WHERE type = ? AND nsid = ? AND ifindex = ?`
	if s.stmtIncrementRevision, err = s.db.Prepare(sqlIncrementRevision); err != nil {
		return fmt.Errorf("prepare IncrementRevision: %w", err)
	}

	const sqlGetDispatcherByType = "SELECT revision FROM dispatchers WHERE type = ? AND nsid = ? AND ifindex = ?"
	if s.stmtGetDispatcherByType, err = s.db.Prepare(sqlGetDispatcherByType); err != nil {
		return fmt.Errorf("prepare GetDispatcherByType: %w", err)
	}

	const sqlCountDispatcherLinks = `
		SELECT
			(SELECT COUNT(*) FROM tc_link_details WHERE dispatcher_id = ?) +
			(SELECT COUNT(*) FROM xdp_link_details WHERE dispatcher_id = ?)`
	if s.stmtCountDispatcherLinks, err = s.db.Prepare(sqlCountDispatcherLinks); err != nil {
		return fmt.Errorf("prepare CountDispatcherLinks: %w", err)
	}

	return nil
}
