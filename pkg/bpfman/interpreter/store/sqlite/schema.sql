-- Schema for bpfman SQLite database
-- This schema uses the registry + detail tables pattern for links,
-- providing both polymorphic access and type-specific constraints.

-- Programs table for managed BPF programs
CREATE TABLE IF NOT EXISTS managed_programs (
    kernel_id INTEGER PRIMARY KEY,
    uuid TEXT,
    metadata TEXT NOT NULL,
    created_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'loaded',
    updated_at TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX IF NOT EXISTS idx_managed_programs_uuid ON managed_programs(uuid);
CREATE INDEX IF NOT EXISTS idx_managed_programs_state ON managed_programs(state);

-- Index table for fast metadata key/value lookups (used by CSI)
CREATE TABLE IF NOT EXISTS program_metadata_index (
    kernel_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (kernel_id, key),
    FOREIGN KEY (kernel_id) REFERENCES managed_programs(kernel_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX IF NOT EXISTS idx_program_metadata_key_value ON program_metadata_index(key, value);

-- Enforce uniqueness for bpfman.io/ProgramName metadata
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_program_name
    ON program_metadata_index(value)
    WHERE key = 'bpfman.io/ProgramName';

--------------------------------------------------------------------------------
-- Link Registry (Polymorphic Core)
--------------------------------------------------------------------------------

-- link_registry contains all common fields for managed links.
-- All polymorphic operations (list, delete by UUID) operate on this table.
CREATE TABLE IF NOT EXISTS link_registry (
    uuid TEXT PRIMARY KEY,
    link_type TEXT NOT NULL,
    kernel_program_id INTEGER NOT NULL,
    kernel_link_id INTEGER,
    pin_path TEXT,
    created_at TEXT NOT NULL,

    FOREIGN KEY (kernel_program_id)
        REFERENCES managed_programs(kernel_id)
        ON DELETE CASCADE
) STRICT;

CREATE INDEX IF NOT EXISTS idx_link_registry_program ON link_registry(kernel_program_id);
CREATE INDEX IF NOT EXISTS idx_link_registry_type ON link_registry(link_type);

--------------------------------------------------------------------------------
-- Type-Specific Detail Tables
--------------------------------------------------------------------------------

-- Tracepoint links
CREATE TABLE IF NOT EXISTS tracepoint_link_details (
    uuid TEXT PRIMARY KEY,
    tracepoint_group TEXT NOT NULL,
    tracepoint_name TEXT NOT NULL,

    FOREIGN KEY (uuid)
        REFERENCES link_registry(uuid)
        ON DELETE CASCADE
) STRICT;

-- Kprobe/Kretprobe links
CREATE TABLE IF NOT EXISTS kprobe_link_details (
    uuid TEXT PRIMARY KEY,
    fn_name TEXT NOT NULL,
    offset INTEGER NOT NULL DEFAULT 0,
    retprobe INTEGER NOT NULL DEFAULT 0 CHECK (retprobe IN (0, 1)),

    FOREIGN KEY (uuid)
        REFERENCES link_registry(uuid)
        ON DELETE CASCADE
) STRICT;

-- Uprobe/Uretprobe links
CREATE TABLE IF NOT EXISTS uprobe_link_details (
    uuid TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    fn_name TEXT,
    offset INTEGER NOT NULL DEFAULT 0,
    pid INTEGER,
    retprobe INTEGER NOT NULL DEFAULT 0 CHECK (retprobe IN (0, 1)),

    FOREIGN KEY (uuid)
        REFERENCES link_registry(uuid)
        ON DELETE CASCADE
) STRICT;

-- Fentry links
CREATE TABLE IF NOT EXISTS fentry_link_details (
    uuid TEXT PRIMARY KEY,
    fn_name TEXT NOT NULL,

    FOREIGN KEY (uuid)
        REFERENCES link_registry(uuid)
        ON DELETE CASCADE
) STRICT;

-- Fexit links
CREATE TABLE IF NOT EXISTS fexit_link_details (
    uuid TEXT PRIMARY KEY,
    fn_name TEXT NOT NULL,

    FOREIGN KEY (uuid)
        REFERENCES link_registry(uuid)
        ON DELETE CASCADE
) STRICT;

-- XDP links (dispatcher-based)
CREATE TABLE IF NOT EXISTS xdp_link_details (
    uuid TEXT PRIMARY KEY,
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    priority INTEGER NOT NULL CHECK (priority >= 0),
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 9),
    proceed_on TEXT NOT NULL CHECK (json_valid(proceed_on)),
    netns TEXT,
    nsid INTEGER,
    dispatcher_id INTEGER NOT NULL,

    FOREIGN KEY (uuid)
        REFERENCES link_registry(uuid)
        ON DELETE CASCADE
) STRICT;

-- Enforce unique position per XDP dispatcher
CREATE UNIQUE INDEX IF NOT EXISTS uq_xdp_dispatcher_position
    ON xdp_link_details(dispatcher_id, nsid, position);

-- TC links (dispatcher-based)
CREATE TABLE IF NOT EXISTS tc_link_details (
    uuid TEXT PRIMARY KEY,
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('ingress', 'egress')),
    priority INTEGER NOT NULL CHECK (priority >= 0),
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 9),
    proceed_on TEXT NOT NULL CHECK (json_valid(proceed_on)),
    netns TEXT,
    nsid INTEGER,
    dispatcher_id INTEGER NOT NULL,

    FOREIGN KEY (uuid)
        REFERENCES link_registry(uuid)
        ON DELETE CASCADE
) STRICT;

-- Enforce unique position per TC dispatcher + direction
CREATE UNIQUE INDEX IF NOT EXISTS uq_tc_dispatcher_position
    ON tc_link_details(dispatcher_id, direction, nsid, position);

-- TCX links (kernel multi-attach)
CREATE TABLE IF NOT EXISTS tcx_link_details (
    uuid TEXT PRIMARY KEY,
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('ingress', 'egress')),
    priority INTEGER NOT NULL CHECK (priority >= 0),
    netns TEXT,
    nsid INTEGER,

    FOREIGN KEY (uuid)
        REFERENCES link_registry(uuid)
        ON DELETE CASCADE
) STRICT;
