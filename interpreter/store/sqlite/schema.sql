-- Schema for bpfman SQLite database
-- This schema uses the registry + detail tables pattern for links,
-- providing both polymorphic access and type-specific constraints.

-- Programs table for managed BPF programs
-- A row exists only after successful load - no reservation/loading states.
-- Schema is normalised: individual columns for queryable fields, JSON only for opaque data.
CREATE TABLE IF NOT EXISTS managed_programs (
    kernel_id INTEGER PRIMARY KEY,
    program_name TEXT NOT NULL,
    program_type TEXT NOT NULL,
    object_path TEXT NOT NULL,
    pin_path TEXT NOT NULL,
    attach_func TEXT,
    global_data TEXT,            -- JSON map<string, bytes>, opaque
    map_owner_id INTEGER,        -- Self-reference: program that owns shared maps
    map_pin_path TEXT,           -- Directory where maps are pinned
    image_source TEXT,           -- JSON ImageSource struct, NULL if file-loaded
    owner TEXT,
    description TEXT,
    created_at TEXT NOT NULL,

    FOREIGN KEY (map_owner_id)
        REFERENCES managed_programs(kernel_id)
        ON DELETE RESTRICT       -- Prevent deleting owner while dependents exist
) STRICT;

-- Tags table for program tags (one-to-many)
CREATE TABLE IF NOT EXISTS program_tags (
    kernel_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY (kernel_id, tag),
    FOREIGN KEY (kernel_id) REFERENCES managed_programs(kernel_id) ON DELETE CASCADE
) STRICT;

-- Index table for fast metadata key/value lookups (used by CSI)
CREATE TABLE IF NOT EXISTS program_metadata_index (
    kernel_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (kernel_id, key),
    FOREIGN KEY (kernel_id) REFERENCES managed_programs(kernel_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX IF NOT EXISTS idx_program_metadata_key_value ON program_metadata_index(key, value);

-- Note: No uniqueness constraint on bpfman.io/ProgramName.
-- Multiple programs can share the same application name (e.g., when loading
-- multiple BPF programs from a single image via the operator).

--------------------------------------------------------------------------------
-- Link Registry (Polymorphic Core)
--------------------------------------------------------------------------------

-- link_registry contains all common fields for managed links.
-- kernel_link_id is the primary key (kernel-assigned link ID or synthetic ID
-- for perf_event-based attachments like container uprobes).
CREATE TABLE IF NOT EXISTS link_registry (
    kernel_link_id INTEGER PRIMARY KEY,
    link_type TEXT NOT NULL,
    kernel_program_id INTEGER NOT NULL,
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
    kernel_link_id INTEGER PRIMARY KEY,
    tracepoint_group TEXT NOT NULL,
    tracepoint_name TEXT NOT NULL,

    FOREIGN KEY (kernel_link_id)
        REFERENCES link_registry(kernel_link_id)
        ON DELETE CASCADE
) STRICT;

-- Kprobe/Kretprobe links
CREATE TABLE IF NOT EXISTS kprobe_link_details (
    kernel_link_id INTEGER PRIMARY KEY,
    fn_name TEXT NOT NULL,
    offset INTEGER NOT NULL DEFAULT 0,
    retprobe INTEGER NOT NULL DEFAULT 0 CHECK (retprobe IN (0, 1)),

    FOREIGN KEY (kernel_link_id)
        REFERENCES link_registry(kernel_link_id)
        ON DELETE CASCADE
) STRICT;

-- Uprobe/Uretprobe links
CREATE TABLE IF NOT EXISTS uprobe_link_details (
    kernel_link_id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    fn_name TEXT,
    offset INTEGER NOT NULL DEFAULT 0,
    pid INTEGER,
    retprobe INTEGER NOT NULL DEFAULT 0 CHECK (retprobe IN (0, 1)),

    FOREIGN KEY (kernel_link_id)
        REFERENCES link_registry(kernel_link_id)
        ON DELETE CASCADE
) STRICT;

-- Fentry links
CREATE TABLE IF NOT EXISTS fentry_link_details (
    kernel_link_id INTEGER PRIMARY KEY,
    fn_name TEXT NOT NULL,

    FOREIGN KEY (kernel_link_id)
        REFERENCES link_registry(kernel_link_id)
        ON DELETE CASCADE
) STRICT;

-- Fexit links
CREATE TABLE IF NOT EXISTS fexit_link_details (
    kernel_link_id INTEGER PRIMARY KEY,
    fn_name TEXT NOT NULL,

    FOREIGN KEY (kernel_link_id)
        REFERENCES link_registry(kernel_link_id)
        ON DELETE CASCADE
) STRICT;

-- Dispatchers table for XDP/TC multi-program chaining
CREATE TABLE IF NOT EXISTS dispatchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK (type IN ('xdp', 'tc-ingress', 'tc-egress')),
    nsid INTEGER NOT NULL,
    ifindex INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    kernel_id INTEGER NOT NULL,
    link_id INTEGER NOT NULL,
    link_pin_path TEXT NOT NULL,
    prog_pin_path TEXT NOT NULL,
    num_extensions INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (type, nsid, ifindex)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_dispatchers_lookup
    ON dispatchers(type, nsid, ifindex);

-- XDP links (dispatcher-based)
CREATE TABLE IF NOT EXISTS xdp_link_details (
    kernel_link_id INTEGER PRIMARY KEY,
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    priority INTEGER NOT NULL CHECK (priority >= 0),
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 9),
    proceed_on TEXT NOT NULL CHECK (json_valid(proceed_on)),
    netns TEXT,
    nsid INTEGER NOT NULL,
    dispatcher_id INTEGER NOT NULL,
    revision INTEGER NOT NULL,

    FOREIGN KEY (kernel_link_id)
        REFERENCES link_registry(kernel_link_id)
        ON DELETE CASCADE
) STRICT;

-- Enforce unique position per interface in namespace
CREATE UNIQUE INDEX IF NOT EXISTS uq_xdp_dispatcher_position
    ON xdp_link_details(nsid, ifindex, position);

-- TC links (dispatcher-based)
CREATE TABLE IF NOT EXISTS tc_link_details (
    kernel_link_id INTEGER PRIMARY KEY,
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('ingress', 'egress')),
    priority INTEGER NOT NULL CHECK (priority >= 0),
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 9),
    proceed_on TEXT NOT NULL CHECK (json_valid(proceed_on)),
    netns TEXT,
    nsid INTEGER NOT NULL,
    dispatcher_id INTEGER NOT NULL,
    revision INTEGER NOT NULL,

    FOREIGN KEY (kernel_link_id)
        REFERENCES link_registry(kernel_link_id)
        ON DELETE CASCADE
) STRICT;

-- Enforce unique position per interface + direction in namespace
CREATE UNIQUE INDEX IF NOT EXISTS uq_tc_dispatcher_position
    ON tc_link_details(nsid, ifindex, direction, position);

-- TCX links (kernel multi-attach)
CREATE TABLE IF NOT EXISTS tcx_link_details (
    kernel_link_id INTEGER PRIMARY KEY,
    interface TEXT NOT NULL,
    ifindex INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('ingress', 'egress')),
    priority INTEGER NOT NULL CHECK (priority >= 0),
    netns TEXT,
    nsid INTEGER,

    FOREIGN KEY (kernel_link_id)
        REFERENCES link_registry(kernel_link_id)
        ON DELETE CASCADE
) STRICT;
