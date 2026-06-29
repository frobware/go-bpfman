-- Drop every object the baseline creates. Child tables first so the
-- foreign-key references unwind cleanly; the per-table indexes go with
-- their tables. Production never runs this -- the store rolls forward,
-- never down -- but a complete down keeps the baseline reversible for
-- tests and ad-hoc inspection.
DROP TABLE IF EXISTS shared_map_pins;
DROP TABLE IF EXISTS link_tcx_details;
DROP TABLE IF EXISTS link_tc_details;
DROP TABLE IF EXISTS link_xdp_details;
DROP TABLE IF EXISTS dispatchers;
DROP TABLE IF EXISTS link_fexit_details;
DROP TABLE IF EXISTS link_fentry_details;
DROP TABLE IF EXISTS link_uprobe_details;
DROP TABLE IF EXISTS link_kprobe_details;
DROP TABLE IF EXISTS link_tracepoint_details;
DROP TABLE IF EXISTS links;
DROP TABLE IF EXISTS managed_programs;
DROP TABLE IF EXISTS map_sets;
