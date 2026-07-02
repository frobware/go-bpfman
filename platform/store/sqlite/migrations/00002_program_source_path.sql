-- +goose Up
-- Record the bytecode path the caller supplied to a file load,
-- verbatim. object_path holds bpfman's stored copy
-- (<runtime-dir>/programs/<id>/bytecode.o); source_path answers "what
-- did I load?" after the fact. NULL for image loads (provenance lives
-- in image_source) and for rows created before this column existed.
ALTER TABLE managed_programs ADD COLUMN source_path TEXT;

-- +goose Down
ALTER TABLE managed_programs DROP COLUMN source_path;
