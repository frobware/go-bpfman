# Logging Configuration

bpfman supports structured logging with fine-grained control over log
levels on a per-component basis.

## Quick Start

```bash
# Default (info level)
bpfman serve

# Enable debug logging
bpfman serve --log=debug

# Debug for manager component only
bpfman serve --log=info,manager=debug

# Using environment variable
BPFMAN_LOG=debug bpfman serve
```

## Log Levels

From most to least verbose:

| Level | Description |
|-------|-------------|
| `trace` | Most verbose, includes internal details |
| `debug` | Debugging information |
| `info` | Informational messages (default) |
| `warn` | Warning messages |
| `error` | Error messages only |

## Log Spec Format

The log specification consists of a base level and optional per-component
overrides:

```
<base-level>[,<component>=<level>]...
```

Examples:
- `info` - base level info for all components
- `debug` - base level debug for all components
- `warn,manager=debug` - base warn, manager at debug
- `info,manager=debug,store=trace` - multiple component overrides

Component names refer to bpfman subsystems (see Components section below).
Unknown component names are silently ignored.

## Configuration Precedence

Configuration is loaded using overlay semantics. Each layer overrides
the previous:

```
built-in defaults → config file → BPFMAN_LOG env → --log CLI flag
```

| Priority | Source | Description |
|----------|--------|-------------|
| 1 (lowest) | Built-in defaults | Embedded in binary (`info` level, `text` format) |
| 2 | Config file | `/etc/bpfman/bpfman.toml` (or `--config` path) |
| 3 | Environment variable | `BPFMAN_LOG` |
| 4 (highest) | CLI flag | `--log` |

This follows Unix convention where explicit command-line flags override
ambient environment variables, which override config files, which override
built-in defaults.

**Overlay behaviour**: The config file only needs to specify values that
differ from defaults. Unspecified fields retain their default values.

Example demonstrating precedence:

```bash
# Env var sets debug, but CLI flag overrides to warn
BPFMAN_LOG=debug bpfman serve --log=warn
# Result: warn level is used

# No flag, env var used
BPFMAN_LOG=debug bpfman serve
# Result: debug level is used

# Neither flag nor env, config file used (if present), else defaults
bpfman serve
# Result: config file's level, or "info" if not specified
```

## CLI Flags

Global flags available on all commands:

```
--log=STRING    Log spec (e.g., 'info,manager=debug') ($BPFMAN_LOG)
--config=PATH   Config file path (default: /etc/bpfman/bpfman.toml)
```

## Config File

Add a `[logging]` section to your config file. Only specify values that
differ from the built-in defaults; unspecified fields retain defaults.

```toml
[logging]
level = "info"
format = "text"

[logging.components]
manager = "debug"
store = "warn"
```

| Field | Description | Default |
|-------|-------------|---------|
| `level` | Log spec (e.g., `"info"` or `"info,manager=debug"`) | `"info"` |
| `format` | Output format: `"text"` or `"json"` | `"text"` |
| `components` | Map of component names to levels (alternative to inline) | (none) |

If both `level` and `components` are specified, `level` takes precedence.

**Note**: If the config file exists but contains invalid TOML, bpfman exits
with an error rather than silently falling back to defaults.

## Components

The following components can be configured independently:

| Component | Description |
|-----------|-------------|
| `manager` | BPF program lifecycle management |
| `server` | gRPC server operations |
| `store` | SQLite database operations |
| `driver` | CSI driver operations |

## Output Format

Log output defaults to text format:

```
time=YYYY-MM-DDT10:00:00.000Z level=INFO msg="opened database" component=store path=/run/bpfman/state.db
```

JSON format can be enabled via config file:

```toml
[logging]
format = "json"
```

```json
{"time":"YYYY-MM-DDT10:00:00.000Z","level":"INFO","msg":"opened database","component":"store","path":"/run/bpfman/state.db"}
```

## Examples

### Debugging a Specific Component

To debug manager operations while keeping other components quiet:

```bash
bpfman serve --log=warn,manager=debug
```

### Verbose Mode for Troubleshooting

Enable trace-level logging for all components:

```bash
bpfman serve --log=trace
```

### Production Configuration

Recommended production config file:

```toml
[logging]
level = "info"
format = "json"
```

### Development Configuration

For local development:

```bash
export BPFMAN_LOG=debug
bpfman serve
```

Or in config file:

```toml
[logging]
level = "debug,store=info"
format = "text"
```
