# Runtime External Rules

This folder is read by the engine when `ENGINE_EXTERNAL_RULES_ENABLED=1`.

Supported file extensions:

- `.yml`
- `.yaml`

Supported fields (YAML subset):

- `id`: unique rule id (required)
- `name`: display name
- `event_type`: `process_start|network_connect|file_open|auth_failure` (required)
- `severity`: `info|low|medium|high|critical`
- `risk_score`: integer
- `summary`: custom alert summary
- `summary_template`: optional summary template with `{{field}}` placeholders
- `tags`: inline list `[a, b]` or block list
- `match`: `all` (default) or `any`
- `min_hits`: threshold count before alerting (default `1`)
- `window_seconds`: sliding window used with `min_hits`
- `alert_cooldown_seconds`: suppression interval after alert fires
- `group_by`: fields used to aggregate event buckets for thresholding
- `conditions`: list of conditions

Condition fields:

- `path`: field path (required), for example `event.process.cmdline`
- `op`: `equals|contains|starts_with|ends_with|regex` (required)
- `value`: expected value

Noise reduction behavior:

- `min_hits=1` means per-event alerting.
- `min_hits>1` enables thresholding within `window_seconds`.
- When `alert_cooldown_seconds` is set, repeated hits in the same group are suppressed during cooldown.
- If `min_hits>1` and no cooldown is set, cooldown defaults to `window_seconds`.

Summary template behavior:

- `summary_template` supports placeholders like `{{host}}`, `{{event.auth.user_name}}`, `{{event.process.cmdline}}`.
- Rule metadata placeholders are also supported: `{{rule.id}}`, `{{rule.name}}`, `{{rule.min_hits}}`, `{{rule.window_seconds}}`.
- Threshold metadata is available as `{{match.current_hits}}` and `{{match.group_key}}`.
- Missing values render as `<missing>` so template issues are visible during tuning.

Path examples:

- `event.process.cmdline`
- `event.network.dst_port`
- `event.file.path`
- `event.auth.user_name`
- `host`
- `event_type`

## Sigma-like Detection Support (Lightweight)

The loader also supports a limited Sigma-like layout:

- `title` (or `name`)
- `id`
- `description`
- `summary_template` (runtime extension)
- `level`
- `detection`
	- `selection_*` blocks with field operators:
		- `field`: equals
		- `field|contains`
		- `field|startswith`
		- `field|endswith`
		- `field|re`
	- `condition` supports:
		- `selection_name`
		- `selection_a and selection_b`
		- `selection_a or selection_b`
		- `all of selection*`
		- `1 of selection*`

Notes:

- At least one selector must include `event_type` (for example `event_type: process_start`).
- This is a pragmatic subset for runtime loading, not the full Sigma spec.
