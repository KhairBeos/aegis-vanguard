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

## Included Runtime Rule Pack

The repository ships with a starter runtime pack in this folder:

- `external_suspicious_download_exec.yml`: process download-and-execute behavior.
- `external_auth_admin_failures.yml`: thresholded privileged auth failures.
- `sigma_like_suspicious_download.yml`: Sigma-like parser example.
- `external_reverse_shell_one_liner.yml`: shell-based reverse shell one-liners.
- `external_temp_dropper_write.yml`: suspicious writable payload drops in temp paths.
- `external_rare_c2_port_egress.yml`: repeated outbound traffic to rare C2 ports.
- `external_privileged_auth_burst.yml`: burst failures against privileged identities.
- `external_data_staging_archive.yml`: tar/zip/7z staging over sensitive paths.
- `external_interpreter_tmp_exec.yml`: interpreter execution from temporary directories.
- `external_download_chmod_exec.yml`: download then chmod +x execution chain.
- `external_smb_rdp_lateral_movement.yml`: repeated SMB/RDP/WinRM egress attempts.
- `external_dns_tunnel_tool_exec.yml`: known DNS tunneling tool execution patterns.
- `external_sensitive_file_enum.yml`: sensitive file access enumeration.
- `external_archive_created_in_tmp.yml`: archive artifact creation in temp paths.
- `external_auth_source_bruteforce.yml`: source-IP-centric auth brute-force thresholding.
- `external_recon_scanner_tool_exec.yml`: scanner tool execution (nmap/masscan/zmap).
