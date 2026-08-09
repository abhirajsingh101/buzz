//! `provider_config` parsing and the `info` config schema.
//!
//! No credential field exists, by I2: SSH auth comes from the ambient agent /
//! `~/.ssh/config` and nothing else. `identity_file` names a *path*, which is
//! why it is spelled that way — the desktop's I2 lint rejects any field whose
//! word-split contains `key`, and the spec's instruction to a provider author
//! hitting that lint is to rename the field, never to weaken the validator
//! (§I2).

/// Where the provider keeps its own per-agent state on the remote host.
/// Everything under here is provider-authored, which is what licenses the
/// destructive rows of the state machine to touch it (§Auto-repair fencing).
pub const DEFAULT_STATE_DIR: &str = "$HOME/.buzz/provider-super";

/// Prepended to the remote `PATH` before the harness is exec'd.
///
/// Not a convenience. A non-interactive `ssh host cmd` gets a login shell's
/// minimal PATH, and the ACP agents this host runs (`claude-agent-acp`) live
/// in `$HOME/.npm-global/bin`. Launching without this yields a harness that
/// starts, fails to spawn its agent, and dies — the failure mode that has
/// already cost this deployment two outages.
pub const DEFAULT_PATH_PREPEND: &str = "$HOME/.npm-global/bin:$HOME/.local/bin";

/// The remote harness binary. A *name* by default, resolved against the
/// remote PATH — the substrate-forced re-derivation rule (§Launch data):
/// a host path from the desktop's filesystem is meaningless here.
pub const DEFAULT_HARNESS_COMMAND: &str = "buzz-acp";

/// Default inactivity budget: **0, meaning no bound** (§Auto-Stop).
///
/// This binding's lifetime policy differs from the Kubernetes binding's 2h on
/// purpose, and the spec blesses both: a pod is metered compute with nobody
/// watching it, whereas this substrate is a host the owner already runs
/// continuously, hosting agents whose whole job is to be present in a channel.
/// Reaping those after two idle hours would be a bug, not a saving.
pub const DEFAULT_INACTIVITY_SECONDS: u64 = 0;

/// How long a freshly launched harness must stay alive before `deploy`
/// reports success. Startup is part of create (§Startup is part of create):
/// a process that execs and dies 200ms later never became an agent.
pub const DEFAULT_STARTUP_SETTLE_SECONDS: u64 = 5;

/// Default SSH port.
pub const DEFAULT_PORT: u16 = 22;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub host: String,
    pub user: Option<String>,
    pub port: u16,
    pub identity_file: Option<String>,
    pub harness_command: String,
    pub path_prepend: String,
    pub state_dir: String,
    /// `None` when `inactivity_seconds` is 0 — the explicit, blessed opt-in
    /// to an indefinitely-lived agent (§Auto-Stop).
    pub inactivity_seconds: Option<u64>,
    pub startup_settle_seconds: u64,
}

/// Read an optional non-empty string field. Rejects non-string scalars rather
/// than stringifying them, so a mistyped field is named at the boundary.
fn optional_string(cfg: &serde_json::Value, field: &str) -> Result<Option<String>, String> {
    match cfg.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => {
            let trimmed = s.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Some(_) => Err(format!("provider_config.{field} must be a string")),
    }
}

fn optional_u64(cfg: &serde_json::Value, field: &str) -> Result<Option<u64>, String> {
    match cfg.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| format!("provider_config.{field} must be a non-negative whole number"))
            .map(Some),
        // The desktop's schema-driven form coerces by declared type, but a
        // hand-edited record can still deliver a string. Accepting a clean
        // numeric string is kinder than failing a deploy over quoting.
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => s
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("provider_config.{field} must be a non-negative whole number"))
            .map(Some),
        Some(serde_json::Value::String(_)) => Ok(None),
        Some(_) => Err(format!("provider_config.{field} must be a number")),
    }
}

pub fn parse(cfg: &serde_json::Value) -> Result<ProviderConfig, String> {
    if !cfg.is_object() && !cfg.is_null() {
        return Err("provider_config must be a JSON object".to_string());
    }

    let host = optional_string(cfg, "host")?
        .ok_or_else(|| "provider_config.host is required — the SSH destination".to_string())?;
    // A destination that smuggles SSH options (`-oProxyCommand=…`) or a
    // command separator would turn a config field into arbitrary local
    // execution. The host is the one config value that reaches an argv.
    if host.starts_with('-') || host.contains(char::is_whitespace) {
        return Err(
            "provider_config.host must be a plain hostname or ssh alias, with no options or spaces"
                .to_string(),
        );
    }

    let user = optional_string(cfg, "user")?;
    if let Some(u) = &user {
        if u.starts_with('-') || u.contains(char::is_whitespace) || u.contains('@') {
            return Err("provider_config.user must be a plain username".to_string());
        }
    }

    let port = match optional_u64(cfg, "port")? {
        None => DEFAULT_PORT,
        Some(p) if p >= 1 && p <= u16::MAX as u64 => p as u16,
        Some(_) => return Err("provider_config.port must be between 1 and 65535".to_string()),
    };

    let identity_file = optional_string(cfg, "identity_file")?;
    if let Some(f) = &identity_file {
        if f.starts_with('-') {
            return Err("provider_config.identity_file must be a path".to_string());
        }
    }

    let harness_command = optional_string(cfg, "harness_command")?
        .unwrap_or_else(|| DEFAULT_HARNESS_COMMAND.to_string());
    let path_prepend =
        optional_string(cfg, "path_prepend")?.unwrap_or_else(|| DEFAULT_PATH_PREPEND.to_string());
    let state_dir =
        optional_string(cfg, "state_dir")?.unwrap_or_else(|| DEFAULT_STATE_DIR.to_string());

    let inactivity_seconds = match optional_u64(cfg, "inactivity_seconds")? {
        None => DEFAULT_INACTIVITY_SECONDS,
        Some(v) => v,
    };
    let startup_settle_seconds =
        optional_u64(cfg, "startup_settle_seconds")?.unwrap_or(DEFAULT_STARTUP_SETTLE_SECONDS);

    Ok(ProviderConfig {
        host,
        user,
        port,
        identity_file,
        harness_command,
        path_prepend,
        state_dir,
        // 0 is legal and means "no bound"; it MUST NOT be rejected (§Auto-Stop).
        inactivity_seconds: (inactivity_seconds > 0).then_some(inactivity_seconds),
        startup_settle_seconds,
    })
}

/// The `info` config schema. Drives the desktop's settings form.
pub fn config_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {
                "type": "string",
                "title": "SSH host",
                "description": "Hostname or ~/.ssh/config alias of the machine that runs the agents.",
                "default": "super"
            },
            "user": {
                "type": "string",
                "title": "SSH user",
                "description": "Leave empty to use your ~/.ssh/config default.",
                "default": ""
            },
            "port": {
                "type": "number",
                "title": "SSH port",
                "default": DEFAULT_PORT
            },
            "identity_file": {
                "type": "string",
                "title": "SSH identity file",
                "description": "Optional path to a private key file. Leave empty to use your SSH agent or ~/.ssh/config.",
                "default": ""
            },
            "harness_command": {
                "type": "string",
                "title": "Harness binary on the host",
                "description": "Name resolved against the host's PATH, or an absolute path.",
                "default": DEFAULT_HARNESS_COMMAND
            },
            "path_prepend": {
                "type": "string",
                "title": "PATH prepended on the host",
                "description": "Prepended before the harness runs, so it can find the ACP agent binary.",
                "default": DEFAULT_PATH_PREPEND
            },
            "state_dir": {
                "type": "string",
                "title": "Provider state directory on the host",
                "default": DEFAULT_STATE_DIR
            },
            "inactivity_seconds": {
                "type": "number",
                "title": "Stop after inactivity (seconds)",
                "description": "0 means no inactivity bound — the agent stays up until it is told to stop.",
                "default": DEFAULT_INACTIVITY_SECONDS
            },
            "startup_settle_seconds": {
                "type": "number",
                "title": "Startup settle (seconds)",
                "description": "How long the harness must stay alive before a deploy is reported successful.",
                "default": DEFAULT_STARTUP_SETTLE_SECONDS
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn host_is_required() {
        assert!(parse(&json!({})).is_err());
        assert!(parse(&json!({"host": "  "})).is_err());
    }

    #[test]
    fn defaults_fill_in() {
        let cfg = parse(&json!({"host": "super"})).unwrap();
        assert_eq!(cfg.host, "super");
        assert_eq!(cfg.port, 22);
        assert_eq!(cfg.harness_command, DEFAULT_HARNESS_COMMAND);
        assert_eq!(cfg.path_prepend, DEFAULT_PATH_PREPEND);
        assert_eq!(cfg.state_dir, DEFAULT_STATE_DIR);
        assert_eq!(cfg.startup_settle_seconds, DEFAULT_STARTUP_SETTLE_SECONDS);
    }

    /// Zero is the blessed "no inactivity bound" value (§Auto-Stop) — it is
    /// an explicit owner choice, not a misconfiguration, and MUST NOT be
    /// rejected. It is also this binding's default.
    #[test]
    fn zero_inactivity_is_no_bound_not_an_error() {
        assert_eq!(
            parse(&json!({"host": "h", "inactivity_seconds": 0}))
                .unwrap()
                .inactivity_seconds,
            None
        );
        assert_eq!(
            parse(&json!({"host": "h"})).unwrap().inactivity_seconds,
            None
        );
        assert_eq!(
            parse(&json!({"host": "h", "inactivity_seconds": 900}))
                .unwrap()
                .inactivity_seconds,
            Some(900)
        );
    }

    /// The host is the one config value that reaches an argv, so a value that
    /// could be read as an SSH option is refused at the boundary rather than
    /// handed to `ssh`.
    #[test]
    fn host_cannot_smuggle_ssh_options() {
        assert!(parse(&json!({"host": "-oProxyCommand=touch /tmp/pwned"})).is_err());
        assert!(parse(&json!({"host": "super -oProxyCommand=x"})).is_err());
        assert!(parse(&json!({"host": "a b"})).is_err());
    }

    #[test]
    fn user_must_be_plain() {
        assert!(parse(&json!({"host": "h", "user": "-oFoo=1"})).is_err());
        assert!(parse(&json!({"host": "h", "user": "abhi@elsewhere"})).is_err());
        assert_eq!(
            parse(&json!({"host": "h", "user": "abhi"}))
                .unwrap()
                .user
                .as_deref(),
            Some("abhi")
        );
    }

    #[test]
    fn port_is_bounded() {
        assert!(parse(&json!({"host": "h", "port": 0})).is_err());
        assert!(parse(&json!({"host": "h", "port": 70000})).is_err());
        assert_eq!(
            parse(&json!({"host": "h", "port": 2222})).unwrap().port,
            2222
        );
    }

    #[test]
    fn mistyped_fields_are_named() {
        let err = parse(&json!({"host": 42})).unwrap_err();
        assert!(err.contains("host"), "{err}");
    }

    /// The schema is what the desktop renders; a field the form cannot show
    /// is a field the user cannot set.
    #[test]
    fn schema_declares_every_parsed_field() {
        let schema = config_schema();
        let props = schema
            .get("properties")
            .and_then(|p| p.as_object())
            .expect("schema has properties");
        for field in [
            "host",
            "user",
            "port",
            "identity_file",
            "harness_command",
            "path_prepend",
            "state_dir",
            "inactivity_seconds",
            "startup_settle_seconds",
        ] {
            assert!(props.contains_key(field), "schema is missing {field}");
        }
    }

    /// I2 is enforced on the desktop, but a field name that trips its lint
    /// would make this provider undeployable — so the naming rule is pinned
    /// on this side too, where the field names actually live.
    #[test]
    fn no_config_field_name_trips_the_i2_lint() {
        let schema = config_schema();
        let props = schema
            .get("properties")
            .and_then(|p| p.as_object())
            .expect("schema has properties");
        let banned = ["secret", "password", "token", "key", "credential"];
        for name in props.keys() {
            for word in name.split(['_', '-', '.', ' ']) {
                assert!(
                    !banned.contains(&word.to_ascii_lowercase().as_str()),
                    "config field `{name}` contains I2-banned word `{word}`"
                );
            }
        }
    }
}
