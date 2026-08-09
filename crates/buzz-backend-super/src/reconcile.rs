//! The deploy state machine (§Deploy State Machine).
//!
//! `deploy` is not "create": it is *converge to at-most-one-live-instance*
//! (I4), keyed on the identity this provider derived itself, within this
//! provider's deployment scope. For this binding the scope is **the host** —
//! not "instances this provider started" — which is why [`classify`] weighs
//! instances started by other launchers on the same machine.
//!
//! The rows this substrate has are a strict subset of the Kubernetes
//! binding's. There is no image to pull and nothing to schedule, so the
//! "never started but recoverable — observe, never delete" rows have no
//! states here: a process either exists or it does not. Six rows, no clocks,
//! and nothing destructive that is not fenced on the management marker.

use crate::config::ProviderConfig;
use crate::host::Host;
use crate::identity::{AgentIdentity, BINDING_VERSION, MANAGED_BY};
use crate::remote::{self, Report, REPORT_MARKER};
use crate::wire::DeployRequest;
use crate::{env, intent, redact};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// Where `agents.sh` — this host's hand-rolled launcher — keeps its pid files
/// and per-agent configuration.
///
/// Hardcoded rather than configured because it is a fact about this
/// substrate, in the same way pod labels are a fact about the Kubernetes one
/// ([L3] binding policy). It is read-only and best-effort: if the convention
/// ever changes, the scan finds nothing and this binding is back to the
/// spec's baseline promise, in which hand launchers sit outside the protocol
/// and carry the uniqueness discipline themselves.
const FOREIGN_RUN_DIR: &str = "$HOME/.buzz/run";
const FOREIGN_CONFIG_DIR: &str = "$HOME/.config/buzz-agents";

/// The desktop's own deploy timeout is 600s. Finishing inside it means the
/// user sees this provider's actionable error instead of a generic timeout.
const OPERATION_DEADLINE: Duration = Duration::from_secs(570);
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(60);
const CLEAR_TIMEOUT: Duration = Duration::from_secs(60);

/// What the reconciler decided to do about one observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// The observation cannot be trusted. Never classified further: an
    /// unusable report that fell through to `Create` would double-launch.
    Unusable(String),
    /// Two live instances of one key already exist. Reported, never repaired
    /// — picking one to kill is not this operation's call.
    ReportDuplicate { name: String },
    /// Another launcher on this host is already running this key.
    AdoptForeign { name: String, pid: String },
    /// Our own instance is live. Strict no-op — Start must never kill a
    /// running agent mid-turn (I3).
    NoOp { pid: String },
    /// State we authored, with nothing alive behind it. The normal restart
    /// path: clear it, then re-enter from step 1.
    ClearResidue,
    /// State we did not author. Fails closed to the operator rather than
    /// being repaired around (§Auto-repair fencing).
    ReportUnowned { marker: Option<String> },
    /// Nothing there. Create.
    Create,
}

/// Classify one observation. Pure — every I/O decision is the caller's, so
/// the whole state machine is testable without a host.
pub fn classify(report: &Report, our_digest: &str) -> Action {
    if !report.complete {
        return Action::Unusable(
            report
                .error
                .clone()
                .unwrap_or_else(|| "the host's reply was incomplete".to_string()),
        );
    }

    let foreign = report
        .foreign
        .iter()
        .find(|candidate| candidate.digest.eq_ignore_ascii_case(our_digest));

    // Ours *and* somebody else's, both live: an I4 violation that already
    // exists. Say so — a silent no-op here would hide the one state the
    // owner most needs to act on.
    if let (Some(other), true) = (foreign, report.alive) {
        return Action::ReportDuplicate {
            name: other.name.clone(),
        };
    }

    // Live under another launcher. "Already running" is the honest answer and
    // the same one the live row gives, so Start is idempotent across
    // launchers rather than a way to accidentally double-launch.
    if let Some(other) = foreign {
        return Action::AdoptForeign {
            name: other.name.clone(),
            pid: other.pid.clone(),
        };
    }

    if report.alive {
        return Action::NoOp {
            pid: report.pid.clone().unwrap_or_default(),
        };
    }

    if report.state_present {
        // Identity evidence is not ownership evidence: the state directory
        // name is derived from a public key, so anything could have created
        // it. Only the management marker licenses a delete.
        return if report.marker.as_deref() == Some(MANAGED_BY) {
            Action::ClearResidue
        } else {
            Action::ReportUnowned {
                marker: report.marker.clone(),
            }
        };
    }

    Action::Create
}

/// A random hex token. Used for the generation nonce and the scan salt.
fn token() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// Run one deploy to a terminal outcome.
pub fn deploy(request: &DeployRequest) -> Result<String, String> {
    let cfg = crate::config::parse(&request.provider_config)?;

    // Identity before any host contact: a malformed nsec is a refusal, not a
    // failed connection (§step 0). Everything below keys on this value.
    let identity = AgentIdentity::from_nsec(&request.agent.private_key_nsec)?;

    let nonce = token();
    let environment = env::build(&request.agent, &identity, &cfg, &nonce)?;
    let secrets = env::secret_values(&environment);

    // From here on the provider holds the nsec, so every error it can return
    // passes through the scrubber on its way out.
    run(&cfg, &identity, &environment, &nonce, request)
        .map_err(|error| redact::scrub(&error, &secrets))
}

fn run(
    cfg: &ProviderConfig,
    identity: &AgentIdentity,
    environment: &std::collections::BTreeMap<String, String>,
    nonce: &str,
    request: &DeployRequest,
) -> Result<String, String> {
    let host = Host::new(cfg);
    let agent_id = identity.agent_id(&cfg.host);
    let fingerprint = intent::fingerprint(&request.agent, cfg);

    // A fresh salt per call. It is what makes the cross-launcher scan a
    // yes/no answer about *this* key rather than a way to fingerprint every
    // other agent's key on the host.
    let salt = token();
    let our_digest = {
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        hasher.update(request.agent.private_key_nsec.trim().as_bytes());
        hex::encode(hasher.finalize())
    };

    let started_at = Instant::now();

    // One create attempt per call is enforced structurally: the `Create` arm
    // below returns on both outcomes, so control never re-enters this loop
    // after an attempt. That is deliberate rather than incidental. Looping
    // back would mean re-running an identical create against the same host
    // inside the same call, which cannot produce a different outcome — what
    // it produces is a hot create/kill cycle every poll interval for the
    // whole deadline. The failed attempt's state directory is left in place
    // so the *next* Start clears it, which gates the retry on fresh owner
    // intent and bounds the litter at one directory per press.
    loop {
        if started_at.elapsed() >= OPERATION_DEADLINE {
            return Err(format!(
                "the agent's startup was not confirmed within {}s",
                OPERATION_DEADLINE.as_secs()
            ));
        }

        let observation = observe(&host, cfg, identity, &salt)?;

        match classify(&observation, &our_digest) {
            Action::Unusable(why) => {
                return Err(format!(
                    "could not read the agent's state on the host: {why}"
                ))
            }

            Action::ReportDuplicate { name } => {
                return Err(format!(
                    "this agent's key is already running twice on {}: once under this \
                     provider, and once as `{name}`. Stop one of them before deploying \
                     — two processes on one key will both answer every message.",
                    cfg.host
                ))
            }

            Action::AdoptForeign { name, pid } => {
                // Strict no-op, and honest about why: the desktop records the
                // id and presence takes over as the status signal (I3).
                eprintln!(
                    "agent already running on {} as `{name}` (pid {pid}), started outside \
                     this provider — adopting it rather than starting a second copy",
                    cfg.host
                );
                return Ok(agent_id);
            }

            Action::NoOp { pid } => {
                if observation.intent.as_deref() != Some(fingerprint.as_str()) {
                    // §Documented consequence: live is a strict no-op whatever
                    // the fingerprint says. Saying so is the whole value of
                    // recording it — otherwise an edit that has not taken
                    // effect looks like an edit that did not save.
                    eprintln!(
                        "agent already running on {} (pid {pid}); its configuration has \
                         changed since it started, and the change will apply the next \
                         time it starts",
                        cfg.host
                    );
                }
                return Ok(agent_id);
            }

            Action::ReportUnowned { marker } => {
                return Err(format!(
                    "{}/{} on {} holds state this provider did not create{} — \
                     refusing to delete it. Remove it by hand if it is stale.",
                    cfg.state_dir,
                    identity.pubkey_hex(),
                    cfg.host,
                    match marker {
                        Some(m) => format!(" (it is marked `{m}`)"),
                        None => " (it has no management marker)".to_string(),
                    }
                ))
            }

            Action::ClearResidue => {
                clear(&host, cfg, identity)?;
                continue;
            }

            Action::Create => {
                let result = create(&host, cfg, identity, environment, nonce, &fingerprint)?;
                if result.started == Some(true) {
                    return Ok(agent_id);
                }
                return Err(start_failure(&result, cfg));
            }
        }
    }
}

/// Compose the actionable error for a harness that did not stay up.
///
/// Startup is part of create (§Startup is part of create): reporting success
/// at "the process was spawned" would hand back an id for something that
/// never became an agent. The log tail is what makes the failure fixable, and
/// it is scrubbed on the way out by [`deploy`].
fn start_failure(report: &Report, cfg: &ProviderConfig) -> String {
    let mut message = format!(
        "the agent did not stay running on {} (it exited within {}s of starting)",
        cfg.host, cfg.startup_settle_seconds
    );
    if let Some(error) = &report.error {
        message.push_str(&format!("; {error}"));
    }
    match report
        .log_tail
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        Some(log) => message.push_str(&format!("\n\nlast lines of its log:\n{log}")),
        None => message.push_str(
            "\n\nits log was empty — check that the harness binary exists on the host \
             and that the ACP agent command is on the PATH the provider prepends.",
        ),
    }
    message
}

fn observe(
    host: &Host,
    cfg: &ProviderConfig,
    identity: &AgentIdentity,
    salt: &str,
) -> Result<Report, String> {
    let output = host.run(
        &remote::observe_script(),
        &[
            cfg.state_dir.clone(),
            identity.pubkey_hex().to_string(),
            salt.to_string(),
            FOREIGN_RUN_DIR.to_string(),
            FOREIGN_CONFIG_DIR.to_string(),
        ],
        OBSERVE_TIMEOUT,
    )?;
    finish("read the agent's state", output, cfg)
}

fn clear(host: &Host, cfg: &ProviderConfig, identity: &AgentIdentity) -> Result<Report, String> {
    let output = host.run(
        &remote::clear_script(),
        &[
            cfg.state_dir.clone(),
            identity.pubkey_hex().to_string(),
            MANAGED_BY.to_string(),
        ],
        CLEAR_TIMEOUT,
    )?;
    let report = finish("clear the previous run", output, cfg)?;
    if let Some(error) = &report.error {
        return Err(format!(
            "could not clear the previous run on {}: {error}",
            cfg.host
        ));
    }
    Ok(report)
}

fn create(
    host: &Host,
    cfg: &ProviderConfig,
    identity: &AgentIdentity,
    environment: &std::collections::BTreeMap<String, String>,
    nonce: &str,
    fingerprint: &str,
) -> Result<Report, String> {
    let delimiter = format!("__BUZZ_ENV_{}__", token());
    let script = remote::create_script(&env::render_env_file(environment), &delimiter)?;

    let output = host.run(
        &script,
        &[
            cfg.state_dir.clone(),
            identity.pubkey_hex().to_string(),
            cfg.path_prepend.clone(),
            cfg.harness_command.clone(),
            MANAGED_BY.to_string(),
            BINDING_VERSION.to_string(),
            fingerprint.to_string(),
            nonce.to_string(),
            cfg.startup_settle_seconds.to_string(),
        ],
        // The settle sleep happens on the host, so this call is at least that
        // long by construction.
        Duration::from_secs(cfg.startup_settle_seconds + 120),
    )?;
    finish("start the agent", output, cfg)
}

/// Turn one remote invocation into a trusted report, or a diagnosable error.
fn finish(what: &str, output: crate::host::Output, cfg: &ProviderConfig) -> Result<Report, String> {
    // The absence of the marker line means the script never ran — a host
    // without bash, a login shell that printed a banner and exited, an ssh
    // that failed to authenticate. None of those are "no agent found", and
    // classifying them as such would authorize a create.
    if !output.stdout.contains(REPORT_MARKER) {
        let detail = [output.stderr.trim(), output.stdout.trim()]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or("it produced no output");
        return Err(format!("could not {what} on {}: {detail}", cfg.host));
    }

    let report = remote::parse_report(&output.stdout);

    if !output.succeeded() && !report.complete {
        let detail = output.stderr.trim();
        return Err(format!(
            "could not {what} on {}: the host's script exited with {}{}",
            cfg.host,
            output
                .status
                .map(|c| c.to_string())
                .unwrap_or_else(|| "a signal".to_string()),
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        ));
    }

    if let Some(error) = report.error.as_deref() {
        if error.starts_with("bad-pubkey") {
            return Err("the host rejected the derived public key".to_string());
        }
        if error == "harness-not-found" {
            return Err(format!(
                "the harness binary `{}` was not found on {} — set `harness_command` to \
                 its absolute path, or add it to the PATH in `path_prepend`.",
                cfg.harness_command, cfg.host
            ));
        }
        if error == "cannot-create-state-dir" {
            return Err(format!(
                "could not create {} on {} — check the directory's permissions.",
                cfg.state_dir, cfg.host
            ));
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::ForeignInstance;

    const OUR_DIGEST: &str = "deadbeef";

    fn report(lines: &str) -> Report {
        remote::parse_report(lines)
    }

    #[test]
    fn nothing_there_creates() {
        assert_eq!(
            classify(&report("report=1\nstate=absent\nend=1\n"), OUR_DIGEST),
            Action::Create
        );
    }

    /// Start must never kill a live agent mid-turn. "Already running" is the
    /// honest answer (I3, I4).
    #[test]
    fn a_live_instance_is_a_strict_no_op() {
        let action = classify(
            &report("report=1\nstate=present\nmarker=buzz-backend-super\npid=99\nalive=1\nend=1\n"),
            OUR_DIGEST,
        );
        assert_eq!(
            action,
            Action::NoOp {
                pid: "99".to_string()
            }
        );
    }

    /// The normal restart path: a reaped or shut-down agent revives.
    #[test]
    fn our_own_residue_is_cleared() {
        assert_eq!(
            classify(
                &report(
                    "report=1\nstate=present\nmarker=buzz-backend-super\npid=99\nalive=0\nend=1\n"
                ),
                OUR_DIGEST
            ),
            Action::ClearResidue
        );
    }

    /// Identity evidence is not ownership evidence. The state directory name
    /// is derived from a *public* key, so anything could have created it —
    /// only the management marker licenses a delete.
    #[test]
    fn state_we_did_not_author_is_reported_not_deleted() {
        assert_eq!(
            classify(
                &report("report=1\nstate=present\nalive=0\nend=1\n"),
                OUR_DIGEST
            ),
            Action::ReportUnowned { marker: None }
        );
        assert_eq!(
            classify(
                &report("report=1\nstate=present\nmarker=something-else\nalive=0\nend=1\n"),
                OUR_DIGEST
            ),
            Action::ReportUnowned {
                marker: Some("something-else".to_string())
            }
        );
    }

    /// The property this binding exists to preserve on a host that already
    /// runs hand-launched agents: a Start for a key another launcher is
    /// already running must adopt it, never start a second copy.
    #[test]
    fn a_key_running_under_another_launcher_is_adopted() {
        let mut r = report("report=1\nstate=absent\nend=1\n");
        r.foreign.push(ForeignInstance {
            name: "ace".into(),
            pid: "1234".into(),
            digest: OUR_DIGEST.into(),
        });
        assert_eq!(
            classify(&r, OUR_DIGEST),
            Action::AdoptForeign {
                name: "ace".into(),
                pid: "1234".into()
            }
        );
    }

    /// Other agents on the host are not ours — their presence must not stop
    /// or divert this deploy.
    #[test]
    fn other_agents_on_the_host_are_ignored() {
        let mut r = report("report=1\nstate=absent\nend=1\n");
        r.foreign.push(ForeignInstance {
            name: "architect".into(),
            pid: "1".into(),
            digest: "another-key-entirely".into(),
        });
        r.foreign.push(ForeignInstance {
            name: "content".into(),
            pid: "2".into(),
            digest: "yet-another".into(),
        });
        assert_eq!(classify(&r, OUR_DIGEST), Action::Create);
    }

    #[test]
    fn digest_comparison_is_case_insensitive() {
        let mut r = report("report=1\nstate=absent\nend=1\n");
        r.foreign.push(ForeignInstance {
            name: "ace".into(),
            pid: "1".into(),
            digest: "DEADBEEF".into(),
        });
        assert!(matches!(
            classify(&r, "deadbeef"),
            Action::AdoptForeign { .. }
        ));
    }

    /// Already two live instances of one key. Reporting beats silently
    /// no-op'ing: this is the state the owner most needs to know about, and
    /// choosing which one to kill is not this operation's call.
    #[test]
    fn two_live_instances_are_reported() {
        let mut r =
            report("report=1\nstate=present\nmarker=buzz-backend-super\npid=99\nalive=1\nend=1\n");
        r.foreign.push(ForeignInstance {
            name: "ace".into(),
            pid: "1234".into(),
            digest: OUR_DIGEST.into(),
        });
        assert_eq!(
            classify(&r, OUR_DIGEST),
            Action::ReportDuplicate {
                name: "ace".to_string()
            }
        );
    }

    /// The single most dangerous misclassification: a dropped connection
    /// mid-report must never read as "nothing there", because that
    /// authorizes a create and double-launches a live agent.
    #[test]
    fn an_incomplete_report_is_never_classified_further() {
        for truncated in [
            "report=1\nstate=absent\n",
            "report=1\n",
            "report=1\nstate=present\nalive=1\n",
            "",
        ] {
            assert!(
                matches!(
                    classify(&report(truncated), OUR_DIGEST),
                    Action::Unusable(_)
                ),
                "classified an incomplete report: {truncated:?}"
            );
        }
    }

    /// A reused pid is reported as not-alive by the host, so the residue is
    /// replaced rather than no-op'd against forever.
    #[test]
    fn a_reused_pid_leads_to_replacement_not_a_no_op() {
        assert_eq!(
            classify(
                &report(
                    "report=1\nstate=present\nmarker=buzz-backend-super\npid=99\n\
                     exe=/usr/bin/vim\nalive=0\nstale_pid=1\nend=1\n"
                ),
                OUR_DIGEST
            ),
            Action::ClearResidue
        );
    }

    #[test]
    fn start_failure_names_the_host_and_carries_the_log() {
        let cfg = crate::config::parse(&serde_json::json!({"host": "super"})).unwrap();
        let r = report("report=1\nstarted=0\nlogtail<<\nboom: no such file\n>>logtail\nend=1\n");
        let message = start_failure(&r, &cfg);
        assert!(message.contains("super"), "{message}");
        assert!(message.contains("boom: no such file"), "{message}");
    }

    #[test]
    fn start_failure_without_a_log_says_where_to_look() {
        let cfg = crate::config::parse(&serde_json::json!({"host": "super"})).unwrap();
        let message = start_failure(&report("report=1\nstarted=0\nend=1\n"), &cfg);
        assert!(message.contains("PATH"), "{message}");
    }

    #[test]
    fn tokens_are_unique_and_hex() {
        let a = token();
        let b = token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
