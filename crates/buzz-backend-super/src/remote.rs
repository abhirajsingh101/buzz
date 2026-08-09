//! The scripts that run on the host, and the reports they emit.
//!
//! Three of them — observe, create, clear — matching the three things the
//! reconciler needs to do. They are POSIX-ish bash, kept deliberately dull:
//! this is the code that runs unattended on a machine full of live agents,
//! and every clever line is one nobody can audit at 2am.
//!
//! The report format is `key=value` lines rather than JSON because the remote
//! side has no JSON encoder it can rely on, and a hand-rolled one in bash is
//! exactly the kind of quoting bug that would misreport a live agent as dead.

/// Emitted by every script as its first line. Its absence means the script
/// never ran — a login shell that printed a banner and died, a host without
/// bash — which must never be read as "no instance found".
pub const REPORT_MARKER: &str = "report=1";

/// One instance found on the host that this provider did not create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignInstance {
    /// The launcher's own name for it (for `agents.sh`, the env-file stem).
    pub name: String,
    pub pid: String,
    /// `sha256(salt || nsec)`, computed on the host.
    pub digest: String,
}

/// What the host reports about one agent identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The script ran to completion. Anything else is unusable.
    pub complete: bool,
    /// A provider state directory exists for this pubkey.
    pub state_present: bool,
    pub marker: Option<String>,
    pub binding: Option<String>,
    pub intent: Option<String>,
    pub pid: Option<String>,
    pub alive: bool,
    pub exe: Option<String>,
    /// The recorded pid belongs to a process that is not the harness we
    /// launched — it was reused after the agent died.
    pub stale_pid: bool,
    pub started: Option<bool>,
    pub log_tail: Option<String>,
    pub error: Option<String>,
    pub foreign: Vec<ForeignInstance>,
}

/// Parse a script's stdout.
///
/// Unknown keys are ignored so a newer script can add a field without
/// breaking an older provider; a missing `end=1` leaves `complete` false, and
/// the reconciler refuses to act on an incomplete report.
pub fn parse_report(stdout: &str) -> Report {
    let mut report = Report::default();
    let mut in_log = false;
    let mut log = String::new();

    for line in stdout.lines() {
        if in_log {
            if line == ">>logtail" {
                in_log = false;
                report.log_tail = Some(log.trim_end().to_string());
            } else {
                log.push_str(line);
                log.push('\n');
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            if line == "logtail<<" {
                in_log = true;
            }
            continue;
        };
        match key {
            "state" => report.state_present = value == "present",
            "marker" => report.marker = non_empty(value),
            "binding" => report.binding = non_empty(value),
            "intent" => report.intent = non_empty(value),
            "pid" => report.pid = non_empty(value),
            "alive" => report.alive = value == "1",
            "stale_pid" => report.stale_pid = value == "1",
            "exe" => report.exe = non_empty(value),
            "started" => report.started = Some(value == "1"),
            "cleared" => report.started = report.started.or(Some(false)),
            "error" => report.error = non_empty(value),
            "refused" => report.error = Some(format!("refused: {value}")),
            "end" => report.complete = value == "1",
            "foreign" => {
                let mut parts = value.split_whitespace();
                if let (Some(name), Some(pid), Some(digest)) =
                    (parts.next(), parts.next(), parts.next())
                {
                    report.foreign.push(ForeignInstance {
                        name: name.to_string(),
                        pid: pid.to_string(),
                        digest: digest.to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    report
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Shared prologue: expand `$HOME`/`~` in provider paths without `eval`.
///
/// The desktop cannot know the remote home directory, so config defaults
/// carry `$HOME` literally. Expanding with `eval` would turn a config string
/// into arbitrary remote execution; bash parameter substitution does the one
/// job needed and nothing else.
const EXPAND_HOME: &str = r#"
expand_home() {
  local v=$1
  v=${v//\$HOME/$HOME}
  v=${v/#\~/$HOME}
  printf '%s' "$v"
}
"#;

/// Refuse any pubkey that is not exactly 64 lowercase hex characters.
///
/// The provider derives the pubkey itself, so this can never fire in
/// practice. It is here because the value is concatenated into a path that a
/// later script passes to `rm -rf`, and a guard on that path should not
/// depend on a correctness argument made in another language.
const GUARD_PUBKEY: &str = r#"
case "$PUBKEY" in
  *[!0-9a-f]*|"") printf 'error=bad-pubkey\nend=1\n'; exit 5 ;;
esac
if [ ${#PUBKEY} -ne 64 ]; then printf 'error=bad-pubkey\nend=1\n'; exit 5; fi
"#;

/// Observe one identity: this provider's own state, plus any instance another
/// launcher on the same host is running for the same key.
///
/// Args: `STATE_DIR PUBKEY SALT RUN_DIR CFG_DIR`
///
/// The cross-launcher scan is what makes I4 hold on this substrate. The scope
/// here is *the host*, not "instances this provider created" — and the host
/// already runs agents started by hand. Without this scan, a Start from the
/// desktop would launch a second process holding the same nsec, and the spec
/// would be satisfied only on a technicality (hand launchers "sit outside the
/// protocol by construction") while the user got two agents answering every
/// mention.
///
/// The match is by **salted digest**, never by reading the other agents'
/// keys back to the desktop: the caller sends a fresh random salt, the host
/// hashes `salt || nsec` for each running agent, and only digests come back.
/// A collision proves same-key; a non-match reveals nothing. Reading twelve
/// live nsecs onto every admin's laptop to answer a yes/no question would be
/// the wrong trade.
pub fn observe_script() -> String {
    format!(
        r#"set -u
STATE_DIR=$1; PUBKEY=$2; SALT=$3; RUN_DIR=$4; CFG_DIR=$5
printf 'report=1\n'
{GUARD_PUBKEY}
{EXPAND_HOME}
STATE_DIR=$(expand_home "$STATE_DIR")
RUN_DIR=$(expand_home "$RUN_DIR")
CFG_DIR=$(expand_home "$CFG_DIR")
DIR="$STATE_DIR/$PUBKEY"

digest_of() {{
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | cut -d' ' -f1
  else
    printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
  fi
}}

if [ -d "$DIR" ]; then
  printf 'state=present\n'
  if [ -f "$DIR/marker" ];  then printf 'marker=%s\n'  "$(cat "$DIR/marker"  2>/dev/null)"; fi
  if [ -f "$DIR/binding" ]; then printf 'binding=%s\n' "$(cat "$DIR/binding" 2>/dev/null)"; fi
  if [ -f "$DIR/intent" ];  then printf 'intent=%s\n'  "$(cat "$DIR/intent"  2>/dev/null)"; fi
  P=$(cat "$DIR/pid" 2>/dev/null || true)
  if [ -n "$P" ]; then printf 'pid=%s\n' "$P"; fi
  if [ -n "$P" ] && [ -d "/proc/$P" ]; then
    LIVE_EXE=$(readlink -f "/proc/$P/exe" 2>/dev/null || true)
    WANT_EXE=$(cat "$DIR/exe" 2>/dev/null || true)
    printf 'exe=%s\n' "$LIVE_EXE"
    # A dead agent's pid can be reused by an unrelated process. Reporting
    # that stranger as the live agent would wedge the identity forever:
    # every Start would no-op against it, and nothing would ever restart the
    # agent. Comparing against the binary recorded at launch closes that.
    if [ -n "$WANT_EXE" ] && [ "$LIVE_EXE" != "$WANT_EXE" ]; then
      printf 'alive=0\nstale_pid=1\n'
    else
      printf 'alive=1\n'
    fi
  else
    printf 'alive=0\n'
  fi
else
  printf 'state=absent\n'
fi

# Cross-launcher scan (I4 across every launcher on this host).
if [ -d "$RUN_DIR" ]; then
  for f in "$RUN_DIR"/*.pid; do
    [ -f "$f" ] || continue
    n=$(basename "$f" .pid)
    p=$(cat "$f" 2>/dev/null || true)
    [ -n "$p" ] || continue
    [ -d "/proc/$p" ] || continue
    c="$CFG_DIR/$n.env"
    [ -f "$c" ] || continue
    # Strip quotes and every kind of surrounding whitespace: bech32 contains
    # none of them, and a stray trailing space would produce a digest miss —
    # which is the one failure direction that matters here, because it would
    # let a second instance of a live agent be launched.
    k=$(sed -n 's/^[[:space:]]*BUZZ_PRIVATE_KEY=//p' "$c" 2>/dev/null | tail -n 1 | tr -d '\040\011\015\042\047')
    [ -n "$k" ] || continue
    printf 'foreign=%s %s %s\n' "$n" "$p" "$(digest_of "$SALT$k")"
  done
fi
printf 'end=1\n'
exit 0
"#
    )
}

/// Write the environment and launch the harness, then confirm it stayed up.
///
/// Args: `STATE_DIR PUBKEY PATH_PREPEND HARNESS MARKER BINDING INTENT NONCE SETTLE`
///
/// Two properties are load-bearing:
///
/// * **The harness is exec'd, not called.** `exec` makes the harness the
///   process that receives the termination signal. A wrapper that ran it as a
///   child without forwarding signals would void both I5's substrate half and
///   the graceful-shutdown budget: the signal would land on the wrapper, the
///   harness would never learn to shut down, and the force-kill would leave
///   presence stale-online — exactly the staleness window the grace period
///   exists to close.
/// * **No supervisor.** Nothing restarts this process, which satisfies I5's
///   restart rule vacuously — the spec's explicit allowance for a launcher
///   with no supervisor at all. A `Restart=on-failure` unit would be strictly
///   better *after* the harness's exit-code contract is pinned by test
///   (Known Defect 6); shipping it before that is how every clean `!shutdown`
///   silently becomes a restart loop with no failing test to catch it.
///
/// The environment travels inside the script over the SSH channel, so the
/// nsec never appears in an argv, a process listing, or a shell history on
/// either machine.
pub fn create_script(env_body: &str, delimiter: &str) -> Result<String, String> {
    // A value containing the delimiter on a line of its own would end the
    // heredoc early and spill the rest of the environment into the shell as
    // commands. The delimiter is random per call, so this is unreachable —
    // and checked anyway, because "unreachable" and "unchecked" is how that
    // class of bug ships.
    if env_body.lines().any(|line| line.trim_end() == delimiter) {
        return Err("could not serialize the agent environment safely".to_string());
    }

    Ok(format!(
        r#"set -u
STATE_DIR=$1; PUBKEY=$2; PATH_PREPEND=$3; HARNESS=$4
MARKER=$5; BINDING=$6; INTENT=$7; NONCE=$8; SETTLE=$9
printf 'report=1\n'
{GUARD_PUBKEY}
{EXPAND_HOME}
STATE_DIR=$(expand_home "$STATE_DIR")
PATH_PREPEND=$(expand_home "$PATH_PREPEND")
DIR="$STATE_DIR/$PUBKEY"

umask 077
mkdir -p "$DIR/workspace" || {{ printf 'error=cannot-create-state-dir\nend=1\n'; exit 3; }}

cat > "$DIR/env" <<'{delimiter}'
{env_body}{delimiter}
chmod 600 "$DIR/env"

printf '%s' "$MARKER"  > "$DIR/marker"
printf '%s' "$BINDING" > "$DIR/binding"
printf '%s' "$INTENT"  > "$DIR/intent"
printf '%s' "$NONCE"   > "$DIR/nonce"
: > "$DIR/log"

export PATH="$PATH_PREPEND:$PATH"
if ! command -v "$HARNESS" >/dev/null 2>&1 && [ ! -x "$HARNESS" ]; then
  printf 'error=harness-not-found\nend=1\n'; exit 4
fi

rm -f "$DIR/pid"
# The child records its own pid and then execs, so the recorded pid *is* the
# harness. Capturing $! in this shell would record the intermediate shell,
# and setsid re-parents anyway.
setsid bash -c '
  cd "$1" || exit 1
  set -a; . "$2" || exit 1; set +a
  echo $$ > "$3"
  exec "$4" >>"$5" 2>&1
' _ "$DIR/workspace" "$DIR/env" "$DIR/pid" "$HARNESS" "$DIR/log" </dev/null >/dev/null 2>&1 &
disown 2>/dev/null || true

sleep "$SETTLE"
P=$(cat "$DIR/pid" 2>/dev/null || true)
if [ -n "$P" ] && [ -d "/proc/$P" ]; then
  # Recorded so a later observe can tell this process from an unrelated one
  # that inherits its pid after it dies.
  readlink -f "/proc/$P/exe" > "$DIR/exe" 2>/dev/null || true
  printf 'started=1\npid=%s\n' "$P"
  printf 'exe=%s\n' "$(cat "$DIR/exe" 2>/dev/null || true)"
else
  printf 'started=0\n'
  printf 'logtail<<\n'
  tail -n 25 "$DIR/log" 2>/dev/null || true
  printf '>>logtail\n'
fi
printf 'end=1\n'
exit 0
"#
    ))
}

/// Remove this provider's residue for one identity.
///
/// Args: `STATE_DIR PUBKEY MARKER`
///
/// Fenced twice, and both fences are the point (§Auto-repair fencing). The
/// management marker must match, so residue this provider did not author is
/// reported rather than repaired around; and the recorded pid must be dead,
/// so a live agent can never be deleted by a classification that went stale
/// between the observation and this call.
pub fn clear_script() -> String {
    format!(
        r#"set -u
STATE_DIR=$1; PUBKEY=$2; MARKER=$3
printf 'report=1\n'
{GUARD_PUBKEY}
{EXPAND_HOME}
STATE_DIR=$(expand_home "$STATE_DIR")
DIR="$STATE_DIR/$PUBKEY"

if [ ! -d "$DIR" ]; then printf 'cleared=1\nend=1\n'; exit 0; fi

M=$(cat "$DIR/marker" 2>/dev/null || true)
if [ "$M" != "$MARKER" ]; then printf 'refused=not-ours\nend=1\n'; exit 0; fi

P=$(cat "$DIR/pid" 2>/dev/null || true)
if [ -n "$P" ] && [ -d "/proc/$P" ]; then printf 'refused=still-alive\nend=1\n'; exit 0; fi

rm -rf "$DIR"
printf 'cleared=1\nend=1\n'
exit 0
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_live_instance() {
        let report = parse_report(
            "report=1\nstate=present\nmarker=buzz-backend-super\nbinding=1\n\
             intent=abc123\npid=4242\nalive=1\nexe=/usr/bin/buzz-acp\nend=1\n",
        );
        assert!(report.complete);
        assert!(report.state_present);
        assert!(report.alive);
        assert_eq!(report.pid.as_deref(), Some("4242"));
        assert_eq!(report.marker.as_deref(), Some("buzz-backend-super"));
        assert_eq!(report.intent.as_deref(), Some("abc123"));
    }

    #[test]
    fn parses_an_absent_instance() {
        let report = parse_report("report=1\nstate=absent\nend=1\n");
        assert!(report.complete);
        assert!(!report.state_present);
        assert!(!report.alive);
    }

    /// A truncated report — a dropped connection mid-script — must never read
    /// as "no instance found", because that classification authorizes a
    /// create and would double-launch a live agent.
    #[test]
    fn a_truncated_report_is_incomplete() {
        let report = parse_report("report=1\nstate=absent\n");
        assert!(!report.complete);
    }

    /// A reused pid reports as not-alive, so the reconciler replaces the
    /// residue instead of no-op'ing against a stranger's process forever.
    #[test]
    fn a_reused_pid_is_not_alive() {
        let report = parse_report(
            "report=1\nstate=present\npid=4242\nexe=/usr/bin/vim\nalive=0\nstale_pid=1\nend=1\n",
        );
        assert!(report.complete);
        assert!(report.state_present);
        assert!(!report.alive);
        assert!(report.stale_pid);
    }

    #[test]
    fn parses_foreign_instances() {
        let report = parse_report(
            "report=1\nstate=absent\nforeign=ace 1234 deadbeef\n\
             foreign=architect 5678 cafebabe\nend=1\n",
        );
        assert_eq!(report.foreign.len(), 2);
        assert_eq!(report.foreign[0].name, "ace");
        assert_eq!(report.foreign[0].pid, "1234");
        assert_eq!(report.foreign[0].digest, "deadbeef");
        assert_eq!(report.foreign[1].name, "architect");
    }

    #[test]
    fn parses_a_failed_start_with_its_log() {
        let report = parse_report(
            "report=1\nstarted=0\nlogtail<<\nerror: could not connect\nretrying\n>>logtail\nend=1\n",
        );
        assert_eq!(report.started, Some(false));
        assert_eq!(
            report.log_tail.as_deref(),
            Some("error: could not connect\nretrying")
        );
    }

    /// A log line that happens to contain `=` must not be parsed as a field.
    #[test]
    fn log_content_is_not_parsed_as_fields() {
        let report = parse_report(
            "report=1\nstarted=0\nlogtail<<\nalive=1\nstate=present\n>>logtail\nend=1\n",
        );
        assert_eq!(report.started, Some(false));
        assert!(!report.alive);
        assert!(!report.state_present);
    }

    #[test]
    fn parses_refusals_as_errors() {
        let report = parse_report("report=1\nrefused=not-ours\nend=1\n");
        assert_eq!(report.error.as_deref(), Some("refused: not-ours"));
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let report = parse_report("report=1\nstate=absent\nfuture_field=x\nend=1\n");
        assert!(report.complete);
    }

    #[test]
    fn create_script_refuses_a_colliding_delimiter() {
        let body = "A='x'\nDELIM\nB='y'\n";
        assert!(create_script(body, "DELIM").is_err());
        assert!(create_script(body, "OTHER_DELIM").is_ok());
    }

    /// The three scripts must be syntactically valid bash. A quoting slip in
    /// a string literal is otherwise only discovered against a live host.
    #[test]
    fn scripts_are_valid_bash() {
        for (name, script) in [
            ("observe", observe_script()),
            ("clear", clear_script()),
            (
                "create",
                create_script("A='1'\n", "__BUZZ_ENV_TEST__").unwrap(),
            ),
        ] {
            let status = std::process::Command::new("bash")
                .arg("-n")
                .arg("-c")
                .arg(&script)
                .status()
                .expect("bash is available");
            assert!(status.success(), "{name} script is not valid bash");
        }
    }
}
