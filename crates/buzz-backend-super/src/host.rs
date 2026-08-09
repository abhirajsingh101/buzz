//! The SSH transport.
//!
//! Every remote operation is one `ssh host bash -s -- args` with the script on
//! stdin. Nothing is ever interpolated into a remote command line: the script
//! is a constant, and its inputs arrive as positional parameters, so a config
//! value cannot become remote syntax.
//!
//! Auth comes from the ambient SSH agent and `~/.ssh/config` — never from
//! `provider_config` (I2's corollary for providers: substrate credentials come
//! from ambient configuration, never from the persisted settings object).

use crate::config::ProviderConfig;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The result of one remote invocation.
pub struct Output {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn succeeded(&self) -> bool {
        self.status == Some(0)
    }
}

pub struct Host {
    destination: String,
    port: u16,
    identity_file: Option<String>,
}

impl Host {
    pub fn new(cfg: &ProviderConfig) -> Self {
        Self {
            destination: match &cfg.user {
                Some(user) => format!("{user}@{}", cfg.host),
                None => cfg.host.clone(),
            },
            port: cfg.port,
            identity_file: cfg.identity_file.clone(),
        }
    }

    /// PATH the provider gives itself before spawning `ssh`.
    ///
    /// A desktop launched from Finder inherits launchd's minimal PATH, which
    /// omits both Homebrew prefixes. `/usr/bin/ssh` is always present, so this
    /// is not usually load-bearing — but a user whose `ssh` is a Homebrew
    /// build with their config's `Match exec` helpers on it would otherwise
    /// get a different binary here than in their terminal, and debug that
    /// difference for an hour.
    fn augmented_path() -> String {
        let existing = std::env::var("PATH").unwrap_or_default();
        let mut prefixes = vec![
            "/opt/homebrew/bin".to_string(),
            "/usr/local/bin".to_string(),
        ];
        if let Some(home) = std::env::var_os("HOME") {
            prefixes.push(format!("{}/.local/bin", home.to_string_lossy()));
        }
        prefixes.push(existing);
        prefixes.join(":")
    }

    fn ssh_args(&self, script_args: &[String]) -> Vec<String> {
        let mut args = vec![
            // Never prompt. A provider is spawned by a GUI with no terminal;
            // an interactive password prompt would hang until the operation
            // deadline and report a timeout instead of "no credentials".
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "ConnectTimeout=10".into(),
            "-o".into(),
            "ServerAliveInterval=15".into(),
            "-o".into(),
            "ServerAliveCountMax=4".into(),
            "-p".into(),
            self.port.to_string(),
        ];
        if let Some(identity) = &self.identity_file {
            args.push("-i".into());
            args.push(identity.clone());
        }
        // `--` terminates option parsing before the destination, so a
        // destination can never be read as a flag.
        args.push("--".into());
        args.push(self.destination.clone());
        args.push("bash".into());
        args.push("-s".into());
        args.push("--".into());
        args.extend(script_args.iter().cloned());
        args
    }

    /// Run one script on the host, bounded by `timeout`.
    pub fn run(
        &self,
        script: &str,
        script_args: &[String],
        timeout: Duration,
    ) -> Result<Output, String> {
        let mut child = Command::new("ssh")
            .args(self.ssh_args(script_args))
            .env("PATH", Self::augmented_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("could not run ssh: {e}"))?;

        // stdin, stdout and stderr are each drained on their own thread. A
        // single-threaded "write everything, then poll for exit" would
        // deadlock the moment the script's output exceeded a pipe buffer —
        // which a harness log tail can do.
        let script = script.to_string();
        let mut stdin = child.stdin.take();
        let writer = std::thread::spawn(move || {
            if let Some(pipe) = stdin.as_mut() {
                let _ = pipe.write_all(script.as_bytes());
            }
            drop(stdin);
        });
        let stdout = drain(child.stdout.take());
        let stderr = drain(child.stderr.take());

        let status = wait_bounded(&mut child, timeout)?;

        let _ = writer.join();
        let stdout = stdout.join().unwrap_or_default();
        let stderr = stderr.join().unwrap_or_default();

        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

/// Read a pipe to EOF on its own thread, capped.
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<String> {
    // Bounded for the same reason the desktop bounds its read of *this*
    // process's output: a remote script that streams without end must not be
    // able to exhaust memory here.
    const CAP: usize = 256 * 1024;
    std::thread::spawn(move || {
        let Some(mut pipe) = pipe else {
            return String::new();
        };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok(n) = pipe.read(&mut chunk) {
            if n == 0 {
                break;
            }
            if buf.len() < CAP {
                buf.extend_from_slice(&chunk[..n.min(CAP - buf.len())]);
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    })
}

/// Wait for the child, killing it if `timeout` elapses.
fn wait_bounded(child: &mut Child, timeout: Duration) -> Result<Option<i32>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code()),
            Ok(None) => {}
            Err(e) => return Err(format!("could not wait for ssh: {e}")),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "the host did not respond within {}s",
                timeout.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn host(cfg: serde_json::Value) -> Host {
        Host::new(&crate::config::parse(&cfg).unwrap())
    }

    #[test]
    fn builds_a_plain_destination() {
        let args = host(json!({"host": "super"})).ssh_args(&[]);
        assert!(args.contains(&"super".to_string()));
        assert!(!args.iter().any(|a| a.contains('@')));
    }

    #[test]
    fn builds_a_user_destination() {
        let args = host(json!({"host": "super", "user": "abhi"})).ssh_args(&[]);
        assert!(args.contains(&"abhi@super".to_string()));
    }

    #[test]
    fn passes_port_and_identity_file() {
        let args = host(json!({
            "host": "super", "port": 2222, "identity_file": "/home/me/.ssh/id_ed25519"
        }))
        .ssh_args(&[]);
        let joined = args.join(" ");
        assert!(joined.contains("-p 2222"), "{joined}");
        assert!(joined.contains("-i /home/me/.ssh/id_ed25519"), "{joined}");
    }

    /// Never prompt: a provider spawned by a GUI has no terminal, so an
    /// interactive prompt would hang to the deadline and be reported as a
    /// timeout rather than as missing credentials.
    #[test]
    fn ssh_never_prompts() {
        let joined = host(json!({"host": "super"})).ssh_args(&[]).join(" ");
        assert!(joined.contains("BatchMode=yes"), "{joined}");
    }

    /// The script is a constant and its inputs are positional parameters, so
    /// a value can never become remote shell syntax.
    #[test]
    fn script_args_are_positional_after_a_separator() {
        let args = host(json!({"host": "super"}))
            .ssh_args(&["/state".to_string(), "; rm -rf /".to_string()]);
        let tail: Vec<&String> = args.iter().skip_while(|a| *a != "bash").collect();
        assert_eq!(tail[0], "bash");
        assert_eq!(tail[1], "-s");
        assert_eq!(tail[2], "--");
        assert_eq!(tail[3], "/state");
        assert_eq!(tail[4], "; rm -rf /");
    }

    /// The destination sits after `--`, so even a value that slipped the
    /// config validator could not be parsed as an ssh option.
    #[test]
    fn destination_follows_an_option_terminator() {
        let args = host(json!({"host": "super"})).ssh_args(&[]);
        let dash_dash = args.iter().position(|a| a == "--").expect("terminator");
        assert_eq!(args[dash_dash + 1], "super");
    }

    #[test]
    fn augmented_path_keeps_the_existing_entries() {
        let path = Host::augmented_path();
        assert!(path.contains("/opt/homebrew/bin"));
        assert!(path.contains("/usr/local/bin"));
        if let Ok(existing) = std::env::var("PATH") {
            if !existing.is_empty() {
                assert!(path.ends_with(&existing), "existing PATH was dropped");
            }
        }
    }

    /// A script that never exits must be killed at the deadline rather than
    /// hanging the provider past the desktop's own 600s timeout.
    #[test]
    fn a_hung_command_is_killed_at_the_deadline() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .spawn()
            .expect("sleep is available");
        let started = Instant::now();
        let result = wait_bounded(&mut child, Duration::from_millis(300));
        assert!(result.is_err(), "expected a timeout");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_prompt_command_reports_its_exit_code() {
        let mut child = Command::new("false").spawn().expect("false is available");
        let status = wait_bounded(&mut child, Duration::from_secs(5)).unwrap();
        assert_eq!(status, Some(1));
    }
}
