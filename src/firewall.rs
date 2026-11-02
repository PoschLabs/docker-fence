//! Access to the system firewall.
//!
//! The [`Firewall`] trait is the seam between the high-level operations in
//! [`crate::ops`] and the outside world. [`SystemFirewall`] implements it by
//! running the `iptables` / `ip6tables` family of binaries; tests substitute
//! an in-memory fake.

use std::fmt;
use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};

use crate::rules::Family;

/// A failure while talking to the firewall tools.
///
/// Wraps a ready-to-display message, typically including the tool name and
/// its trimmed stderr output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallError(pub String);

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FirewallError {}

/// Operations on the `filter` table that docker-fence needs.
pub trait Firewall {
    /// Lists the rules of `chain` in `iptables -S` format, one entry per line.
    ///
    /// `Ok(None)` means the chain does not exist. Any `Err` is a listing
    /// failure: a hard error for IPv4; for IPv6 it is tolerated only when
    /// [`ipv6_available`](Self::ipv6_available) is false or no IPv6 subnets
    /// are configured.
    fn list_chain(&self, family: Family, chain: &str)
    -> Result<Option<Vec<String>>, FirewallError>;

    /// Applies an `iptables-restore --noflush` `script` for `family`.
    ///
    /// The script is committed as a single transaction: either all of it
    /// takes effect or none of it does.
    ///
    /// # Errors
    ///
    /// Returns a [`FirewallError`] if the tool cannot be run or exits
    /// unsuccessfully.
    fn restore(&self, family: Family, script: &str) -> Result<(), FirewallError>;

    /// Whether the kernel has IPv6 at all (false for `ipv6.disable=1`).
    fn ipv6_available(&self) -> bool;
}

/// The real [`Firewall`], backed by the `iptables` command-line tools.
///
/// Uses `iptables` / `ip6tables` for listing and `iptables-restore` /
/// `ip6tables-restore` for changes (see [`Family::tool`] and
/// [`Family::restore_tool`]). Requires privileges to modify the firewall.
///
/// Like `wg-quick`, every command is echoed to stderr as `[#] <command>`
/// before it runs. Scripts fed to `*-restore` are shown as a heredoc.
pub struct SystemFirewall {
    /// When true, commands that would change the firewall are printed but not
    /// executed. Read-only listings still run, because the changes cannot be
    /// computed without knowing the current rules.
    pub dry_run: bool,
}

/// Prefix of echoed commands, as used by `wg-quick`.
const TRACE_PREFIX: &str = "[#]";

/// Formats `tool args...` the way it is echoed, e.g. `[#] iptables -w 10 -S DOCKER-USER`.
fn format_command(tool: &str, args: &[&str]) -> String {
    let mut line = format!("{TRACE_PREFIX} {tool}");
    for arg in args {
        line.push(' ');
        line.push_str(arg);
    }
    line
}

/// Formats a command that reads `script` from stdin as a shell heredoc, so
/// the echoed text can be pasted into a shell.
fn format_restore(tool: &str, args: &[&str], script: &str) -> String {
    let mut text = format_command(tool, args);
    text.push_str(" <<'EOF'\n");
    text.push_str(script);
    if !script.ends_with('\n') {
        text.push('\n');
    }
    text.push_str("EOF");
    text
}

/// Bounded xtables lock wait (seconds). A bare `-w` could block a oneshot
/// unit forever; nft-backed tools accept and ignore the flag.
const LOCK_WAIT: &str = "10";

/// Arguments for listing `chain` as rule specifications (`-S`), waiting at
/// most [`LOCK_WAIT`] seconds for the xtables lock.
fn list_args(chain: &str) -> [&str; 4] {
    ["-w", LOCK_WAIT, "-S", chain]
}

/// Arguments for `*-restore` that keep existing chains (`--noflush`) and wait
/// at most [`LOCK_WAIT`] seconds for the xtables lock.
fn restore_args() -> [&'static str; 3] {
    ["-w", LOCK_WAIT, "--noflush"]
}

/// Converts a failure to start `tool` into a [`FirewallError`].
///
/// A missing binary gets an actionable hint to install the iptables package.
fn spawn_error(tool: &str, e: std::io::Error) -> FirewallError {
    if e.kind() == ErrorKind::NotFound {
        FirewallError(format!("{tool} not found; install the iptables package"))
    } else {
        FirewallError(format!("failed to run {tool}: {e}"))
    }
}

/// Runs `tool` with `args`, optionally feeding `stdin`, and waits for it.
///
/// Returns `(exit code, stdout, stderr)`. The exit code is `None` if the
/// process was terminated by a signal; output is decoded lossily as UTF-8.
///
/// # Errors
///
/// Fails if the process cannot be spawned, its stdin cannot be written, or
/// waiting for it fails. A non-zero exit status is *not* an error here.
fn run(
    tool: &str,
    args: &[&str],
    stdin: Option<&str>,
) -> Result<(Option<i32>, String, String), FirewallError> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| spawn_error(tool, e))?;
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().expect("piped stdin");
        pipe.write_all(input.as_bytes())
            .map_err(|e| FirewallError(format!("failed to write to {tool}: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| FirewallError(format!("failed to wait for {tool}: {e}")))?;
    Ok((
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

impl Firewall for SystemFirewall {
    /// Checks for `/proc/sys/net/ipv6`, which is absent when IPv6 is disabled.
    fn ipv6_available(&self) -> bool {
        std::path::Path::new("/proc/sys/net/ipv6").exists()
    }

    /// Runs `<tool> -S <chain>`.
    ///
    /// Exit status 1 with "No chain/target/match by that name" on stderr is
    /// mapped to `Ok(None)`; every other failure is an `Err`.
    fn list_chain(
        &self,
        family: Family,
        chain: &str,
    ) -> Result<Option<Vec<String>>, FirewallError> {
        let tool = family.tool();
        let args = list_args(chain);
        eprintln!("{}", format_command(tool, &args));
        let (code, stdout, stderr) = run(tool, &args, None)?;
        if code == Some(0) {
            return Ok(Some(stdout.lines().map(str::to_string).collect()));
        }
        if code == Some(1) && stderr.contains("No chain/target/match by that name") {
            return Ok(None);
        }
        Err(FirewallError(format!(
            "{tool} -S {chain} failed: {}",
            stderr.trim()
        )))
    }

    /// Pipes `script` into `<tool>-restore --noflush`.
    ///
    /// The command and script are echoed first. In dry-run mode that is all
    /// that happens and the call succeeds without running anything.
    fn restore(&self, family: Family, script: &str) -> Result<(), FirewallError> {
        let tool = family.restore_tool();
        let args = restore_args();
        eprintln!("{}", format_restore(tool, &args, script));
        if self.dry_run {
            return Ok(());
        }
        let (code, _, stderr) = run(tool, &args, Some(script))?;
        if code == Some(0) {
            Ok(())
        } else {
            Err(FirewallError(format!("{tool} failed: {}", stderr.trim())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocations_use_bounded_lock_wait() {
        assert_eq!(list_args("DOCKER-USER"), ["-w", "10", "-S", "DOCKER-USER"]);
        assert_eq!(restore_args(), ["-w", "10", "--noflush"]);
    }

    #[test]
    fn commands_are_echoed_like_wg_quick() {
        assert_eq!(
            format_command("iptables", &list_args("DOCKER-USER")),
            "[#] iptables -w 10 -S DOCKER-USER"
        );
    }

    #[test]
    fn restore_script_is_echoed_as_heredoc() {
        assert_eq!(
            format_restore("iptables-restore", &restore_args(), "*filter\nCOMMIT\n"),
            "[#] iptables-restore -w 10 --noflush <<'EOF'\n*filter\nCOMMIT\nEOF"
        );
        // A script without trailing newline still gets its terminator on its own line.
        assert!(format_restore("x", &[], "a").ends_with("\na\nEOF"));
    }

    #[test]
    fn dry_run_restore_runs_nothing() {
        // Succeeds even though the restore tool may not exist on this machine.
        let fw = SystemFirewall { dry_run: true };
        assert_eq!(fw.restore(Family::V4, "*filter\nCOMMIT\n"), Ok(()));
    }

    #[test]
    fn missing_binary_error_names_the_package() {
        let err = run("docker-fence-no-such-tool", &["-S"], None).unwrap_err();
        assert!(err.0.contains("install the iptables package"), "{err}");
    }
}
