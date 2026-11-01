use std::fmt;
use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};

use crate::rules::Family;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallError(pub String);

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FirewallError {}

pub trait Firewall {
    /// `Ok(None)` means the chain does not exist.
    fn list_chain(&self, family: Family, chain: &str) -> Result<Option<Vec<String>>, FirewallError>;
    fn restore(&self, family: Family, script: &str) -> Result<(), FirewallError>;
}

pub struct SystemFirewall;

fn spawn_error(tool: &str, e: std::io::Error) -> FirewallError {
    if e.kind() == ErrorKind::NotFound {
        FirewallError(format!("{tool} not found; install the iptables package"))
    } else {
        FirewallError(format!("failed to run {tool}: {e}"))
    }
}

/// Run `tool args`, optionally feeding `stdin`. Returns (exit code, stdout, stderr).
fn run(tool: &str, args: &[&str], stdin: Option<&str>) -> Result<(Option<i32>, String, String), FirewallError> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
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
    fn list_chain(&self, family: Family, chain: &str) -> Result<Option<Vec<String>>, FirewallError> {
        let tool = family.tool();
        let (code, stdout, stderr) = run(tool, &["-S", chain], None)?;
        if code == Some(0) {
            return Ok(Some(stdout.lines().map(str::to_string).collect()));
        }
        if code == Some(1) && stderr.contains("No chain/target/match by that name") {
            return Ok(None);
        }
        Err(FirewallError(format!("{tool} -S {chain} failed: {}", stderr.trim())))
    }

    fn restore(&self, family: Family, script: &str) -> Result<(), FirewallError> {
        let tool = family.restore_tool();
        let (code, _, stderr) = run(tool, &["--noflush"], Some(script))?;
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
    fn missing_binary_error_names_the_package() {
        let err = run("docker-fence-no-such-tool", &["-S"], None).unwrap_err();
        assert!(err.0.contains("install the iptables package"), "{err}");
    }
}
