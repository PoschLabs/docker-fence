//! Configuration file parsing.
//!
//! The configuration file lists networks containers must not be able to
//! reach (`block`) and exceptions to that (`allow`), one entry per line:
//!
//! ```text
//! # management network, except the jump host
//! block 192.0.2.0/24        # inline comments are allowed
//! allow 192.0.2.10/32
//! block 2001:db8:10::/64
//! ```
//!
//! * Each entry is `block <network>` or `allow <network>`. The keywords are
//!   lowercase, and an entry without one is an error.
//! * A network is a CIDR such as `192.0.2.0/24`, or a single address such as
//!   `192.0.2.10` or `2001:db8::5`, which means that one host (`/32` or `/128`).
//! * `#` starts a comment that runs to the end of the line.
//! * Blank lines and surrounding whitespace (including `\r` and tabs) are ignored.
//! * Host bits are cleared, so `block 192.0.2.5/24` is stored as `192.0.2.0/24`.
//! * Exact duplicates (same action and network after normalisation) are
//!   dropped; first-seen order is kept.
//! * Listing the same network as both `block` and `allow` is an error.
//!
//! When entries overlap, the **most specific** one (longest prefix) wins. That
//! ordering is applied when rules are generated, see [`crate::rules`]; the
//! parsed [`FenceConfig`] keeps file order.

use ipnet::IpNet;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Location of the configuration file when `--config` is not given.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/docker-fence/docker-fence.conf";

/// What to do with new connections towards an entry's network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Reject new connections from containers.
    Block,
    /// Let connections through; an exception inside a larger blocked network.
    Allow,
}

impl Action {
    /// The keyword used for this action in the configuration file.
    pub fn keyword(self) -> &'static str {
        match self {
            Action::Block => "block",
            Action::Allow => "allow",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.keyword())
    }
}

/// One line of the configuration: an [`Action`] for a network `N`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<N> {
    /// Whether the network is blocked or allowed.
    pub action: Action,
    /// The network, with host bits cleared.
    pub net: N,
}

/// The configured entries, split by address family.
///
/// Both lists are normalised (host bits cleared), free of duplicates and
/// ordered as they first appeared in the file. No network appears with both
/// actions. Either list may be empty.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FenceConfig {
    /// IPv4 entries, enforced with `iptables`.
    pub v4: Vec<Entry<ipnet::Ipv4Net>>,
    /// IPv6 entries, enforced with `ip6tables`.
    pub v6: Vec<Entry<ipnet::Ipv6Net>>,
}

/// An error encountered while reading or parsing the configuration file.
///
/// Its [`Display`](fmt::Display) output is `path:line: message` for syntax
/// errors and `path: message` when no particular line is involved (for
/// example when the file cannot be read).
#[derive(Debug)]
pub struct ConfigError {
    /// The file being read; used only for error reporting.
    pub path: PathBuf,
    /// 1-based line number of the offending entry, or `None` for errors that
    /// concern the file as a whole.
    pub line: Option<usize>,
    /// Human-readable description of the problem.
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(n) => write!(f, "{}:{}: {}", self.path.display(), n, self.message),
            None => write!(f, "{}: {}", self.path.display(), self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parses a network: a CIDR (host bits cleared) or a single address, which
/// becomes a `/32` or `/128` host network.
fn parse_network(text: &str) -> Option<IpNet> {
    match text.parse::<IpNet>() {
        Ok(net) => Some(net.trunc()),
        Err(_) => text.parse::<IpAddr>().ok().map(IpNet::from),
    }
}

/// Parses configuration `text` into a [`FenceConfig`].
///
/// `path` is not read; it is only recorded in any returned [`ConfigError`].
/// See the [module documentation](self) for the accepted syntax.
///
/// # Errors
///
/// Returns a [`ConfigError`] carrying the 1-based line number of the first
/// problem: a missing or unknown action keyword, an invalid CIDR, trailing
/// text, or a network that was already listed with the opposite action.
pub fn parse(text: &str, path: &Path) -> Result<FenceConfig, ConfigError> {
    let mut cfg = FenceConfig::default();
    // First action and line number seen for each normalised network.
    let mut seen: HashMap<IpNet, (Action, usize)> = HashMap::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        let content = raw.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }
        let err = |message: String| ConfigError {
            path: path.to_path_buf(),
            line: Some(line),
            message,
        };
        let mut toks = content.split_whitespace();
        let (keyword, cidr) = match (toks.next(), toks.next(), toks.next()) {
            (Some(keyword), Some(cidr), None) => (keyword, cidr),
            (Some(only), None, _) if parse_network(only).is_some() => {
                return Err(err(format!(
                    "missing action before {only:?} (write `block {only}` or `allow {only}`)"
                )));
            }
            _ => {
                return Err(err(format!(
                    "invalid entry {content:?} (expected `block <cidr>` or `allow <cidr>`, \
                     e.g. block 192.0.2.0/24)"
                )));
            }
        };
        let action = match keyword {
            "block" => Action::Block,
            "allow" => Action::Allow,
            _ => {
                return Err(err(format!(
                    "unknown action {keyword:?} (expected `block` or `allow`)"
                )));
            }
        };
        let net = parse_network(cidr).ok_or_else(|| {
            err(format!(
                "invalid network {cidr:?} (expected a CIDR such as 192.0.2.0/24 or a host such as 192.0.2.10)"
            ))
        })?;
        match seen.get(&net) {
            Some(&(first, _)) if first == action => continue,
            Some(&(first, first_line)) => {
                return Err(err(format!(
                    "{net} is listed as both {first} (line {first_line}) and {action}"
                )));
            }
            None => {
                seen.insert(net, (action, line));
            }
        }
        match net {
            IpNet::V4(net) => cfg.v4.push(Entry { action, net }),
            IpNet::V6(net) => cfg.v6.push(Entry { action, net }),
        }
    }
    Ok(cfg)
}

/// Reads the file at `path` and parses it with [`parse`].
///
/// # Errors
///
/// Returns a [`ConfigError`] with `line == None` if the file cannot be read,
/// or the error from [`parse`] if its contents are invalid.
pub fn load(path: &Path) -> Result<FenceConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError {
        path: path.to_path_buf(),
        line: None,
        message: format!("cannot read config: {e}"),
    })?;
    parse(&text, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> &'static Path {
        Path::new("/etc/x.conf")
    }

    fn v4(action: Action, net: &str) -> Entry<ipnet::Ipv4Net> {
        Entry {
            action,
            net: net.parse().unwrap(),
        }
    }

    fn v6(action: Action, net: &str) -> Entry<ipnet::Ipv6Net> {
        Entry {
            action,
            net: net.parse().unwrap(),
        }
    }

    #[test]
    fn parses_mixed_families_actions_comments_crlf_and_tabs() {
        let c = parse(
            "# mgmt\r\nblock 192.0.2.0/24\t # inline\r\nallow\t192.0.2.10/32\r\n\r\n\
             block   2001:db8:10::/64  \n",
            p(),
        )
        .unwrap();
        assert_eq!(
            c.v4,
            vec![
                v4(Action::Block, "192.0.2.0/24"),
                v4(Action::Allow, "192.0.2.10/32")
            ]
        );
        assert_eq!(c.v6, vec![v6(Action::Block, "2001:db8:10::/64")]);
    }

    #[test]
    fn normalises_host_bits() {
        let c = parse("block 192.0.2.5/24", p()).unwrap();
        assert_eq!(c.v4, vec![v4(Action::Block, "192.0.2.0/24")]);
    }

    #[test]
    fn bare_cidr_is_rejected_with_hint_and_line_number() {
        let e = parse("block 192.0.2.0/24\n192.0.2.5/32\n", p()).unwrap_err();
        assert_eq!(e.line, Some(2));
        assert!(e.to_string().starts_with("/etc/x.conf:2:"));
        assert!(e.message.contains("missing action"), "{e}");
        assert!(e.message.contains("block 192.0.2.5/32"), "{e}");
    }

    #[test]
    fn bare_address_means_a_single_host() {
        let c = parse(
            "allow 192.0.2.10\nblock 2001:db8::5\nallow 192.0.2.11/32\n",
            p(),
        )
        .unwrap();
        assert_eq!(
            c.v4,
            vec![
                v4(Action::Allow, "192.0.2.10/32"),
                v4(Action::Allow, "192.0.2.11/32")
            ]
        );
        assert_eq!(c.v6, vec![v6(Action::Block, "2001:db8::5/128")]);
        // Same host written both ways is a duplicate, and a conflict across actions.
        assert_eq!(
            parse("allow 192.0.2.10\nallow 192.0.2.10/32\n", p())
                .unwrap()
                .v4
                .len(),
            1
        );
        assert!(parse("allow 192.0.2.10\nblock 192.0.2.10/32\n", p()).is_err());
    }

    #[test]
    fn rejects_unknown_action() {
        let e = parse("deny 192.0.2.0/24", p()).unwrap_err();
        assert_eq!(e.line, Some(1));
        assert!(e.message.contains("unknown action"), "{e}");
        // Keywords are case-sensitive.
        assert!(parse("BLOCK 192.0.2.0/24", p()).is_err());
    }

    #[test]
    fn rejects_garbage() {
        for s in [
            "hello",
            "block",
            "block 192.0.2.256",
            "block 192.0.2.0/33",
            "block 192.0.2.0/24 extra",
            "allow",
        ] {
            assert!(parse(s, p()).is_err(), "{s}");
        }
    }

    #[test]
    fn dedupes_exact_duplicates_keeping_order() {
        let c = parse(
            "block 192.0.2.0/25\nallow 198.51.100.0/24\nblock 192.0.2.0/25\nblock 192.0.2.5/25\n",
            p(),
        )
        .unwrap();
        assert_eq!(
            c.v4,
            vec![
                v4(Action::Block, "192.0.2.0/25"),
                v4(Action::Allow, "198.51.100.0/24")
            ]
        );
    }

    #[test]
    fn same_network_as_block_and_allow_is_an_error_naming_both_lines() {
        let e = parse("block 192.0.2.0/24\n\nallow 192.0.2.77/24\n", p()).unwrap_err();
        assert_eq!(e.line, Some(3));
        assert!(e.message.contains("both block (line 1) and allow"), "{e}");
    }

    #[test]
    fn same_text_in_different_families_does_not_conflict() {
        let c = parse("block 192.0.2.0/24\nallow 2001:db8::/32\n", p()).unwrap();
        assert_eq!(c.v4.len(), 1);
        assert_eq!(c.v6.len(), 1);
    }

    #[test]
    fn empty_and_comment_only_are_ok() {
        for s in ["", "\n\n", "# only\n  # comment\n"] {
            let c = parse(s, p()).unwrap();
            assert!(c.v4.is_empty() && c.v6.is_empty());
        }
    }

    #[test]
    fn load_missing_file_errors_without_line() {
        let e = load(Path::new("/nonexistent/docker-fence.conf")).unwrap_err();
        assert_eq!(e.line, None);
    }
}
