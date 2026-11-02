//! Pure rule generation and parsing.
//!
//! Nothing here touches the system: functions turn data into
//! `iptables-restore` script text, or parse `iptables -S` output back into
//! data. That keeps the exact rule layout easy to unit-test.
//!
//! # Rule layout
//!
//! iptables evaluates a chain top to bottom and the first matching rule wins.
//! To make the **most specific** entry win, entries are sorted by prefix
//! length, longest first (file order breaks ties), and each one becomes a
//! `RETURN` (allow) or `REJECT` (block) rule per bridge interface:
//!
//! ```text
//! -A DOCKER-FENCE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
//! -A DOCKER-FENCE -i docker0 -d 10.1.2.7/32 -j RETURN   # allow 10.1.2.7/32
//! -A DOCKER-FENCE -i br+     -d 10.1.2.7/32 -j RETURN
//! -A DOCKER-FENCE -i docker0 -d 10.1.2.0/24 -j REJECT   # block 10.1.2.0/24
//! -A DOCKER-FENCE -i br+     -d 10.1.2.0/24 -j REJECT
//! -A DOCKER-FENCE -i docker0 -d 10.0.0.0/8  -j REJECT   # block 10.0.0.0/8
//! -A DOCKER-FENCE -i br+     -d 10.0.0.0/8  -j REJECT
//! ```
//!
//! plus one `-A DOCKER-USER -j DOCKER-FENCE` jump as the first rule of
//! `DOCKER-USER`. Traffic that matches no rule falls out of the chain and is
//! accepted as before.

use std::cmp::Reverse;
use std::collections::BTreeSet;

use ipnet::IpNet;

use crate::config::Action;

/// Name of the chain owned and managed by docker-fence.
pub const CHAIN: &str = "DOCKER-FENCE";

/// Docker's hook chain for user rules; docker-fence only ever adds or removes
/// its jump here and never declares or flushes the chain itself.
pub const USER_CHAIN: &str = "DOCKER-USER";

/// Interfaces the rules are matched on: the default bridge and all
/// user-defined bridges.
const INTERFACES: [&str; 2] = ["docker0", "br+"];

/// IP address family, selecting which set of iptables tools to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    /// IPv4, managed with `iptables`.
    V4,
    /// IPv6, managed with `ip6tables`.
    V6,
}

impl Family {
    /// The command used to inspect rules: `iptables` or `ip6tables`.
    pub fn tool(self) -> &'static str {
        match self {
            Family::V4 => "iptables",
            Family::V6 => "ip6tables",
        }
    }

    /// The command used to apply a rule script: `iptables-restore` or
    /// `ip6tables-restore`.
    pub fn restore_tool(self) -> &'static str {
        match self {
            Family::V4 => "iptables-restore",
            Family::V6 => "ip6tables-restore",
        }
    }
}

/// A configured entry of a single family: an action for a network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Block or allow.
    pub action: Action,
    /// The network, with host bits cleared.
    pub net: IpNet,
}

/// One per-interface rule inside `DOCKER-FENCE`.
///
/// This is the structured form of
/// `-A DOCKER-FENCE -i <iface> -d <dst> -j RETURN|REJECT`, used both for
/// rendering the expected rules and for reading back the installed ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FenceRule {
    /// The incoming interface the rule matches (`docker0` or `br+`).
    pub iface: String,
    /// The destination network in CIDR notation.
    pub dst: String,
    /// [`Action::Allow`] is a `RETURN`, [`Action::Block`] a `REJECT`.
    pub action: Action,
}

impl FenceRule {
    /// The rule in `-A` form, as passed to `iptables-restore`.
    pub fn render(&self) -> String {
        let target = match self.action {
            Action::Allow => "RETURN",
            Action::Block => "REJECT",
        };
        format!("-A {CHAIN} -i {} -d {} -j {target}", self.iface, self.dst)
    }

    /// Short human-readable form, such as `block 192.0.2.0/24`.
    pub fn summary(&self) -> String {
        format!("{} {}", self.action, self.dst)
    }
}

/// What the `DOCKER-USER` chain currently contains with respect to the jump
/// to [`CHAIN`], as computed by [`parse_jump_state`].
#[derive(Debug, PartialEq, Eq)]
pub struct JumpState {
    /// Number of `-A DOCKER-USER -j DOCKER-FENCE` rules found. The desired
    /// value is exactly `1`.
    pub count: usize,
    /// Whether the first appended rule of `DOCKER-USER` is that jump.
    /// `false` when the chain has no rules.
    pub at_top: bool,
}

/// The per-network rules [`CHAIN`] must contain for `targets`, in order.
///
/// Sorted by prefix length, longest first, so that the most specific entry is
/// reached first. The sort is stable: entries of equal length (which cannot
/// overlap, as identical networks are rejected by the parser) keep their
/// input order. Each target yields one rule per interface.
pub fn fence_rules(targets: &[Target]) -> Vec<FenceRule> {
    let mut sorted: Vec<&Target> = targets.iter().collect();
    sorted.sort_by_key(|t| Reverse(t.net.prefix_len()));
    sorted
        .into_iter()
        .flat_map(|t| {
            INTERFACES.iter().map(move |iface| FenceRule {
                iface: (*iface).to_string(),
                dst: t.net.to_string(),
                action: t.action,
            })
        })
        .collect()
}

/// The complete rules (in `-A` form, in order) that [`CHAIN`] must contain
/// for `targets`: the conntrack exception followed by [`fence_rules`].
///
/// The first rule returns early for established/related traffic so replies
/// still flow.
///
/// ```text
/// expected_rules([block 192.0.2.0/24]) ==
///   -A DOCKER-FENCE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
///   -A DOCKER-FENCE -i docker0 -d 192.0.2.0/24 -j REJECT
///   -A DOCKER-FENCE -i br+ -d 192.0.2.0/24 -j REJECT
/// ```
pub fn expected_rules(targets: &[Target]) -> Vec<String> {
    let mut rules = vec![format!(
        "-A {CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
    )];
    rules.extend(fence_rules(targets).iter().map(FenceRule::render));
    rules
}

/// Returns the `allow` targets that can never take effect.
///
/// An allow is an exception, so it only matters when the closest enclosing
/// entry (the one with the longest shorter prefix containing it) is a
/// `block`. An allow with no enclosing entry, or one nested directly inside
/// another allow, changes nothing because unlisted traffic is already
/// accepted.
pub fn ineffective_allows(targets: &[Target]) -> Vec<&Target> {
    targets
        .iter()
        .filter(|t| t.action == Action::Allow)
        .filter(|t| {
            let closest = targets
                .iter()
                .filter(|o| o.net.prefix_len() < t.net.prefix_len() && o.net.contains(&t.net))
                .max_by_key(|o| o.net.prefix_len());
            !matches!(closest, Some(o) if o.action == Action::Block)
        })
        .collect()
}

/// Builds an atomic `iptables-restore --noflush` script that (re)creates
/// [`CHAIN`] with the [`expected_rules`] for `targets`.
///
/// Declaring `:DOCKER-FENCE - [0:0]` flushes any previous contents, so the
/// chain is replaced in one transaction. The jump from [`USER_CHAIN`] is only
/// touched when `jump` shows it is not already present exactly once at the
/// top: in that case every existing jump is deleted and a single one is
/// inserted at position 1. This makes the script idempotent.
///
/// Never declares `DOCKER-USER` (declaring an existing chain would flush it).
pub fn render_apply(targets: &[Target], jump: &JumpState) -> String {
    let mut out = format!("*filter\n:{CHAIN} - [0:0]\n");
    for rule in expected_rules(targets) {
        out.push_str(&rule);
        out.push('\n');
    }
    if !(jump.count == 1 && jump.at_top) {
        for _ in 0..jump.count {
            out.push_str(&format!("-D {USER_CHAIN} -j {CHAIN}\n"));
        }
        out.push_str(&format!("-I {USER_CHAIN} 1 -j {CHAIN}\n"));
    }
    out.push_str("COMMIT\n");
    out
}

/// Builds an atomic `iptables-restore --noflush` script that removes
/// docker-fence.
///
/// Deletes `jump_count` jumps from [`USER_CHAIN`] (each `-D` removes one
/// matching rule), then flushes and deletes [`CHAIN`]. The jumps must go
/// first because a chain that is still referenced cannot be deleted.
pub fn render_remove(jump_count: usize) -> String {
    let mut out = String::from("*filter\n");
    for _ in 0..jump_count {
        out.push_str(&format!("-D {USER_CHAIN} -j {CHAIN}\n"));
    }
    out.push_str(&format!("-F {CHAIN}\n-X {CHAIN}\nCOMMIT\n"));
    out
}

/// Whether `line` is exactly `-A DOCKER-USER -j DOCKER-FENCE` (ignoring
/// whitespace differences). Jumps with extra matches do not count.
fn is_jump(line: &str) -> bool {
    line.split_whitespace().collect::<Vec<_>>() == ["-A", USER_CHAIN, "-j", CHAIN]
}

/// Inspects a listing of [`USER_CHAIN`] (`iptables -S DOCKER-USER` output)
/// and reports how many jumps to [`CHAIN`] it holds and whether the first
/// rule is one of them.
///
/// Non-rule lines such as the `-N DOCKER-USER` declaration are ignored when
/// deciding what the "first rule" is.
pub fn parse_jump_state(user_chain_listing: &[String]) -> JumpState {
    let count = user_chain_listing.iter().filter(|l| is_jump(l)).count();
    let at_top = user_chain_listing
        .iter()
        .find(|l| l.trim_start().starts_with("-A "))
        .is_some_and(|l| is_jump(l));
    JumpState { count, at_top }
}

/// Reads the per-network rules back from a listing of [`CHAIN`]
/// (`iptables -S DOCKER-FENCE` output), in the order they appear.
///
/// Only `-A DOCKER-FENCE` lines that carry an input interface (`-i`), a
/// destination (`-d`) and a `RETURN` or `REJECT` target (`-j`) are returned;
/// the position of the flags and trailing options such as
/// `--reject-with icmp-port-unreachable` do not matter. The conntrack rule
/// has no destination and is therefore skipped.
pub fn parse_fence_rules(chain_listing: &[String]) -> Vec<FenceRule> {
    let mut rules = Vec::new();
    for line in chain_listing {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 2 || toks[0] != "-A" || toks[1] != CHAIN {
            continue;
        }
        let value = |flag: &str| toks.windows(2).find(|w| w[0] == flag).map(|w| w[1]);
        let (Some(iface), Some(dst), Some(target)) = (value("-i"), value("-d"), value("-j")) else {
            continue;
        };
        let action = match target {
            "RETURN" => Action::Allow,
            "REJECT" => Action::Block,
            _ => continue,
        };
        rules.push(FenceRule {
            iface: iface.to_string(),
            dst: dst.to_string(),
            action,
        });
    }
    rules
}

/// The distinct [`FenceRule::summary`] strings of `rules`, as a set.
pub fn summaries(rules: &[FenceRule]) -> BTreeSet<String> {
    rules.iter().map(FenceRule::summary).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn t(action: Action, net: &str) -> Target {
        Target {
            action,
            net: net.parse().unwrap(),
        }
    }

    fn block(net: &str) -> Target {
        t(Action::Block, net)
    }

    fn allow(net: &str) -> Target {
        t(Action::Allow, net)
    }

    const R0: &str = "-A DOCKER-FENCE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN";
    const R1: &str = "-A DOCKER-FENCE -i docker0 -d 192.0.2.0/24 -j REJECT";
    const R2: &str = "-A DOCKER-FENCE -i br+ -d 192.0.2.0/24 -j REJECT";

    #[test]
    fn expected_rules_order() {
        assert_eq!(expected_rules(&[block("192.0.2.0/24")]), vec![R0, R1, R2]);
        assert_eq!(expected_rules(&[]), vec![R0]);
    }

    #[test]
    fn most_specific_entry_comes_first() {
        let rules = expected_rules(&[
            block("10.0.0.0/8"),
            allow("10.1.0.0/16"),
            block("10.1.2.0/24"),
            allow("10.1.2.7/32"),
        ]);
        let want = [
            R0,
            "-A DOCKER-FENCE -i docker0 -d 10.1.2.7/32 -j RETURN",
            "-A DOCKER-FENCE -i br+ -d 10.1.2.7/32 -j RETURN",
            "-A DOCKER-FENCE -i docker0 -d 10.1.2.0/24 -j REJECT",
            "-A DOCKER-FENCE -i br+ -d 10.1.2.0/24 -j REJECT",
            "-A DOCKER-FENCE -i docker0 -d 10.1.0.0/16 -j RETURN",
            "-A DOCKER-FENCE -i br+ -d 10.1.0.0/16 -j RETURN",
            "-A DOCKER-FENCE -i docker0 -d 10.0.0.0/8 -j REJECT",
            "-A DOCKER-FENCE -i br+ -d 10.0.0.0/8 -j REJECT",
        ];
        assert_eq!(rules, want);
    }

    #[test]
    fn equal_prefix_lengths_keep_input_order() {
        let rules = fence_rules(&[block("198.51.100.0/24"), allow("192.0.2.0/24")]);
        let dsts: Vec<&str> = rules.iter().map(|r| r.dst.as_str()).collect();
        assert_eq!(
            dsts,
            [
                "198.51.100.0/24",
                "198.51.100.0/24",
                "192.0.2.0/24",
                "192.0.2.0/24"
            ]
        );
    }

    #[test]
    fn ipv6_prefixes_are_ordered_the_same_way() {
        let rules = fence_rules(&[block("2001:db8::/32"), allow("2001:db8::1/128")]);
        assert_eq!(rules[0].dst, "2001:db8::1/128");
        assert_eq!(rules[0].action, Action::Allow);
        assert_eq!(rules[2].dst, "2001:db8::/32");
    }

    #[test]
    fn allow_is_effective_only_as_exception_to_a_block() {
        let targets = [
            block("10.0.0.0/8"),
            allow("10.1.0.0/16"),   // effective: inside the block
            allow("10.1.2.0/24"),   // redundant: closest enclosing entry is an allow
            allow("192.0.2.10/32"), // not inside anything
            block("10.1.2.128/25"), // makes the next allow effective again
            allow("10.1.2.130/32"),
        ];
        let useless: Vec<String> = ineffective_allows(&targets)
            .iter()
            .map(|t| t.net.to_string())
            .collect();
        assert_eq!(useless, ["10.1.2.0/24", "192.0.2.10/32"]);
    }

    #[test]
    fn apply_script_inserts_jump_when_absent() {
        let out = render_apply(
            &[block("192.0.2.0/24")],
            &JumpState {
                count: 0,
                at_top: false,
            },
        );
        assert_eq!(
            out,
            format!(
                "*filter\n:DOCKER-FENCE - [0:0]\n{R0}\n{R1}\n{R2}\n-I DOCKER-USER 1 -j DOCKER-FENCE\nCOMMIT\n"
            )
        );
    }

    #[test]
    fn apply_script_has_no_jump_lines_when_already_on_top() {
        let out = render_apply(
            &[block("192.0.2.0/24")],
            &JumpState {
                count: 1,
                at_top: true,
            },
        );
        assert!(!out.contains("-j DOCKER-FENCE"));
        assert!(out.ends_with("COMMIT\n"));
    }

    #[test]
    fn apply_script_removes_then_reinserts_when_displaced_or_duplicated() {
        let out = render_apply(
            &[],
            &JumpState {
                count: 2,
                at_top: false,
            },
        );
        let d = "-D DOCKER-USER -j DOCKER-FENCE\n";
        assert!(out.contains(&format!("{d}{d}-I DOCKER-USER 1 -j DOCKER-FENCE\nCOMMIT\n")));
        assert_eq!(out.matches("-D DOCKER-USER").count(), 2);
    }

    #[test]
    fn apply_script_never_declares_docker_user() {
        for j in [
            JumpState {
                count: 0,
                at_top: false,
            },
            JumpState {
                count: 1,
                at_top: true,
            },
            JumpState {
                count: 3,
                at_top: false,
            },
        ] {
            let out = render_apply(&[block("192.0.2.0/24")], &j);
            assert!(!out.lines().any(|l| l.starts_with(":DOCKER-USER")));
        }
    }

    #[test]
    fn remove_script() {
        assert_eq!(
            render_remove(1),
            "*filter\n-D DOCKER-USER -j DOCKER-FENCE\n-F DOCKER-FENCE\n-X DOCKER-FENCE\nCOMMIT\n"
        );
        assert_eq!(
            render_remove(0),
            "*filter\n-F DOCKER-FENCE\n-X DOCKER-FENCE\nCOMMIT\n"
        );
    }

    #[test]
    fn jump_state_parsing() {
        let top = s(&[
            "-N DOCKER-USER",
            "-A DOCKER-USER -j DOCKER-FENCE",
            "-A DOCKER-USER -j RETURN",
        ]);
        assert_eq!(
            parse_jump_state(&top),
            JumpState {
                count: 1,
                at_top: true
            }
        );
        let low = s(&[
            "-N DOCKER-USER",
            "-A DOCKER-USER -j RETURN",
            "-A DOCKER-USER -j DOCKER-FENCE",
        ]);
        assert_eq!(
            parse_jump_state(&low),
            JumpState {
                count: 1,
                at_top: false
            }
        );
        let none = s(&["-N DOCKER-USER", "-A DOCKER-USER -j RETURN"]);
        assert_eq!(
            parse_jump_state(&none),
            JumpState {
                count: 0,
                at_top: false
            }
        );
    }

    #[test]
    fn fence_rules_parse_real_iptables_output() {
        let l = s(&[
            "-N DOCKER-FENCE",
            "-A DOCKER-FENCE -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
            "-A DOCKER-FENCE -d 192.0.2.10/32 -i docker0 -j RETURN",
            "-A DOCKER-FENCE -d 192.0.2.0/24 -i br+ -j REJECT --reject-with icmp-port-unreachable",
            "-A DOCKER-FENCE -i br+ -d 10.0.0.0/8 -j LOG",
        ]);
        let got = parse_fence_rules(&l);
        assert_eq!(
            got,
            vec![
                FenceRule {
                    iface: "docker0".into(),
                    dst: "192.0.2.10/32".into(),
                    action: Action::Allow
                },
                FenceRule {
                    iface: "br+".into(),
                    dst: "192.0.2.0/24".into(),
                    action: Action::Block
                },
            ]
        );
    }

    #[test]
    fn rendered_rules_round_trip_through_the_parser() {
        let targets = [block("10.0.0.0/8"), allow("10.1.0.0/16")];
        let rendered = expected_rules(&targets);
        assert_eq!(parse_fence_rules(&rendered), fence_rules(&targets));
    }
}
