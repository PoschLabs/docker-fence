//! The user-facing operations: [`apply`], [`remove`] and [`status`].
//!
//! All of them take a `&dyn` [`Firewall`], so they contain the policy
//! (ordering, IPv6 tolerance, error reporting) while the actual system calls
//! live behind the trait.
//!
//! # IPv6 handling
//!
//! IPv4 is mandatory: any IPv4 listing failure aborts the operation. IPv6 is
//! best-effort when it makes sense. A failure to list the IPv6 `DOCKER-USER`
//! chain is tolerated, with a notice, if the kernel has no IPv6
//! ([`Firewall::ipv6_available`]) or, for `apply`/`status`, if the
//! configuration contains no IPv6 networks. Otherwise it is an error, so
//! IPv6 protection is never silently skipped.

use std::fmt;

use ipnet::IpNet;

use crate::config::{Action, ConfigError, FenceConfig};
use crate::firewall::{Firewall, FirewallError};
use crate::rules::{
    CHAIN, Family, Target, USER_CHAIN, fence_rules, ineffective_allows, parse_fence_rules,
    parse_jump_state, render_apply, render_remove, summaries,
};

/// Everything that can make an operation fail.
#[derive(Debug)]
pub enum FenceError {
    /// The configuration file could not be loaded.
    Config(ConfigError),
    /// The `DOCKER-USER` chain does not exist for this family, which usually
    /// means Docker is not running. Nothing was changed.
    DockerUserMissing(Family),
    /// A firewall command failed before anything was changed, or no earlier
    /// step had already succeeded.
    Firewall(FirewallError),
    /// One family was fully applied but the other failed, leaving the system
    /// in a mixed state that the operator should know about.
    PartiallyApplied {
        /// The family whose rules were installed.
        applied: Family,
        /// The family that could not be installed.
        failed: Family,
        /// Why `failed` could not be installed.
        cause: FirewallError,
    },
}

impl fmt::Display for FenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FenceError::Config(e) => write!(f, "{e}"),
            FenceError::DockerUserMissing(fam) => write!(
                f,
                "{} chain {USER_CHAIN} not found; is Docker running? (nothing was changed)",
                fam.tool()
            ),
            FenceError::Firewall(e) => write!(f, "{e}"),
            FenceError::PartiallyApplied {
                applied,
                failed,
                cause,
            } => write!(
                f,
                "partially applied: {} rules were installed but {} failed: {cause}",
                applied.tool(),
                failed.tool()
            ),
        }
    }
}

impl std::error::Error for FenceError {}

impl From<ConfigError> for FenceError {
    fn from(e: ConfigError) -> Self {
        FenceError::Config(e)
    }
}

impl From<FirewallError> for FenceError {
    fn from(e: FirewallError) -> Self {
        FenceError::Firewall(e)
    }
}

/// Outcome of a successful [`apply`] or [`remove`].
#[derive(Debug, Default)]
pub struct Report {
    /// Non-fatal conditions the operator should be told about (skipped IPv6,
    /// an empty configuration, ...). The caller decides how to display them.
    pub notices: Vec<String>,
}

/// The configured entries for `family`, in file order.
fn targets(cfg: &FenceConfig, family: Family) -> Vec<Target> {
    match family {
        Family::V4 => cfg
            .v4
            .iter()
            .map(|e| Target {
                action: e.action,
                net: IpNet::V4(e.net),
            })
            .collect(),
        Family::V6 => cfg
            .v6
            .iter()
            .map(|e| Target {
                action: e.action,
                net: IpNet::V6(e.net),
            })
            .collect(),
    }
}

/// Notices for `allow` entries in `targets` that can never take effect.
fn ineffective_allow_notices(targets: &[Target]) -> impl Iterator<Item = String> + '_ {
    ineffective_allows(targets).into_iter().map(|t| {
        format!(
            "allow {} has no effect: it is not an exception to a block",
            t.net
        )
    })
}

/// How a failed IPv6 `DOCKER-USER` listing is handled.
enum V6Listing {
    /// The listing succeeded; `None` means the chain does not exist.
    Listed(Option<Vec<String>>),
    /// Tolerated: no IPv6 subnets are configured or the kernel has no IPv6.
    /// Holds the underlying error message.
    Unavailable(String),
    /// IPv6 is present and the listing failed: must not be skipped silently.
    Failed(FirewallError),
}

/// Lists the IPv6 `DOCKER-USER` chain and classifies the result.
///
/// `needs_v6` is true when the configuration contains IPv6 networks. A
/// failure is only [`V6Listing::Failed`] if IPv6 is needed *and* available.
fn list_v6_user(fw: &dyn Firewall, needs_v6: bool) -> V6Listing {
    match fw.list_chain(Family::V6, USER_CHAIN) {
        Ok(l) => V6Listing::Listed(l),
        Err(e) if needs_v6 && fw.ipv6_available() => V6Listing::Failed(e),
        Err(e) => V6Listing::Unavailable(e.0),
    }
}

/// Installs the firewall rules described by `cfg`.
///
/// Per family, one `iptables-restore` transaction replaces the `DOCKER-FENCE`
/// chain and makes sure `DOCKER-USER` has exactly one jump to it, as its
/// first rule. Running it again with the same input changes nothing, and it
/// also repairs a displaced or duplicated jump. IPv4 is applied before IPv6.
///
/// # Notices
///
/// The returned [`Report`] contains a notice when IPv6 is skipped (a stronger
/// `WARNING` if the configuration has IPv6 entries that therefore are *not*
/// enforced), when there is no `block` entry at all, and for each `allow`
/// entry that cannot take effect because it is not an exception to a block.
///
/// Entries are installed most-specific first, see [`crate::rules`].
///
/// # Errors
///
/// * [`FenceError::DockerUserMissing`] if the IPv4 `DOCKER-USER` chain does
///   not exist; nothing is changed.
/// * [`FenceError::Firewall`] if listing IPv4 fails or the first restore fails.
/// * [`FenceError::PartiallyApplied`] if IPv4 was applied but IPv6 could not
///   be listed or restored.
pub fn apply(fw: &dyn Firewall, cfg: &FenceConfig) -> Result<Report, FenceError> {
    let mut report = Report::default();
    let v4_user = fw
        .list_chain(Family::V4, USER_CHAIN)?
        .ok_or(FenceError::DockerUserMissing(Family::V4))?;
    let mut v6_failure = None;
    let (v6_user, v6_err) = match list_v6_user(fw, !cfg.v6.is_empty()) {
        V6Listing::Listed(l) => (l, None),
        V6Listing::Unavailable(e) => (None, Some(e)),
        V6Listing::Failed(e) => {
            v6_failure = Some(e);
            (None, None)
        }
    };
    let why = v6_err.map_or_else(
        || format!("chain {USER_CHAIN} not found"),
        |e| format!("unavailable ({e})"),
    );

    let v4_targets = targets(cfg, Family::V4);
    let v6_targets = targets(cfg, Family::V6);
    report
        .notices
        .extend(ineffective_allow_notices(&v4_targets));
    let mut scripts = vec![(
        Family::V4,
        render_apply(&v4_targets, &parse_jump_state(&v4_user)),
    )];
    match v6_user {
        Some(listing) => {
            report
                .notices
                .extend(ineffective_allow_notices(&v6_targets));
            scripts.push((
                Family::V6,
                render_apply(&v6_targets, &parse_jump_state(&listing)),
            ));
        }
        None if v6_failure.is_some() => {}
        None if cfg.v6.is_empty() => report
            .notices
            .push(format!("ip6tables {why}; skipping IPv6")),
        None => report.notices.push(format!(
            "WARNING: ip6tables {why}; IPv6 subnets in the config are NOT blocked"
        )),
    }
    let blocks = |t: &[Target]| t.iter().any(|t| t.action == Action::Block);
    if !blocks(&v4_targets) && !blocks(&v6_targets) {
        report
            .notices
            .push("no block entries configured; nothing is blocked".to_string());
    }

    let mut applied: Option<Family> = None;
    for (family, script) in &scripts {
        match fw.restore(*family, script) {
            Ok(()) => applied = Some(*family),
            Err(cause) => {
                return Err(match applied {
                    Some(applied) => FenceError::PartiallyApplied {
                        applied,
                        failed: *family,
                        cause,
                    },
                    None => FenceError::Firewall(cause),
                });
            }
        }
    }
    if let Some(cause) = v6_failure {
        return Err(FenceError::PartiallyApplied {
            applied: Family::V4,
            failed: Family::V6,
            cause,
        });
    }
    Ok(report)
}

/// Removes docker-fence from the firewall for both families.
///
/// Deletes every jump to `DOCKER-FENCE` from `DOCKER-USER` and then deletes
/// the chain itself, in one transaction per family. Other rules in
/// `DOCKER-USER` are left untouched. The configuration is not consulted, and
/// the operation is a no-op for a family where nothing is installed.
///
/// `remove` still works if `DOCKER-USER` is gone (for instance Docker was
/// stopped) as long as the `DOCKER-FENCE` chain exists. If a jump exists
/// without the chain, a notice asks for manual cleanup.
///
/// # Errors
///
/// Any IPv4 failure, and any failure to list the `DOCKER-FENCE` chain, is
/// returned as [`FenceError::Firewall`]. An IPv6 `DOCKER-USER` listing
/// failure is an error when IPv6 is available (IPv4 has already been
/// removed by then) and a notice otherwise.
pub fn remove(fw: &dyn Firewall) -> Result<Report, FenceError> {
    let mut report = Report::default();
    for family in [Family::V4, Family::V6] {
        let user = match fw.list_chain(family, USER_CHAIN) {
            Ok(l) => l,
            Err(e) if family == Family::V6 && fw.ipv6_available() => {
                return Err(FenceError::Firewall(FirewallError(format!(
                    "ip6tables: failed to list {USER_CHAIN}: {e}; IPv6 rules were not removed"
                ))));
            }
            Err(e) if family == Family::V6 => {
                report.notices.push(format!(
                    "{}: unavailable ({e}); skipping IPv6",
                    family.tool()
                ));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let chain = fw.list_chain(family, CHAIN)?;
        let jumps = user.as_deref().map_or(0, |l| parse_jump_state(l).count);
        if chain.is_none() {
            if jumps > 0 {
                report.notices.push(format!(
                    "{}: {USER_CHAIN} has a jump to {CHAIN} but the chain does not exist; \
                     remove it manually",
                    family.tool()
                ));
            }
            continue;
        }
        fw.restore(family, &render_remove(jumps))?;
    }
    Ok(report)
}

/// Result of checking one address family in [`status`].
#[derive(Debug, PartialEq, Eq)]
pub enum FamilyStatus {
    /// IPv6 only: `DOCKER-USER` is unavailable and the configuration has no
    /// IPv6 networks, so there is nothing to check. Counts as healthy.
    Skipped,
    /// The expected chain (`DOCKER-USER` or `DOCKER-FENCE`) does not exist.
    Missing,
    /// The rules exist but do not match the configuration. Holds a
    /// description of the difference.
    Mismatch(String),
    /// The installed rules match the configuration.
    Ok,
}

/// Per-family result of [`status`].
#[derive(Debug)]
pub struct StatusReport {
    /// One entry per family, always IPv4 first, then IPv6.
    pub families: Vec<(Family, FamilyStatus)>,
}

impl StatusReport {
    /// True if every family is [`FamilyStatus::Ok`] or [`FamilyStatus::Skipped`].
    pub fn is_ok(&self) -> bool {
        self.families
            .iter()
            .all(|(_, s)| matches!(s, FamilyStatus::Ok | FamilyStatus::Skipped))
    }
}

/// Compares the installed rules with `cfg` without changing anything.
///
/// For each family a [`FamilyStatus::Ok`] requires that `DOCKER-USER` has
/// exactly one jump to `DOCKER-FENCE`, that it is the first rule, and that
/// the installed per-network rules equal the expected ones *in the expected
/// order* (order is the meaning, since the first match wins). A
/// [`FamilyStatus::Mismatch`] message names the first violated condition; for
/// a rule difference it lists the `extra` and `missing` entries (such as
/// `block 192.0.2.0/24`), or says the order or interfaces differ.
///
/// Unlike [`apply`], an IPv6 listing failure never aborts the check: the
/// family is reported as `Skipped` (no IPv6 networks configured) or
/// `Missing`.
///
/// # Errors
///
/// A [`FenceError::Firewall`] if listing IPv4 `DOCKER-USER` fails, or if
/// listing a `DOCKER-FENCE` chain fails for either family.
pub fn status(fw: &dyn Firewall, cfg: &FenceConfig) -> Result<StatusReport, FenceError> {
    let mut families = Vec::new();
    for family in [Family::V4, Family::V6] {
        let want = fence_rules(&targets(cfg, family));
        let user = match fw.list_chain(family, USER_CHAIN) {
            Ok(l) => l,
            Err(_) if family == Family::V6 => None,
            Err(e) => return Err(e.into()),
        };
        let st = match user {
            None if family == Family::V6 && want.is_empty() => FamilyStatus::Skipped,
            None => FamilyStatus::Missing,
            Some(user) => {
                let jump = parse_jump_state(&user);
                match fw.list_chain(family, CHAIN)? {
                    None => FamilyStatus::Missing,
                    Some(chain) => {
                        let have = parse_fence_rules(&chain);
                        if jump.count != 1 {
                            FamilyStatus::Mismatch(format!(
                                "expected exactly one jump to {CHAIN} in {USER_CHAIN}, found {}",
                                jump.count
                            ))
                        } else if !jump.at_top {
                            FamilyStatus::Mismatch(format!(
                                "jump to {CHAIN} is not the first rule in {USER_CHAIN}"
                            ))
                        } else if have != want {
                            let (have, want) = (summaries(&have), summaries(&want));
                            let extra: Vec<_> = have.difference(&want).cloned().collect();
                            let missing: Vec<_> = want.difference(&have).cloned().collect();
                            if extra.is_empty() && missing.is_empty() {
                                FamilyStatus::Mismatch(
                                    "installed rules differ from config (same entries, but \
                                     in a different order or on different interfaces)"
                                        .to_string(),
                                )
                            } else {
                                FamilyStatus::Mismatch(format!(
                                    "installed rules differ from config (extra: [{}], missing: [{}])",
                                    extra.join(", "),
                                    missing.join(", ")
                                ))
                            }
                        } else {
                            FamilyStatus::Ok
                        }
                    }
                }
            }
        };
        families.push((family, st));
    }
    Ok(StatusReport { families })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::rules::expected_rules;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::Path;

    const JUMP: &str = "-A DOCKER-USER -j DOCKER-FENCE";

    #[derive(Default)]
    struct FakeFirewall {
        lists: HashMap<(Family, String), Vec<String>>,
        restores: RefCell<Vec<(Family, String)>>,
        fail_v6_restore: bool,
        fail_v6_list: bool,
        fail_fence_list: bool,
        fail_v6_fence_list: bool,
        ipv6_absent: bool,
    }

    impl FakeFirewall {
        fn with(mut self, f: Family, chain: &str, lines: &[&str]) -> Self {
            self.lists.insert(
                (f, chain.to_string()),
                lines.iter().map(|s| s.to_string()).collect(),
            );
            self
        }
        fn docker() -> Self {
            Self::default()
                .with(
                    Family::V4,
                    "DOCKER-USER",
                    &["-N DOCKER-USER", "-A DOCKER-USER -j RETURN"],
                )
                .with(
                    Family::V6,
                    "DOCKER-USER",
                    &["-N DOCKER-USER", "-A DOCKER-USER -j RETURN"],
                )
        }
        fn calls(&self) -> Vec<(Family, String)> {
            self.restores.borrow().clone()
        }
    }

    impl Firewall for FakeFirewall {
        fn list_chain(&self, f: Family, chain: &str) -> Result<Option<Vec<String>>, FirewallError> {
            if f == Family::V6 && self.fail_v6_list {
                return Err(FirewallError("Address family not supported".into()));
            }
            if (self.fail_fence_list || (self.fail_v6_fence_list && f == Family::V6))
                && chain == "DOCKER-FENCE"
            {
                return Err(FirewallError("lock timeout".into()));
            }
            Ok(self.lists.get(&(f, chain.to_string())).cloned())
        }
        fn ipv6_available(&self) -> bool {
            !self.ipv6_absent
        }
        fn restore(&self, f: Family, script: &str) -> Result<(), FirewallError> {
            if f == Family::V6 && self.fail_v6_restore {
                return Err(FirewallError("boom".into()));
            }
            self.restores.borrow_mut().push((f, script.to_string()));
            Ok(())
        }
    }

    fn cfg(text: &str) -> FenceConfig {
        config::parse(text, Path::new("t.conf")).unwrap()
    }

    fn both() -> FenceConfig {
        cfg("block 192.0.2.0/24\nblock 2001:db8:10::/64\n")
    }

    fn chain_lines(cidrs: &[&str]) -> Vec<String> {
        let t: Vec<Target> = cidrs
            .iter()
            .map(|s| Target {
                action: Action::Block,
                net: s.parse().unwrap(),
            })
            .collect();
        expected_rules(&t)
    }

    #[test]
    fn apply_sends_v4_and_v6_scripts_in_one_transaction_each() {
        let fw = FakeFirewall::docker();
        apply(&fw, &both()).unwrap();
        let calls = fw.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, Family::V4);
        assert_eq!(calls[1].0, Family::V6);
        assert!(calls[0].1.contains("-d 192.0.2.0/24") && !calls[0].1.contains("2001:db8"));
        assert!(calls[1].1.contains("-d 2001:db8:10::/64") && !calls[1].1.contains("192.0.2"));
        for (_, s) in &calls {
            assert_eq!(s.matches("COMMIT").count(), 1);
            assert!(s.contains("-I DOCKER-USER 1 -j DOCKER-FENCE"));
        }
    }

    #[test]
    fn apply_is_idempotent_when_jump_on_top() {
        let fw = FakeFirewall::docker()
            .with(
                Family::V4,
                "DOCKER-USER",
                &[JUMP, "-A DOCKER-USER -j RETURN"],
            )
            .with(
                Family::V6,
                "DOCKER-USER",
                &[JUMP, "-A DOCKER-USER -j RETURN"],
            );
        apply(&fw, &both()).unwrap();
        for (_, s) in fw.calls() {
            assert!(!s.contains("-I ") && !s.contains("-D "), "{s}");
        }
    }

    #[test]
    fn apply_missing_v4_docker_user_errors_and_restores_nothing() {
        let fw = FakeFirewall::default().with(Family::V6, "DOCKER-USER", &["-N DOCKER-USER"]);
        let err = apply(&fw, &both()).unwrap_err();
        assert!(matches!(err, FenceError::DockerUserMissing(Family::V4)));
        assert!(fw.calls().is_empty());
    }

    #[test]
    fn apply_skips_v6_with_notice_when_chain_missing() {
        let fw = FakeFirewall::default().with(Family::V4, "DOCKER-USER", &["-N DOCKER-USER"]);
        let r = apply(&fw, &cfg("block 192.0.2.0/24\n")).unwrap();
        assert_eq!(fw.calls().len(), 1);
        assert_eq!(r.notices.len(), 1);
        assert!(!r.notices[0].contains("WARNING"));
    }

    #[test]
    fn apply_skips_v6_with_stronger_notice_when_config_has_v6() {
        let fw = FakeFirewall::default().with(Family::V4, "DOCKER-USER", &["-N DOCKER-USER"]);
        let r = apply(&fw, &both()).unwrap();
        assert_eq!(fw.calls().len(), 1);
        assert!(
            r.notices
                .iter()
                .any(|n| n.contains("WARNING") && n.contains("NOT blocked"))
        );
    }

    #[test]
    fn apply_v6_failure_after_v4_reports_partially_applied() {
        let mut fw = FakeFirewall::docker();
        fw.fail_v6_restore = true;
        let err = apply(&fw, &both()).unwrap_err();
        match err {
            FenceError::PartiallyApplied {
                applied,
                failed,
                cause,
            } => {
                assert_eq!(applied, Family::V4);
                assert_eq!(failed, Family::V6);
                assert_eq!(cause.0, "boom");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(fw.calls().len(), 1);
    }

    #[test]
    fn apply_empty_config_warns_and_installs_only_established_rule() {
        let fw = FakeFirewall::docker();
        let r = apply(&fw, &FenceConfig::default()).unwrap();
        assert!(
            r.notices
                .iter()
                .any(|n| n == "no block entries configured; nothing is blocked")
        );
        for (_, s) in fw.calls() {
            assert!(s.contains("ESTABLISHED,RELATED"));
            assert!(!s.contains("REJECT"));
        }
    }

    #[test]
    fn remove_deletes_jump_and_chain_only() {
        let fw = FakeFirewall::default()
            .with(
                Family::V4,
                "DOCKER-USER",
                &[JUMP, "-A DOCKER-USER -j RETURN"],
            )
            .with(Family::V4, "DOCKER-FENCE", &["-N DOCKER-FENCE"]);
        remove(&fw).unwrap();
        let calls = fw.calls();
        assert_eq!(calls, vec![(Family::V4, render_remove(1))]);
    }

    #[test]
    fn remove_with_nothing_installed_makes_no_calls() {
        let fw = FakeFirewall::docker();
        remove(&fw).unwrap();
        assert!(fw.calls().is_empty());
    }

    #[test]
    fn remove_still_deletes_chain_when_docker_user_missing() {
        let fw = FakeFirewall::default().with(Family::V4, "DOCKER-FENCE", &["-N DOCKER-FENCE"]);
        remove(&fw).unwrap();
        assert_eq!(fw.calls(), vec![(Family::V4, render_remove(0))]);
    }

    fn installed(jump_first: bool, v4: &[&str]) -> FakeFirewall {
        let user: Vec<&str> = if jump_first {
            vec![JUMP, "-A DOCKER-USER -j RETURN"]
        } else {
            vec!["-A DOCKER-USER -j RETURN", JUMP]
        };
        let mut fw = FakeFirewall::default()
            .with(Family::V4, "DOCKER-USER", &user)
            .with(Family::V6, "DOCKER-USER", &user);
        fw.lists
            .insert((Family::V4, "DOCKER-FENCE".into()), chain_lines(v4));
        fw.lists.insert(
            (Family::V6, "DOCKER-FENCE".into()),
            chain_lines(&["2001:db8:10::/64"]),
        );
        fw
    }

    fn v4_status(r: &StatusReport) -> &FamilyStatus {
        &r.families[0].1
    }

    #[test]
    fn status_ok_and_mismatch() {
        let c = both();
        let r = status(&installed(true, &["192.0.2.0/24"]), &c).unwrap();
        assert!(r.is_ok(), "{r:?}");

        let r = status(&installed(true, &["192.0.2.0/24", "198.51.100.0/24"]), &c).unwrap();
        assert!(matches!(v4_status(&r), FamilyStatus::Mismatch(_)));
        assert!(!r.is_ok());

        let r = status(&installed(true, &[]), &c).unwrap();
        assert!(matches!(v4_status(&r), FamilyStatus::Mismatch(_)));

        let r = status(&installed(false, &["192.0.2.0/24"]), &c).unwrap();
        assert!(matches!(v4_status(&r), FamilyStatus::Mismatch(m) if m.contains("first")));

        let r = status(&FakeFirewall::docker(), &c).unwrap();
        assert_eq!(*v4_status(&r), FamilyStatus::Missing);

        let fw = FakeFirewall::default().with(Family::V4, "DOCKER-USER", &["-N DOCKER-USER"]);
        let r = status(&fw, &cfg("block 192.0.2.0/24\n")).unwrap();
        assert_eq!(r.families[1].1, FamilyStatus::Skipped);
        let r = status(&fw, &c).unwrap();
        assert_eq!(r.families[1].1, FamilyStatus::Missing);
    }

    fn v6_broken() -> FakeFirewall {
        let mut fw = FakeFirewall::docker();
        fw.fail_v6_list = true;
        fw
    }

    #[test]
    fn apply_v6_error_with_v6_config_and_ipv6_present_is_partially_applied() {
        let fw = v6_broken();
        let err = apply(&fw, &both()).unwrap_err();
        match err {
            FenceError::PartiallyApplied {
                applied,
                failed,
                cause,
            } => {
                assert_eq!(applied, Family::V4);
                assert_eq!(failed, Family::V6);
                assert!(cause.0.contains("Address family not supported"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let calls = fw.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, Family::V4);
    }

    #[test]
    fn apply_v6_error_with_v6_config_and_ipv6_absent_warns_and_succeeds() {
        let mut fw = v6_broken();
        fw.ipv6_absent = true;
        let r = apply(&fw, &both()).unwrap();
        assert_eq!(fw.calls().len(), 1);
        assert!(r.notices.iter().any(|n| n.contains("WARNING")
            && n.contains("NOT blocked")
            && n.contains("Address family not supported")));
    }

    #[test]
    fn apply_v6_error_without_v6_config_skips_with_notice() {
        let fw = v6_broken();
        let r = apply(&fw, &cfg("block 192.0.2.0/24\n")).unwrap();
        assert_eq!(fw.calls().len(), 1);
        assert!(
            r.notices
                .iter()
                .any(|n| n.contains("Address family not supported") && !n.contains("WARNING"))
        );
    }

    #[test]
    fn apply_v4_listing_error_stays_hard() {
        struct V4Broken;
        impl Firewall for V4Broken {
            fn list_chain(&self, _: Family, _: &str) -> Result<Option<Vec<String>>, FirewallError> {
                Err(FirewallError("nope".into()))
            }
            fn restore(&self, _: Family, _: &str) -> Result<(), FirewallError> {
                Ok(())
            }
            fn ipv6_available(&self) -> bool {
                true
            }
        }
        assert!(matches!(
            apply(&V4Broken, &both()),
            Err(FenceError::Firewall(_))
        ));
    }

    fn v6_broken_with_v4_installed() -> FakeFirewall {
        let mut fw = FakeFirewall::default()
            .with(Family::V4, "DOCKER-USER", &[JUMP])
            .with(Family::V4, "DOCKER-FENCE", &["-N DOCKER-FENCE"]);
        fw.fail_v6_list = true;
        fw
    }

    #[test]
    fn remove_v6_error_with_ipv6_present_removes_v4_then_errors() {
        let fw = v6_broken_with_v4_installed();
        let err = remove(&fw).unwrap_err();
        assert!(matches!(&err, FenceError::Firewall(_)));
        assert!(err.to_string().contains("ip6tables"), "{err}");
        assert_eq!(fw.calls(), vec![(Family::V4, render_remove(1))]);
    }

    #[test]
    fn remove_v6_error_with_ipv6_absent_skips_with_notice() {
        let mut fw = v6_broken_with_v4_installed();
        fw.ipv6_absent = true;
        let r = remove(&fw).unwrap();
        assert_eq!(fw.calls(), vec![(Family::V4, render_remove(1))]);
        assert!(
            r.notices
                .iter()
                .any(|n| n.contains("Address family not supported"))
        );
    }

    #[test]
    fn remove_and_status_propagate_fence_chain_listing_error() {
        let mut fw = installed(true, &["192.0.2.0/24"]);
        fw.fail_fence_list = true;
        assert!(matches!(remove(&fw), Err(FenceError::Firewall(_))));
        assert!(matches!(status(&fw, &both()), Err(FenceError::Firewall(_))));
    }

    #[test]
    fn remove_propagates_v6_only_fence_chain_listing_error() {
        let mut fw = installed(true, &["192.0.2.0/24"]);
        fw.fail_v6_fence_list = true;
        assert!(matches!(remove(&fw), Err(FenceError::Firewall(_))));
        assert_eq!(fw.calls(), vec![(Family::V4, render_remove(1))]);
    }

    #[test]
    fn status_propagates_v6_only_fence_chain_listing_error() {
        let mut fw = installed(true, &["192.0.2.0/24"]);
        fw.fail_v6_fence_list = true;
        assert!(matches!(status(&fw, &both()), Err(FenceError::Firewall(_))));
    }

    #[test]
    fn status_treats_v6_listing_error_as_unavailable() {
        let mut fw = installed(true, &["192.0.2.0/24"]);
        fw.fail_v6_list = true;
        let r = status(&fw, &cfg("block 192.0.2.0/24\n")).unwrap();
        assert_eq!(r.families[1].1, FamilyStatus::Skipped);
        assert!(r.is_ok());
        let r = status(&fw, &both()).unwrap();
        assert_eq!(r.families[1].1, FamilyStatus::Missing);
    }

    const NESTED: &str =
        "block 10.0.0.0/8\nallow 10.1.0.0/16\nblock 10.1.2.0/24\nallow 10.1.2.7/32\n";

    #[test]
    fn apply_installs_nested_entries_most_specific_first() {
        let fw = FakeFirewall::docker();
        apply(&fw, &cfg(NESTED)).unwrap();
        let script = &fw.calls()[0].1;
        let pos = |needle: &str| {
            script
                .find(needle)
                .unwrap_or_else(|| panic!("{needle}\n{script}"))
        };
        let (a, b, c, d) = (
            pos("-i docker0 -d 10.1.2.7/32 -j RETURN"),
            pos("-i docker0 -d 10.1.2.0/24 -j REJECT"),
            pos("-i docker0 -d 10.1.0.0/16 -j RETURN"),
            pos("-i docker0 -d 10.0.0.0/8 -j REJECT"),
        );
        assert!(a < b && b < c && c < d, "{script}");
    }

    #[test]
    fn apply_warns_about_allow_that_is_not_an_exception() {
        let fw = FakeFirewall::docker();
        let r = apply(&fw, &cfg("block 10.0.0.0/8\nallow 192.0.2.10/32\n")).unwrap();
        assert!(
            r.notices
                .iter()
                .any(|n| n.contains("allow 192.0.2.10/32 has no effect")),
            "{:?}",
            r.notices
        );
        assert_eq!(r.notices.len(), 1, "{:?}", r.notices);
        // The effective allow gets no notice.
        let r = apply(&fw, &cfg("block 10.0.0.0/8\nallow 10.1.0.0/16\n")).unwrap();
        assert!(r.notices.is_empty(), "{:?}", r.notices);
    }

    #[test]
    fn apply_allow_only_config_says_nothing_is_blocked() {
        let fw = FakeFirewall::docker();
        let r = apply(&fw, &cfg("allow 192.0.2.10/32\n")).unwrap();
        assert!(
            r.notices
                .iter()
                .any(|n| n == "no block entries configured; nothing is blocked")
        );
    }

    fn installed_from(c: &FenceConfig) -> FakeFirewall {
        let mut fw = installed(true, &[]);
        for (family, t) in [
            (Family::V4, targets(c, Family::V4)),
            (Family::V6, targets(c, Family::V6)),
        ] {
            fw.lists
                .insert((family, "DOCKER-FENCE".into()), expected_rules(&t));
        }
        fw
    }

    #[test]
    fn status_ok_with_nested_allow_and_block() {
        let c = cfg(&format!(
            "{NESTED}block 2001:db8:10::/64\nallow 2001:db8:10::5/128\n"
        ));
        let r = status(&installed_from(&c), &c).unwrap();
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn status_reports_missing_allow_and_flipped_action() {
        let want = cfg("block 192.0.2.0/24\nallow 192.0.2.10/32\n");
        // Installed: only the block.
        let have = cfg("block 192.0.2.0/24\n");
        let r = status(&installed_from(&have), &want).unwrap();
        assert!(
            matches!(v4_status(&r), FamilyStatus::Mismatch(m) if m.contains("missing: [allow 192.0.2.10/32]")),
            "{r:?}"
        );
        // Installed: the same network blocked instead of allowed.
        let flipped = cfg("block 192.0.2.0/24\nblock 192.0.2.10/32\n");
        let r = status(&installed_from(&flipped), &want).unwrap();
        assert!(
            matches!(v4_status(&r), FamilyStatus::Mismatch(m)
                if m.contains("extra: [block 192.0.2.10/32]") && m.contains("missing: [allow 192.0.2.10/32]")),
            "{r:?}"
        );
    }

    #[test]
    fn status_reports_wrong_order_even_with_same_entries() {
        let c = cfg("block 192.0.2.0/24\nallow 192.0.2.10/32\n");
        let mut fw = installed_from(&c);
        // Put the broad block before the specific allow.
        let mut chain = fw.lists[&(Family::V4, "DOCKER-FENCE".to_string())].clone();
        let tail = chain.split_off(1);
        let (allow_rules, block_rules) = tail.split_at(2);
        chain.extend(block_rules.iter().cloned());
        chain.extend(allow_rules.iter().cloned());
        fw.lists.insert((Family::V4, "DOCKER-FENCE".into()), chain);
        let r = status(&fw, &c).unwrap();
        assert!(
            matches!(v4_status(&r), FamilyStatus::Mismatch(m) if m.contains("different order")),
            "{r:?}"
        );
    }
}
