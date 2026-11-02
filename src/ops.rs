use std::collections::BTreeSet;
use std::fmt;

use crate::config::{ConfigError, FenceConfig};
use crate::firewall::{Firewall, FirewallError};
use crate::rules::{
    CHAIN, Family, USER_CHAIN, parse_fenced_destinations, parse_jump_state, render_apply,
    render_remove,
};

#[derive(Debug)]
pub enum FenceError {
    Config(ConfigError),
    DockerUserMissing(Family),
    Firewall(FirewallError),
    PartiallyApplied {
        applied: Family,
        failed: Family,
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

#[derive(Debug, Default)]
pub struct Report {
    pub notices: Vec<String>,
}

fn cidrs(cfg: &FenceConfig, family: Family) -> Vec<String> {
    match family {
        Family::V4 => cfg.v4.iter().map(|c| c.to_string()).collect(),
        Family::V6 => cfg.v6.iter().map(|c| c.to_string()).collect(),
    }
}

/// How a failed IPv6 `DOCKER-USER` listing is handled.
enum V6Listing {
    Listed(Option<Vec<String>>),
    /// Tolerated: no IPv6 subnets are configured or the kernel has no IPv6.
    Unavailable(String),
    /// IPv6 is present and the listing failed: must not be skipped silently.
    Failed(FirewallError),
}

fn list_v6_user(fw: &dyn Firewall, needs_v6: bool) -> V6Listing {
    match fw.list_chain(Family::V6, USER_CHAIN) {
        Ok(l) => V6Listing::Listed(l),
        Err(e) if needs_v6 && fw.ipv6_available() => V6Listing::Failed(e),
        Err(e) => V6Listing::Unavailable(e.0),
    }
}

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

    let mut scripts = vec![(
        Family::V4,
        render_apply(&cidrs(cfg, Family::V4), &parse_jump_state(&v4_user)),
    )];
    match v6_user {
        Some(listing) => scripts.push((
            Family::V6,
            render_apply(&cidrs(cfg, Family::V6), &parse_jump_state(&listing)),
        )),
        None if v6_failure.is_some() => {}
        None if cfg.v6.is_empty() => report
            .notices
            .push(format!("ip6tables {why}; skipping IPv6")),
        None => report.notices.push(format!(
            "WARNING: ip6tables {why}; IPv6 subnets in the config are NOT blocked"
        )),
    }
    if cfg.v4.is_empty() && cfg.v6.is_empty() {
        report
            .notices
            .push("no subnets configured; nothing is blocked".to_string());
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

#[derive(Debug, PartialEq, Eq)]
pub enum FamilyStatus {
    Skipped,
    Missing,
    Mismatch(String),
    Ok,
}

#[derive(Debug)]
pub struct StatusReport {
    pub families: Vec<(Family, FamilyStatus)>,
}

impl StatusReport {
    pub fn is_ok(&self) -> bool {
        self.families
            .iter()
            .all(|(_, s)| matches!(s, FamilyStatus::Ok | FamilyStatus::Skipped))
    }
}

pub fn status(fw: &dyn Firewall, cfg: &FenceConfig) -> Result<StatusReport, FenceError> {
    let mut families = Vec::new();
    for family in [Family::V4, Family::V6] {
        let want: BTreeSet<String> = cidrs(cfg, family).into_iter().collect();
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
                        let have = parse_fenced_destinations(&chain);
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
                            let extra: Vec<_> = have.difference(&want).cloned().collect();
                            let missing: Vec<_> = want.difference(&have).cloned().collect();
                            FamilyStatus::Mismatch(format!(
                                "installed rules differ from config (extra: [{}], missing: [{}])",
                                extra.join(", "),
                                missing.join(", ")
                            ))
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
            if self.fail_fence_list && chain == "DOCKER-FENCE" {
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
        cfg("192.0.2.0/24\n2001:db8:10::/64\n")
    }

    fn chain_lines(cidrs: &[&str]) -> Vec<String> {
        let c: Vec<String> = cidrs.iter().map(|s| s.to_string()).collect();
        expected_rules(&c)
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
        let r = apply(&fw, &cfg("192.0.2.0/24\n")).unwrap();
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
                .any(|n| n == "no subnets configured; nothing is blocked")
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
        let r = status(&fw, &cfg("192.0.2.0/24\n")).unwrap();
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
        let r = apply(&fw, &cfg("192.0.2.0/24\n")).unwrap();
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
    fn status_treats_v6_listing_error_as_unavailable() {
        let mut fw = installed(true, &["192.0.2.0/24"]);
        fw.fail_v6_list = true;
        let r = status(&fw, &cfg("192.0.2.0/24\n")).unwrap();
        assert_eq!(r.families[1].1, FamilyStatus::Skipped);
        assert!(r.is_ok());
        let r = status(&fw, &both()).unwrap();
        assert_eq!(r.families[1].1, FamilyStatus::Missing);
    }
}
