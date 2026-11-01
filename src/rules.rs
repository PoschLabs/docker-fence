use std::collections::BTreeSet;

pub const CHAIN: &str = "DOCKER-FENCE";
pub const USER_CHAIN: &str = "DOCKER-USER";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn tool(self) -> &'static str {
        match self {
            Family::V4 => "iptables",
            Family::V6 => "ip6tables",
        }
    }

    pub fn restore_tool(self) -> &'static str {
        match self {
            Family::V4 => "iptables-restore",
            Family::V6 => "ip6tables-restore",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct JumpState {
    pub count: usize,
    pub at_top: bool,
}

pub fn expected_rules(cidrs: &[String]) -> Vec<String> {
    let mut rules = vec![format!(
        "-A {CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
    )];
    for cidr in cidrs {
        for iface in ["docker0", "br+"] {
            rules.push(format!("-A {CHAIN} -i {iface} -d {cidr} -j REJECT"));
        }
    }
    rules
}

/// Build an atomic `iptables-restore --noflush` script. Never declares
/// DOCKER-USER (declaring an existing chain would flush it).
pub fn render_apply(cidrs: &[String], jump: &JumpState) -> String {
    let mut out = format!("*filter\n:{CHAIN} - [0:0]\n");
    for rule in expected_rules(cidrs) {
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

pub fn render_remove(jump_count: usize) -> String {
    let mut out = String::from("*filter\n");
    for _ in 0..jump_count {
        out.push_str(&format!("-D {USER_CHAIN} -j {CHAIN}\n"));
    }
    out.push_str(&format!("-F {CHAIN}\n-X {CHAIN}\nCOMMIT\n"));
    out
}

fn is_jump(line: &str) -> bool {
    line.split_whitespace().collect::<Vec<_>>() == ["-A", USER_CHAIN, "-j", CHAIN]
}

pub fn parse_jump_state(user_chain_listing: &[String]) -> JumpState {
    let count = user_chain_listing.iter().filter(|l| is_jump(l)).count();
    let at_top = user_chain_listing
        .iter()
        .find(|l| l.trim_start().starts_with("-A "))
        .is_some_and(|l| is_jump(l));
    JumpState { count, at_top }
}

pub fn parse_fenced_destinations(chain_listing: &[String]) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for line in chain_listing {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 2 || toks[0] != "-A" || toks[1] != CHAIN {
            continue;
        }
        for w in toks.windows(2) {
            if w[0] == "-d" {
                set.insert(w[1].to_string());
            }
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    const R0: &str = "-A DOCKER-FENCE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN";
    const R1: &str = "-A DOCKER-FENCE -i docker0 -d 192.0.2.0/24 -j REJECT";
    const R2: &str = "-A DOCKER-FENCE -i br+ -d 192.0.2.0/24 -j REJECT";

    #[test]
    fn expected_rules_order() {
        assert_eq!(expected_rules(&s(&["192.0.2.0/24"])), vec![R0, R1, R2]);
        assert_eq!(expected_rules(&[]), vec![R0]);
    }

    #[test]
    fn apply_script_inserts_jump_when_absent() {
        let out = render_apply(&s(&["192.0.2.0/24"]), &JumpState { count: 0, at_top: false });
        assert_eq!(
            out,
            format!("*filter\n:DOCKER-FENCE - [0:0]\n{R0}\n{R1}\n{R2}\n-I DOCKER-USER 1 -j DOCKER-FENCE\nCOMMIT\n")
        );
    }

    #[test]
    fn apply_script_has_no_jump_lines_when_already_on_top() {
        let out = render_apply(&s(&["192.0.2.0/24"]), &JumpState { count: 1, at_top: true });
        assert!(!out.contains("-j DOCKER-FENCE"));
        assert!(out.ends_with("COMMIT\n"));
    }

    #[test]
    fn apply_script_removes_then_reinserts_when_displaced_or_duplicated() {
        let out = render_apply(&[], &JumpState { count: 2, at_top: false });
        let d = "-D DOCKER-USER -j DOCKER-FENCE\n";
        assert!(out.contains(&format!("{d}{d}-I DOCKER-USER 1 -j DOCKER-FENCE\nCOMMIT\n")));
        assert_eq!(out.matches("-D DOCKER-USER").count(), 2);
    }

    #[test]
    fn apply_script_never_declares_docker_user() {
        for j in [
            JumpState { count: 0, at_top: false },
            JumpState { count: 1, at_top: true },
            JumpState { count: 3, at_top: false },
        ] {
            let out = render_apply(&s(&["192.0.2.0/24"]), &j);
            assert!(!out.lines().any(|l| l.starts_with(":DOCKER-USER")));
        }
    }

    #[test]
    fn remove_script() {
        assert_eq!(
            render_remove(1),
            "*filter\n-D DOCKER-USER -j DOCKER-FENCE\n-F DOCKER-FENCE\n-X DOCKER-FENCE\nCOMMIT\n"
        );
        assert_eq!(render_remove(0), "*filter\n-F DOCKER-FENCE\n-X DOCKER-FENCE\nCOMMIT\n");
    }

    #[test]
    fn jump_state_parsing() {
        let top = s(&["-N DOCKER-USER", "-A DOCKER-USER -j DOCKER-FENCE", "-A DOCKER-USER -j RETURN"]);
        assert_eq!(parse_jump_state(&top), JumpState { count: 1, at_top: true });
        let low = s(&["-N DOCKER-USER", "-A DOCKER-USER -j RETURN", "-A DOCKER-USER -j DOCKER-FENCE"]);
        assert_eq!(parse_jump_state(&low), JumpState { count: 1, at_top: false });
        let none = s(&["-N DOCKER-USER", "-A DOCKER-USER -j RETURN"]);
        assert_eq!(parse_jump_state(&none), JumpState { count: 0, at_top: false });
    }

    #[test]
    fn fenced_destinations_parsing() {
        let l = s(&[
            "-N DOCKER-FENCE",
            "-A DOCKER-FENCE -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
            "-A DOCKER-FENCE -d 192.0.2.0/24 -i docker0 -j REJECT --reject-with icmp-port-unreachable",
        ]);
        let got = parse_fenced_destinations(&l);
        assert_eq!(got.into_iter().collect::<Vec<_>>(), vec!["192.0.2.0/24".to_string()]);
    }
}
