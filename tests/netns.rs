//! Integration tests against real `iptables`/`ip6tables` in throwaway
//! network namespaces. They need root, iptables, iproute2, curl and python3:
//!
//! ```sh
//! sudo -E env "PATH=$PATH" cargo test --test netns -- --ignored --test-threads=1
//! ```

#[path = "netns/mod.rs"]
mod harness;

use std::thread;

use harness::*;

fn jump_count(listing: &[String]) -> usize {
    listing.iter().filter(|l| l.as_str() == JUMP).count()
}

fn first_rule(listing: &[String]) -> Option<&str> {
    listing
        .iter()
        .map(String::as_str)
        .find(|l| l.starts_with("-A "))
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn harness_forwards_without_fence() {
    let h = Harness::new();
    assert!(h.probe_from_container(PN_V4));
    assert!(h.probe_from_container(PN_V6));
    assert!(h.probe_from_container(OTHER_V4));
    assert!(h.probe_from_container(OTHER_V6));
    assert!(h.probe_from_protected(CT_V4));
    assert!(h.probe_from_protected(CT_V6));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn container_new_connection_to_protected_v4_is_rejected() {
    let h = Harness::new();
    assert!(h.probe_from_container(PN_V4), "precondition");
    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    assert!(!h.probe_from_container(PN_V4));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn container_new_connection_to_protected_v6_is_rejected() {
    let h = Harness::new();
    assert!(h.probe_from_container(PN_V6), "precondition");
    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    assert!(!h.probe_from_container(PN_V6));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn unprotected_destination_stays_reachable() {
    let h = Harness::new();
    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    assert!(h.probe_from_container(OTHER_V4));
    assert!(h.probe_from_container(OTHER_V6));
    // Same link, same listener process type: only the CIDR differs.
    assert!(!h.probe_from_container(PN_V4));
    assert!(!h.probe_from_container(PN_V6));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn reply_on_connection_started_from_protected_net_is_allowed() {
    let h = Harness::new();
    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    // The container's replies go docker0 -> protected net and would hit
    // the REJECT rule without the ESTABLISHED,RELATED exception.
    assert!(h.probe_from_protected(CT_V4));
    assert!(h.probe_from_protected(CT_V6));
    assert!(!h.probe_from_container(PN_V4));
    assert!(!h.probe_from_container(PN_V6));

    // Negative control: without the ESTABLISHED,RELATED rule (the first
    // rule of DOCKER-FENCE) the container's SYN-ACK is rejected, so the
    // probes above really did traverse the fence.
    for tool in ["iptables", "ip6tables"] {
        let fence = h.list(tool, "DOCKER-FENCE");
        assert!(
            fence.len() > 1 && fence[1].contains("conntrack"),
            "{tool}: {fence:?}"
        );
        h.ipt(tool, &["-D", "DOCKER-FENCE", "1"]);
    }
    assert!(!h.probe_from_protected(CT_V4));
    assert!(!h.probe_from_protected(CT_V6));

    // Re-applying restores the exception.
    h.apply_ok();
    assert!(h.probe_from_protected(CT_V4));
    assert!(h.probe_from_protected(CT_V6));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn reload_with_smaller_config_unblocks_removed_subnet() {
    let h = Harness::new();
    h.write_config(WIDE_CONFIG);
    h.apply_ok();
    assert!(!h.probe_from_container(OTHER_V4));
    assert!(!h.probe_from_container(OTHER_V6));

    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    assert!(h.probe_from_container(OTHER_V4));
    assert!(h.probe_from_container(OTHER_V6));
    assert!(!h.probe_from_container(PN_V4));
    assert!(!h.probe_from_container(PN_V6));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn invalid_reload_keeps_old_rules() {
    let h = Harness::new();
    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    let before4 = h.list("iptables", "");
    let before6 = h.list("ip6tables", "");

    h.write_config("garbage");
    let out = h.docker_fence(&["apply"]);
    assert_exit(&out, 2, "apply with invalid config");
    assert!(stderr(&out).contains("docker-fence: "), "{}", stderr(&out));

    assert_eq!(h.list("iptables", ""), before4);
    assert_eq!(h.list("ip6tables", ""), before6);
    assert!(!h.probe_from_container(PN_V4));
    assert!(!h.probe_from_container(PN_V6));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn invalid_start_applies_nothing() {
    let h = Harness::new();
    let before4 = h.list("iptables", "");
    let before6 = h.list("ip6tables", "");

    h.write_config("garbage");
    let out = h.docker_fence(&["apply"]);
    assert_exit(&out, 2, "apply with invalid config");

    for tool in ["iptables", "ip6tables"] {
        assert!(!h.chain_exists(tool, "DOCKER-FENCE"), "{tool}");
        assert_eq!(h.list(tool, "DOCKER-USER"), DOCKER_USER_BASELINE, "{tool}");
    }
    assert_eq!(h.list("iptables", ""), before4);
    assert_eq!(h.list("ip6tables", ""), before6);
    assert!(h.probe_from_container(PN_V4));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn missing_config_file_exits_2_and_keeps_rules() {
    let h = Harness::new();
    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    let before4 = h.list("iptables", "");
    let before6 = h.list("ip6tables", "");

    let missing = h.missing_path();
    let out = h.docker_fence_with_config(&missing, &["apply"]);
    assert_exit(&out, 2, "apply with missing config file");
    assert!(
        stderr(&out).contains(missing.to_str().unwrap()),
        "stderr should name the file: {}",
        stderr(&out)
    );

    assert_eq!(h.list("iptables", ""), before4);
    assert_eq!(h.list("ip6tables", ""), before6);
    assert!(!h.probe_from_container(PN_V4));
    assert!(!h.probe_from_container(PN_V6));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn apply_twice_gives_identical_rule_listing() {
    let h = Harness::new();
    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    let first4 = h.list("iptables", "");
    let first6 = h.list("ip6tables", "");

    h.apply_ok();
    assert_eq!(h.list("iptables", ""), first4);
    assert_eq!(h.list("ip6tables", ""), first6);

    for tool in ["iptables", "ip6tables"] {
        let user = h.list(tool, "DOCKER-USER");
        assert_eq!(jump_count(&user), 1, "{tool}: {user:?}");
        assert_eq!(first_rule(&user), Some(JUMP), "{tool}: {user:?}");
    }
    let st = h.docker_fence(&["status"]);
    assert_exit(&st, 0, "status after apply");
    assert_eq!(stdout(&st), "ipv4: ok\nipv6: ok\n");
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn displaced_jump_is_moved_back_to_top() {
    let h = Harness::new();
    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    h.ipt(
        "iptables",
        &[
            "-I",
            "DOCKER-USER",
            "1",
            "-s",
            "203.0.113.0/24",
            "-j",
            "RETURN",
        ],
    );
    h.ipt(
        "ip6tables",
        &[
            "-I",
            "DOCKER-USER",
            "1",
            "-s",
            "2001:db8:30::/64",
            "-j",
            "RETURN",
        ],
    );
    for tool in ["iptables", "ip6tables"] {
        assert_ne!(first_rule(&h.list(tool, "DOCKER-USER")), Some(JUMP));
    }
    let st = h.docker_fence(&["status"]);
    assert_exit(&st, 1, "status with displaced jump");
    assert!(
        stdout(&st).contains("not the first rule"),
        "{}",
        stdout(&st)
    );

    h.apply_ok();
    for tool in ["iptables", "ip6tables"] {
        let user = h.list(tool, "DOCKER-USER");
        assert_eq!(first_rule(&user), Some(JUMP), "{tool}: {user:?}");
        assert_eq!(jump_count(&user), 1, "{tool}: {user:?}");
        // The other rule is still there, and the trailing RETURN stays last.
        assert_eq!(user.len(), 4, "{tool}: {user:?}");
        assert_eq!(user[3], "-A DOCKER-USER -j RETURN", "{tool}: {user:?}");
    }
    let st = h.docker_fence(&["status"]);
    assert_exit(&st, 0, "status after re-apply");
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn remove_deletes_chain_and_jump_but_keeps_other_docker_user_rules() {
    let h = Harness::new();
    h.ipt(
        "iptables",
        &[
            "-I",
            "DOCKER-USER",
            "1",
            "-s",
            "203.0.113.0/24",
            "-j",
            "RETURN",
        ],
    );
    h.ipt(
        "ip6tables",
        &[
            "-I",
            "DOCKER-USER",
            "1",
            "-s",
            "2001:db8:30::/64",
            "-j",
            "RETURN",
        ],
    );
    let user4 = h.list("iptables", "DOCKER-USER");
    let user6 = h.list("ip6tables", "DOCKER-USER");
    assert_eq!(user4.len(), 3, "{user4:?}");
    assert_eq!(user6.len(), 3, "{user6:?}");

    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    assert!(!h.probe_from_container(PN_V4));

    let out = h.docker_fence(&["remove"]);
    assert_exit(&out, 0, "remove");
    for (tool, before) in [("iptables", &user4), ("ip6tables", &user6)] {
        assert!(!h.chain_exists(tool, "DOCKER-FENCE"), "{tool}");
        assert_eq!(&h.list(tool, "DOCKER-USER"), before, "{tool}");
        // FORWARD -> DOCKER-USER is untouched.
        assert!(
            h.list(tool, "FORWARD")
                .iter()
                .any(|l| l == "-A FORWARD -j DOCKER-USER"),
            "{tool}"
        );
    }
    assert!(h.probe_from_container(PN_V4));
    assert!(h.probe_from_container(PN_V6));

    // A second remove has nothing to do and still succeeds.
    let out = h.docker_fence(&["remove"]);
    assert_exit(&out, 0, "second remove");
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn reapply_has_no_gap() {
    const APPLIES: usize = 100;
    const MIN_PROBES: usize = 200;

    let h = Harness::new();
    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    assert!(!h.probe_from_container_within(PN_V4, 1), "precondition");
    assert!(!h.probe_from_container_within(PN_V6, 1), "precondition");

    let (results, applies) = thread::scope(|s| {
        let applier = s.spawn(|| {
            (0..APPLIES)
                .map(|_| h.docker_fence(&["apply"]))
                .collect::<Vec<_>>()
        });
        // Probe without pause, alternating families, for at least
        // MIN_PROBES probes and for as long as the apply loop is running.
        let mut results = Vec::new();
        while results.len() < MIN_PROBES || !applier.is_finished() {
            let addr = if results.len() % 2 == 0 { PN_V4 } else { PN_V6 };
            results.push((addr, h.probe_from_container_within(addr, 1)));
        }
        (results, applier.join().expect("apply loop panicked"))
    });

    for (i, out) in applies.iter().enumerate() {
        assert_exit(out, 0, &format!("apply #{i} in loop"));
    }
    let leaked: Vec<String> = results
        .iter()
        .enumerate()
        .filter(|(_, (_, ok))| *ok)
        .map(|(i, (addr, _))| format!("#{i} {addr}"))
        .collect();
    assert!(
        leaked.is_empty(),
        "{} of {} probes got through during re-apply: {leaked:?}",
        leaked.len(),
        results.len()
    );
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn missing_docker_user_is_a_clear_error() {
    let h = Harness::new();
    h.delete_docker_user("iptables");
    h.delete_docker_user("ip6tables");
    h.write_config(PROTECTED_CONFIG);

    let out = h.docker_fence(&["apply"]);
    assert_exit(&out, 1, "apply without DOCKER-USER");
    let err = stderr(&out);
    assert!(err.contains("Docker"), "{err}");
    assert!(err.starts_with("docker-fence: "), "{err}");
    for tool in ["iptables", "ip6tables"] {
        assert!(!h.chain_exists(tool, "DOCKER-FENCE"), "{tool}");
    }
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn v6_notice_when_ipv6_docker_user_missing() {
    let h = Harness::new();
    h.delete_docker_user("ip6tables");
    h.write_config(PROTECTED_CONFIG);

    let out = h.apply_ok();
    let err = stderr(&out);
    assert!(
        err.contains("docker-fence: WARNING: ip6tables chain DOCKER-USER not found"),
        "{err}"
    );
    assert!(h.chain_exists("iptables", "DOCKER-FENCE"));
    assert!(!h.chain_exists("ip6tables", "DOCKER-FENCE"));
    assert!(!h.probe_from_container(PN_V4));
    // Nothing was installed for IPv6 and FORWARD no longer reaches a fence.
    assert!(h.probe_from_container(PN_V6));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn allow_entry_is_an_exception_inside_a_blocked_network() {
    let h = Harness::new();
    h.write_config(ALLOW_HOST_CONFIG);
    h.apply_ok();
    // The allowed host is reachable again, for both families ...
    assert!(h.probe_from_container(PN_V4));
    assert!(h.probe_from_container(PN_V6));
    // ... while the rest of the same network, and the other blocks, stay as
    // configured: block the other protected /24 and /64 to prove it.
    h.write_config(&format!(
        "{ALLOW_HOST_CONFIG}block 198.51.100.0/24\nblock 2001:db8:20::/64\n"
    ));
    h.apply_ok();
    assert!(h.probe_from_container(PN_V4));
    assert!(h.probe_from_container(PN_V6));
    assert!(!h.probe_from_container(OTHER_V4));
    assert!(!h.probe_from_container(OTHER_V6));

    let st = h.docker_fence(&["status"]);
    assert_exit(&st, 0, "status with allow entries");
    assert_eq!(stdout(&st), "ipv4: ok\nipv6: ok\n");
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn most_specific_entry_wins_for_nested_networks() {
    let h = Harness::new();
    // 192.0.2.2 sits in all of these; only the longest prefix decides.
    let steps = [
        ("block 192.0.2.0/24\n", false),
        ("block 192.0.2.0/24\nallow 192.0.2.0/25\n", true),
        (
            "block 192.0.2.0/24\nallow 192.0.2.0/25\nblock 192.0.2.0/30\n",
            false,
        ),
        (
            "block 192.0.2.0/24\nallow 192.0.2.0/25\nblock 192.0.2.0/30\nallow 192.0.2.2/32\n",
            true,
        ),
    ];
    for (config, reachable) in steps {
        h.write_config(config);
        h.apply_ok();
        assert_eq!(h.probe_from_container(PN_V4), reachable, "{config}");
        let st = h.docker_fence(&["status"]);
        assert_exit(&st, 0, "status");
    }
    // Order in the file does not matter, only prefix length does.
    h.write_config(
        "allow 192.0.2.2/32\nblock 192.0.2.0/30\nallow 192.0.2.0/25\nblock 192.0.2.0/24\n",
    );
    h.apply_ok();
    assert!(h.probe_from_container(PN_V4));
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn bare_cidr_and_conflicting_entries_are_config_errors() {
    let h = Harness::new();
    for config in ["192.0.2.0/24\n", "block 192.0.2.0/24\nallow 192.0.2.0/24\n"] {
        h.write_config(config);
        let out = h.docker_fence(&["apply"]);
        assert_exit(&out, 2, config);
        assert!(!h.chain_exists("iptables", "DOCKER-FENCE"));
    }
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn status_flags_a_missing_allow_entry() {
    let h = Harness::new();
    h.write_config(PROTECTED_CONFIG);
    h.apply_ok();
    h.write_config(ALLOW_HOST_CONFIG);
    let st = h.docker_fence(&["status"]);
    assert_exit(&st, 1, "status after adding an allow to the config");
    assert!(
        stdout(&st).contains("missing: [allow 192.0.2.2/32]"),
        "{}",
        stdout(&st)
    );
}

#[test]
#[ignore = "needs root, iptables, iproute2, curl, python3"]
fn commands_are_echoed_and_dry_run_changes_nothing() {
    let h = Harness::new();
    h.write_config(PROTECTED_CONFIG);
    let before4 = h.list("iptables", "");
    let before6 = h.list("ip6tables", "");

    let out = h.docker_fence(&["apply", "--dry"]);
    assert_exit(&out, 0, "apply --dry");
    let err = stderr(&out);
    assert!(err.contains("[#] iptables -w 10 -S DOCKER-USER"), "{err}");
    assert!(
        err.contains("[#] iptables-restore -w 10 --noflush <<'EOF'\n*filter\n:DOCKER-FENCE"),
        "{err}"
    );
    assert!(
        err.contains("[#] ip6tables-restore -w 10 --noflush"),
        "{err}"
    );
    assert!(err.contains("dry run: no changes were made"), "{err}");
    assert_eq!(h.list("iptables", ""), before4);
    assert_eq!(h.list("ip6tables", ""), before6);
    assert!(h.probe_from_container(PN_V4));

    // A real run echoes the same commands and does change things.
    let out = h.docker_fence(&["apply"]);
    assert_exit(&out, 0, "apply");
    assert!(
        stderr(&out).contains("[#] iptables-restore"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("dry run"), "{}", stderr(&out));
    assert!(!h.probe_from_container(PN_V4));

    // A dry remove leaves the fence in place.
    let out = h.docker_fence(&["--dry", "remove"]);
    assert_exit(&out, 0, "remove --dry");
    assert!(h.chain_exists("iptables", "DOCKER-FENCE"));
    assert!(!h.probe_from_container(PN_V4));
}
