# docker-fence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `docker-fence`, a Rust tool that keeps Docker containers from opening new connections to a configurable list of subnets (IPv4 and IPv6), packaged as signed .deb and .rpm for x86_64 and aarch64, with polished docs.

**Architecture:** A small Rust CLI (`apply`, `remove`, `status`) reads a CIDR list, renders `iptables-restore --noflush` scripts, and installs one dedicated `DOCKER-FENCE` chain plus a single jump at the top of `DOCKER-USER`. A firewall trait separates rule logic (unit-tested with a fake) from the real `iptables` calls (tested in network namespaces). A oneshot systemd unit calls the CLI. GoReleaser `nfpms` builds the packages; a release workflow signs and publishes them using GitHub variables and secrets.

**Tech Stack:** Rust (edition 2024, MSRV 1.85), `ipnet` crate, `iptables`/`ip6tables`/`iptables-restore`, systemd, GoReleaser + cargo-zigbuild, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-01-docker-fence-design.md` (read it first; this plan refers to its numbered calls as "call N").

## Global Constraints

- Repo `PoschLabs/docker-fence`, MIT license. Package, binary, unit and config dir are all named `docker-fence`.
- Chain `DOCKER-FENCE` in the filter table of both `iptables` and `ip6tables`; one jump **inserted at the top** of `DOCKER-USER`.
- First rule in the chain returns `ESTABLISHED,RELATED`; then for each CIDR, `REJECT` for `-i docker0` and `-i br+`. `NEW` and `INVALID` are rejected. No strict mode.
- Config: `/etc/docker-fence/docker-fence.conf`, one CIDR per line, `#` starts a comment, blank lines ignored, anything else is an error naming file and line.
- Invalid config: apply nothing, exit non-zero; on a failed reload the old rules stay (call 4); on start nothing is applied and the unit fails (call 9).
- Reload never flushes and refills the live chain (call 7): one atomic `iptables-restore --noflush` transaction per family.
- Missing IPv4 `DOCKER-USER` is a hard error; missing IPv6 `DOCKER-USER` is skipped with a notice.
- `remove` deletes only the `DOCKER-FENCE` chain and the exact jump rule (call 12).
- Unit: `Type=oneshot`, `RemainAfterExit=yes`, `Requires=`/`After=`/`PartOf=docker.service`; `ExecStart` and `ExecReload` run `apply`, `ExecStop` runs `remove`.
- Targets: Ubuntu Server (primary), Rocky Linux 9+ (best effort; a failing Rocky check never blocks a release). Architectures x86_64 and aarch64.
- Nothing environment-specific in the repo: endpoints and names come from GitHub `vars.*`, credentials from `secrets.*`. No homelab hostnames, subnets or local paths anywhere (code, docs, workflows, tests).
- Docs must state the project is independent and not affiliated with Docker, Inc.
- Exit codes: `0` success, `1` runtime/firewall failure, `2` usage or invalid config.
- Pull-request workflows run on GitHub-hosted runners only. `self-hosted` appears only in tag-triggered release jobs.

## Review Focus

Failure modes the spec implies; each has a test in the named task.

1. Config with CRLF line endings, tabs, trailing spaces, and inline `# comments` is accepted (Task 1).
2. `192.0.2.5/24` (host bits set) is accepted and normalised to `192.0.2.0/24`; a bare IP with no prefix is rejected with its line number (Task 1).
3. Exact duplicate entries produce one rule set; order of first appearance is kept (Task 1).
4. Empty or comment-only config is valid and yields a chain containing only the `ESTABLISHED,RELATED` rule; a missing or unreadable config file is an error that leaves existing rules untouched (Tasks 1, 3, 5).
5. Docker not running (no `DOCKER-USER`) gives a clear hard error; a missing `iptables` binary gives a clear error naming the package to install; IPv6 entries with no IPv6 `DOCKER-USER` give a visible notice, not a silent skip (Task 3).

---

## File Structure

```
Cargo.toml, Cargo.lock, .gitignore, LICENSE
src/main.rs          CLI parsing, exit codes, wiring only
src/config.rs        parse/load the CIDR file
src/rules.rs         pure: Family, rule text, restore-script rendering, listing parsers
src/firewall.rs      Firewall trait + SystemFirewall (spawns iptables tools)
src/ops.rs           apply / remove / status using &dyn Firewall
tests/netns.rs       integration tests (ignored by default; need root)
tests/netns/mod.rs   namespace harness
packaging/docker-fence.service, docker-fence.conf, postinstall.sh, preremove.sh, postremove.sh
.goreleaser.yaml
.github/workflows/ci.yaml, release.yaml
README.md, docs/{install,configuration,how-it-works,verifying,troubleshooting,threat-model,releasing}.md
```

---

### Task 1: Project scaffold and config parser

**Files:**
- Create: `Cargo.toml`, `.gitignore`, `LICENSE` (MIT, holder "PoschLabs"), `src/main.rs` (stub `fn main() {}` plus `mod config;`), `src/config.rs`
- Also commit: the spec and this plan under `docs/superpowers/`

**Interfaces:**
- Produces (`src/config.rs`):
  - `pub const DEFAULT_CONFIG_PATH: &str = "/etc/docker-fence/docker-fence.conf";`
  - `pub struct FenceConfig { pub v4: Vec<ipnet::Ipv4Net>, pub v6: Vec<ipnet::Ipv6Net> }`
  - `pub struct ConfigError { pub path: PathBuf, pub line: Option<usize>, pub message: String }` implementing `Display` as `<path>:<line>: <message>` (or `<path>: <message>` when `line` is `None`) and `std::error::Error`
  - `pub fn parse(text: &str, path: &Path) -> Result<FenceConfig, ConfigError>` (first error wins)
  - `pub fn load(path: &Path) -> Result<FenceConfig, ConfigError>`

- [ ] **Step 1:** Scaffold with cargo tools, not by hand-writing files: from the repo root run `cargo init --name docker-fence --edition 2024 --vcs git` (creates `Cargo.toml`, `src/main.rs`, `.gitignore`, and the git repo), then `cargo add ipnet@2`. Edit `Cargo.toml` only to add `rust-version = "1.85"`, `license = "MIT"`, and `description`; append `/dist` to `.gitignore`; add `LICENSE` (MIT, holder "PoschLabs"); add `mod config;` to `main.rs`. Use `cargo add`/`cargo new`/`cargo init` for any later dependency or crate change as well.
- [ ] **Step 2: Write failing tests** in `src/config.rs` `#[cfg(test)]`, named and asserting:
  - `parses_mixed_families_comments_crlf_and_tabs`: input `"# mgmt\r\n192.0.2.0/24\t # inline\r\n\r\n2001:db8:10::/64  \n"` gives `v4 == [192.0.2.0/24]`, `v6 == [2001:db8:10::/64]`
  - `normalises_host_bits`: `"192.0.2.5/24"` gives `192.0.2.0/24` (use `trunc()`)
  - `rejects_bare_ip_with_line_number`: `"192.0.2.0/24\n192.0.2.5\n"` errors with `line == Some(2)` and `to_string().starts_with("/etc/x.conf:2:")`
  - `rejects_garbage`: `"hello"`, `"192.0.2.0/33"`, `"192.0.2.0/24 extra"` each error
  - `dedupes_exact_duplicates_keeping_order`
  - `empty_and_comment_only_are_ok`
  - `load_missing_file_errors_without_line`
- [ ] **Step 3:** Run `cargo test config` — expect compile/test FAIL.
- [ ] **Step 4:** Implement `parse`/`load`. Strip everything from `#`, trim, skip empty, parse with `str::parse::<IpNet>()`, route to `v4`/`v6`.
- [ ] **Step 5:** Run `cargo test config` — expect all PASS.
- [ ] **Step 6:** `git add -A && git commit -m "feat: scaffold project and parse CIDR config"` (end the message with the attribution line from the session's commit guidance).

---

### Task 2: Rule rendering (pure)

**Files:**
- Create: `src/rules.rs`; add `mod rules;` to `main.rs`

**Interfaces:**
- Consumes: nothing from other tasks (takes CIDRs as `&[String]`).
- Produces:
  - `pub const CHAIN: &str = "DOCKER-FENCE"; pub const USER_CHAIN: &str = "DOCKER-USER";`
  - `#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub enum Family { V4, V6 }` with `pub fn tool(self) -> &'static str` (`"iptables"`/`"ip6tables"`) and `pub fn restore_tool(self) -> &'static str` (`"iptables-restore"`/`"ip6tables-restore"`)
  - `#[derive(Debug, PartialEq, Eq)] pub struct JumpState { pub count: usize, pub at_top: bool }`
  - `pub fn expected_rules(cidrs: &[String]) -> Vec<String>`
  - `pub fn render_apply(cidrs: &[String], jump: &JumpState) -> String`
  - `pub fn render_remove(jump_count: usize) -> String`
  - `pub fn parse_jump_state(user_chain_listing: &[String]) -> JumpState` (input is `iptables -S DOCKER-USER` lines; top means the first `-A` line is the jump)
  - `pub fn parse_fenced_destinations(chain_listing: &[String]) -> std::collections::BTreeSet<String>` (the `-d` values of `-A DOCKER-FENCE` lines)

- [ ] **Step 1: Write failing tests:**
  - `expected_rules_order`: for `["192.0.2.0/24"]` equals exactly `["-A DOCKER-FENCE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN", "-A DOCKER-FENCE -i docker0 -d 192.0.2.0/24 -j REJECT", "-A DOCKER-FENCE -i br+ -d 192.0.2.0/24 -j REJECT"]`; for `[]` only the first line
  - `apply_script_inserts_jump_when_absent`: output is `"*filter\n:DOCKER-FENCE - [0:0]\n<rules, one per line>\n-I DOCKER-USER 1 -j DOCKER-FENCE\nCOMMIT\n"`
  - `apply_script_has_no_jump_lines_when_already_on_top` (`count: 1, at_top: true`)
  - `apply_script_removes_then_reinserts_when_displaced_or_duplicated`: `count: 2, at_top: false` gives two `-D DOCKER-USER -j DOCKER-FENCE` lines before one `-I DOCKER-USER 1 ...`
  - `apply_script_never_declares_docker_user` (no line starting `:DOCKER-USER`, because declaring an existing chain flushes it)
  - `remove_script`: `render_remove(1)` is `"*filter\n-D DOCKER-USER -j DOCKER-FENCE\n-F DOCKER-FENCE\n-X DOCKER-FENCE\nCOMMIT\n"`; `render_remove(0)` omits the `-D` line
  - `jump_state_parsing`: listing `["-N DOCKER-USER","-A DOCKER-USER -j DOCKER-FENCE","-A DOCKER-USER -j RETURN"]` is `{1, true}`; with the jump after RETURN `{1, false}`; with none `{0, false}`
  - `fenced_destinations_parsing`: collects `192.0.2.0/24` from iptables-style `-A DOCKER-FENCE -d 192.0.2.0/24 -i docker0 -j REJECT --reject-with icmp-port-unreachable`
- [ ] **Step 2:** Run `cargo test rules` — expect FAIL.
- [ ] **Step 3:** Implement the functions above. The listing parsers must tolerate iptables reordering options within a line.
- [ ] **Step 4:** Run `cargo test rules` — expect PASS.
- [ ] **Step 5:** Commit `feat: render iptables-restore scripts and parse listings`.

---

### Task 3: Firewall backend and operations

**Files:**
- Create: `src/firewall.rs`, `src/ops.rs`; add both `mod`s to `main.rs`

**Interfaces:**
- Consumes: `rules::{Family, CHAIN, USER_CHAIN, JumpState, render_apply, render_remove, parse_jump_state, parse_fenced_destinations}`, `config::{FenceConfig, ConfigError}`.
- Produces:
  - `firewall.rs`: `pub struct FirewallError(pub String)` (`Display`, `Error`);
    `pub trait Firewall { fn list_chain(&self, family: Family, chain: &str) -> Result<Option<Vec<String>>, FirewallError>; fn restore(&self, family: Family, script: &str) -> Result<(), FirewallError>; }`
    (`None` means the chain does not exist); `pub struct SystemFirewall;` implementing it by running `<tool> -S <chain>` and `<restore_tool> --noflush` with the script on stdin
  - `ops.rs`: `pub enum FenceError { Config(ConfigError), DockerUserMissing(Family), Firewall(FirewallError), PartiallyApplied { applied: Family, failed: Family, cause: FirewallError } }` (`Display`, `Error`, `From` impls)
    `pub struct Report { pub notices: Vec<String> }`
    `pub fn apply(fw: &dyn Firewall, cfg: &FenceConfig) -> Result<Report, FenceError>`
    `pub fn remove(fw: &dyn Firewall) -> Result<Report, FenceError>`
    `pub struct StatusReport { pub families: Vec<(Family, FamilyStatus)> }` with `pub enum FamilyStatus { Skipped, Missing, Mismatch(String), Ok }` and `pub fn status(fw: &dyn Firewall, cfg: &FenceConfig) -> Result<StatusReport, FenceError>`; `StatusReport::is_ok(&self) -> bool`

**Behavior to implement (decisions, not code):**
- `apply`: list `DOCKER-USER` for V4; `None` gives `DockerUserMissing(V4)` before anything is changed. List V6; `None` skips V6 with a notice (a stronger notice if `cfg.v6` is non-empty). Render both scripts before running either. Run V4 then V6; if V6 fails after V4 succeeded, return `PartiallyApplied` naming V4 as applied (no rollback; the error is loud and non-zero). Empty config adds notice "no subnets configured; nothing is blocked".
- `SystemFirewall`: a missing tool binary becomes `FirewallError("iptables not found; install the iptables package")`. For `-S`, exit code 1 whose stderr contains `No chain/target/match by that name` means `Ok(None)`; any other non-zero exit is an error carrying stderr.
- `remove`: per family, list `DOCKER-USER` and `DOCKER-FENCE` independently (a missing `DOCKER-USER` does not stop removal of our chain); if neither jump nor chain exists, make no `restore` call; otherwise one `render_remove` transaction.
- `status`: per family, `Ok` only when the jump count is 1 and at top and `parse_fenced_destinations` equals the config's CIDR set; V6 with no `DOCKER-USER` is `Skipped` when `cfg.v6` is empty, else `Missing`.

- [ ] **Step 1: Write failing tests** in `ops.rs` using an in-test `FakeFirewall` (stores listings per `(Family, chain)`, records `restore` calls, can be told to fail the V6 restore):
  - `apply_sends_v4_and_v6_scripts_in_one_transaction_each`
  - `apply_is_idempotent_when_jump_on_top`: second script contains no `-I`/`-D` lines
  - `apply_missing_v4_docker_user_errors_and_restores_nothing` (assert zero `restore` calls)
  - `apply_skips_v6_with_notice_when_chain_missing` and `..._stronger_notice_when_config_has_v6`
  - `apply_v6_failure_after_v4_reports_partially_applied`
  - `apply_empty_config_warns_and_installs_only_established_rule`
  - `remove_deletes_jump_and_chain_only` (script equals `render_remove(1)`)
  - `remove_with_nothing_installed_makes_no_calls`
  - `remove_still_deletes_chain_when_docker_user_missing`
  - `status_ok_and_mismatch` (extra or missing CIDR gives `Mismatch`; jump not on top gives `Mismatch`)
  - in `firewall.rs`: `missing_binary_error_names_the_package`: run the spawn helper with a nonexistent tool name and assert the error text contains `install the iptables package`
- [ ] **Step 2:** Run `cargo test ops` — expect FAIL.
- [ ] **Step 3:** Implement `firewall.rs` and `ops.rs` per the behavior above.
- [ ] **Step 4:** Run `cargo test` — expect all PASS.
- [ ] **Step 5:** Commit `feat: apply, remove and status operations`.

---

### Task 4: CLI, systemd unit, default config

**Files:**
- Modify: `src/main.rs`
- Create: `packaging/docker-fence.service`, `packaging/docker-fence.conf`

**Interfaces:**
- Consumes: `config::{load, DEFAULT_CONFIG_PATH}`, `ops::{apply, remove, status}`, `firewall::SystemFirewall`.
- Produces: `pub enum Command { Apply, Remove, Status }`; `pub struct Cli { pub command: Command, pub config: PathBuf }`; `pub fn parse_args(args: &[String]) -> Result<Cli, String>` (Err is a usage message). Usage: `docker-fence [--config PATH] <apply|remove|status>`, plus `--help` and `--version` (prints `docker-fence <CARGO_PKG_VERSION>`). Logs go to stderr as `docker-fence: <message>`; notices are printed the same way; `status` prints one line per family (`ipv4: ok`, `ipv6: skipped (no DOCKER-USER chain)`, ...) and exits 1 unless all are ok or skipped.

- [ ] **Step 1: Write failing tests** for `parse_args`: default config path; `--config /tmp/x apply`; unknown command errors; missing command errors; `--version`/`--help` handled.
- [ ] **Step 2:** Run `cargo test` — expect FAIL.
- [ ] **Step 3:** Implement `parse_args` and `main` with the exit codes in Global Constraints (config errors exit 2 and print every message; `remove` ignores the config file).
- [ ] **Step 4:** Write the unit file exactly as in the Global Constraints (`ExecStart=/usr/bin/docker-fence apply`, `ExecReload=/usr/bin/docker-fence apply`, `ExecStop=/usr/bin/docker-fence remove`, `WantedBy=multi-user.target`, `Documentation=https://github.com/PoschLabs/docker-fence`). Write the default config with only comments: a header explaining the format and commented examples `# 192.0.2.0/24` and `# 2001:db8:10::/64`.
- [ ] **Step 5:** Run `cargo test` — PASS; run `systemd-analyze verify packaging/docker-fence.service` (a "binary not found" warning for `/usr/bin/docker-fence` is acceptable; no syntax errors).
- [ ] **Step 6:** Commit `feat: command line, systemd unit and default config`.

---

### Task 5: Integration tests in network namespaces

**Files:**
- Create: `tests/netns.rs`, `tests/netns/mod.rs`

**Interfaces:**
- Consumes: the built binary via `env!("CARGO_BIN_EXE_docker-fence")`.
- Produces: `Harness::new() -> Harness` (creates and on `Drop` deletes the namespaces), `h.write_config(&str)`, `h.docker_fence(&[&str]) -> Output` (runs the binary inside the host namespace with `--config`), `h.probe_from_container(addr) -> bool`, `h.probe_from_protected(addr) -> bool`, `h.fh(&[&str]) -> Output` (run any command in the host namespace).

**Harness topology** (all via `ip netns`; names prefixed `fence-test-<pid>`): namespace `host` (stands in for the Docker host) with bridge `docker0` (172.30.0.1/24, `fd30::1/64`), a veth into namespace `ct` (container: 172.30.0.2, `fd30::2`, default route via the bridge) and a veth `prot0` into namespace `pn` (protected network host: 192.0.2.2/24 and `2001:db8:10::2/64`, host side 192.0.2.1 and `2001:db8:10::1`; `pn` routes back to the 172.30.0.0/24 and `fd30::/64` networks via the host). Enable IPv4 and IPv6 forwarding in `host`. Emulate Docker in `host`: create `DOCKER-USER` containing only `-A DOCKER-USER -j RETURN` (so the "appended after RETURN" problem is real), and make `FORWARD` jump to it, in both `iptables` and `ip6tables`. Probes use `curl --max-time 3` against `python3 -m http.server` listeners (port 9000 in `pn`, 9001 in `ct`).

All tests are `#[ignore]` (need root) and run with `sudo -E env "PATH=$PATH" cargo test --test netns -- --ignored --test-threads=1`.

- [ ] **Step 1: Write the harness and a smoke test** `harness_forwards_without_fence`: with no rules, `probe_from_container("192.0.2.2:9000")` is true. Run it; it must pass before anything else is written.
- [ ] **Step 2: Write these tests** (each applies a config and asserts probe results):
  - `container_new_connection_to_protected_v4_is_rejected` and `..._v6_...` (config `192.0.2.0/24` and `2001:db8:10::/64`)
  - `unprotected_destination_stays_reachable` (a second listener on an address outside the CIDRs)
  - `reply_on_connection_started_from_protected_net_is_allowed`: `probe_from_protected("172.30.0.2:9001")` is true while the fence is applied
  - `reload_with_smaller_config_unblocks_removed_subnet`
  - `invalid_reload_keeps_old_rules`: after a good apply, write `"garbage"`, apply exits 2, and the container is still blocked
  - `invalid_start_applies_nothing`: invalid config on a clean host exits 2 and no `DOCKER-FENCE` chain exists
  - `missing_config_file_exits_2_and_keeps_rules`
  - `apply_twice_gives_identical_rule_listing`
  - `displaced_jump_is_moved_back_to_top`: insert another rule above the jump, apply, assert `-S DOCKER-USER` lists the jump first
  - `remove_deletes_chain_and_jump_but_keeps_other_docker_user_rules`
  - `reapply_has_no_gap`: while a loop of 100 `apply` runs in the host namespace, 200 container probes to the protected host must all fail
  - `missing_docker_user_is_a_clear_error`: delete `DOCKER-USER` first; apply exits 1 and stderr mentions Docker
  - `v6_notice_when_ipv6_docker_user_missing`: delete only the IPv6 `DOCKER-USER`; config with an IPv6 CIDR; apply exits 0 and stderr contains a notice
- [ ] **Step 3:** Run the suite; expect FAIL where behavior differs. Fix the implementation (not the tests) for real bugs; if `iptables-restore` rejects a `-X`/`-F` line or behaves differently under the nft backend, adjust `rules.rs` and its unit tests accordingly.
- [ ] **Step 4:** Run the suite until all PASS on Ubuntu (note the `iptables --version` backend in the commit message).
- [ ] **Step 5:** Commit `test: integration tests in network namespaces`.

---

### Task 6: Pull-request CI

**Files:**
- Create: `.github/workflows/ci.yaml`

**Interfaces:** none.

- [ ] **Step 1:** Write the workflow, triggered on `pull_request` and pushes to `main`, `permissions: contents: read`, all jobs `runs-on: ubuntu-latest` (never self-hosted):
  - `lint-test`: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`
  - `integration`: install `iptables iproute2 curl python3`, then the Task 5 command
  - `rocky9`: `container: { image: rockylinux:9, options: --privileged }`, install `iptables iproute curl python3 gcc` and a minimal rustup toolchain, run the Task 5 command; set `continue-on-error: true`
- [ ] **Step 2:** Run `cargo fmt --check` and `cargo clippy -- -D warnings` locally and fix findings.
- [ ] **Step 3:** Validate the YAML (`python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yaml'))"`); a real run happens on the first pull request.
- [ ] **Step 4:** Commit `ci: lint, test and integration workflow`.

---

### Task 7: Packaging (GoReleaser nfpms)

**Files:**
- Create: `.goreleaser.yaml`, `packaging/postinstall.sh`, `packaging/preremove.sh`, `packaging/postremove.sh`

**Interfaces:** consumes `packaging/docker-fence.service` and `packaging/docker-fence.conf` from Task 4.

- [ ] **Step 1:** Write `.goreleaser.yaml` following the maintainer's reference project: `version: 2`, `project_name: docker-fence`, Rust builder with `--release` and targets `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (static binaries avoid a glibc floor; if the builder rejects them, fall back to the `-gnu` targets with a glibc suffix and note it in the commit), tar.gz archives, `checksums.txt`, `release.github` owner `PoschLabs` name `docker-fence`. `nfpms`: `package_name: docker-fence`, vendor/maintainer `PoschLabs`, homepage `https://github.com/PoschLabs/docker-fence`, license MIT, formats `deb` and `rpm`, `dependencies: [iptables]` (no Docker dependency; call in "Left to the builder"), `bindir: /usr/bin`, contents: the unit to `/usr/lib/systemd/system/docker-fence.service`, the config to `/etc/docker-fence/docker-fence.conf` with `type: config|noreplace`, `LICENSE` as `type: license`; scripts `postinstall`, `preremove`, `postremove`.
- [ ] **Step 2:** Scripts (POSIX `sh`, every systemctl call guarded with `|| true` and skipped when `/run/systemd/system` is absent): `postinstall` runs `systemctl daemon-reload` and does **not** enable or start the service; `preremove` stops and disables the service only when `$1` is `remove` (deb) or `0` (rpm), never on upgrade; `postremove` runs `daemon-reload`.
- [ ] **Step 3:** Run `goreleaser release --snapshot --clean --skip=publish` (install `cargo-zigbuild` and Zig 0.13.0 as the reference workflow does). Expect four packages in `dist/` (deb and rpm for each architecture).
- [ ] **Step 4: Verify the packages:**
  - `dpkg-deb -c dist/*amd64*.deb` lists the binary, unit, config, license; `dpkg-deb -e` then `cat DEBIAN/conffiles` lists `/etc/docker-fence/docker-fence.conf`
  - `rpm -qpl` and `rpm -qpc` list the same, with the config flagged as a config file; `rpm -qp --scripts` shows the three scripts
  - install the .deb in an `ubuntu:24.04` container and the .rpm in a `rockylinux:9` container; `docker-fence --version` prints the version
- [ ] **Step 5:** Commit `build: GoReleaser packaging for deb and rpm`.

---

### Task 8: Release workflow

**Files:**
- Create: `.github/workflows/release.yaml`

**Interfaces:** consumes `.goreleaser.yaml` from Task 7.

- [ ] **Step 1:** Adapt the maintainer's reference release workflow (the maintainer provides a local checkout): trigger on tags `v*`; jobs `test` (ubuntu-latest, `cargo test` unit tests), `build` (needs `test`; Rust toolchain, `cargo-zigbuild`, Zig, GoReleaser with `--skip=publish`, upload unsigned `.deb`/`.rpm` as an artifact), `sign-release` (needs `build`; `runs-on: [self-hosted]`; sign RPMs, create the GitHub Release with the signed files), `publish-packages` (needs `build`, `sign-release`; self-hosted; publish to the APT and YUM repositories). Keep the reference project's custom `uses:` action references as they are, and list them in the Task 10 checklist for the maintainer to confirm they are fine to appear publicly.
- [ ] **Step 2:** Replace every environment-specific literal with variables or secrets:

  | Purpose | Reference |
  |---|---|
  | signing service URL | `vars.SIGNING_URL` |
  | signing role | `vars.SIGNING_ROLE` |
  | signing auth path | `vars.SIGNING_AUTH_PATH` |
  | OIDC audience | `vars.SIGNING_OIDC_AUDIENCE` |
  | signing secret path | `vars.SIGNING_SECRET_PATH` |
  | package repository URL | `vars.PACKAGES_URL` |
  | APT / YUM repository names | `vars.APT_REPOSITORY`, `vars.YUM_REPOSITORY` |
  | repository credentials | `secrets.PACKAGES_USERNAME`, `secrets.PACKAGES_PASSWORD` |

- [ ] **Step 3:** Check that no environment-specific values remain: grep `.github`, `.goreleaser.yaml` and `packaging` for the maintainer's hostnames, personal repo names and private subnets that the controller supplies; none may remain, except the two custom action references from the reference project in the release workflow.
- [ ] **Step 4:** Validate the YAML as in Task 6. A real tag run happens in Task 10.
- [ ] **Step 5:** Commit `ci: tag-triggered release workflow using repository variables`.

---

### Task 9: Documentation

**Files:**
- Create: `README.md`, `docs/install.md`, `docs/configuration.md`, `docs/how-it-works.md`, `docs/verifying.md`, `docs/troubleshooting.md`, `docs/threat-model.md`, `docs/releasing.md`

**Interfaces:** none. Examples use only documentation ranges `192.0.2.0/24` and `2001:db8:10::/64`.

- [ ] **Step 1:** `README.md`: one-paragraph purpose, the three-network scenario in generic words, a 5-line quick start (install, edit config, `systemctl enable --now docker-fence`, verify), links to every docs page, supported platforms (Ubuntu primary; Rocky 9+ best effort), license, and the "independent project, not affiliated with Docker, Inc." statement.
- [ ] **Step 2:** `install.md` (apt and yum repository setup with placeholder URLs, manual .deb/.rpm install, the service is installed disabled on purpose, upgrade and removal behavior), `configuration.md` (file format, examples, error messages with a sample, reload with `systemctl reload docker-fence`, host-bits normalisation, empty config), `how-it-works.md` (the chain layout with an example `iptables -S` listing, why the jump is inserted at the top of `DOCKER-USER` because Docker's chain ends in `RETURN`, atomic reload, why only new connections are blocked and replies are allowed, start/stop/restart lifecycle with Docker).
- [ ] **Step 3:** `verifying.md` (the `status` command, `iptables -S DOCKER-FENCE`, and a worked test with a throwaway container using a documentation-range target), `troubleshooting.md` (Docker not running, missing `iptables`, IPv6 notice, Rocky and firewalld interaction (call 14), unit failed after bad config), `threat-model.md` (what it protects; and the known limitations verbatim from the spec: forwarded traffic only so the host's own addresses are not covered, `docker0` and `br+` only so custom bridge names are not covered, `DOCKER-USER` required).
- [ ] **Step 4:** `releasing.md`: the maintainer setup for a fork or new repo: the variables table from Task 8 with placeholder values, the two secrets, the signing role, the self-hosted runner requirement, and a warning not to run untrusted pull-request code on self-hosted runners.
- [ ] **Step 5:** Check: grep `README.md` and `docs` for environment-specific values (the maintainer's hostnames, personal repo names, private subnets) that the controller supplies, plus generic private ranges (`192\.168|172\.16`); none may remain; every relative link in the README resolves to an existing file.
- [ ] **Step 6:** Commit `docs: README and documentation pages`.

---

### Task 10: Release readiness

**Files:** none new (fixes only if something fails).

- [ ] **Step 1:** Run the full local suite: `cargo fmt --check && cargo clippy -- -D warnings && cargo test`, then the Task 5 integration command. All pass.
- [ ] **Step 2:** On a real Ubuntu Server host with Docker: install the snapshot .deb, edit the config, `systemctl enable --now docker-fence`, run `docker-fence status`, start a throwaway container and confirm a new connection to a configured subnet is refused while a management-side connection to a published port still works; `systemctl restart docker` and confirm `status` is ok afterwards; `systemctl stop docker-fence` and confirm `iptables -S` shows no `DOCKER-FENCE`.
- [ ] **Step 3:** Repeat Step 2 on Rocky Linux 9 (best effort; record any firewalld interaction in `docs/troubleshooting.md`).
- [ ] **Step 4:** Maintainer checklist (hand to the maintainer, do not perform): create the repo variables and secrets from `docs/releasing.md`, create the signing role, confirm the two custom action references in `release.yaml` are fine to be public, confirm the self-hosted runner only serves tag-triggered jobs, then push a `v0.1.0` tag and confirm signed packages appear in the APT and YUM repositories.
- [ ] **Step 5:** Check the name `docker-fence` is not already taken on GitHub and in common package indexes (promised earlier to the maintainer); report the result.
