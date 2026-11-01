# docker-fence — Design

Date: 2026-11-01
Status: approved
Repo: `PoschLabs/docker-fence` (open source, MIT)

## Intent and why

A common server layout has several network interfaces: a management network, a
storage network, and a service-facing network (DMZ-like, where others reach the
services). Docker containers run on the same hosts. If a container is
compromised, it must not be able to reach the management or storage networks.

The starting point is a hand-made setup: a small shell script plus a oneshot
systemd unit. The script appends `REJECT` rules to the `DOCKER-USER` chain for
traffic arriving from `docker0` and `br+` and headed to a few hardcoded IPv4
subnets.

The goal is to turn this into a proper, public, polished project called
**docker-fence**: a configurable tool, installable as a .deb and .rpm, with good
documentation. Motivation is convenience (no copying files between servers) and
publishing it as open source.

## Goals

- Block traffic from Docker containers to a configurable list of subnets, for
  both IPv4 and IPv6.
- Configure the subnets in one plain config file in CIDR notation.
- The firewall always matches the config: reload reconciles, stop removes.
- Ship as signed .deb and .rpm (x86_64 and aarch64) through the maintainer's
  standard release pipeline, published to an APT and a YUM repository.
- Polished documentation in the repo: a README plus a `docs/` folder.

## Non-goals

- Not a general firewall manager. No allow-lists, per-container rules, port
  rules, or rate limits.
- Does not manage Docker itself, or replace host firewalls (ufw, firewalld,
  nftables rulesets).
- No support for non-Docker runtimes (Podman, containerd) is promised.
- No documentation website. GitHub rendering of Markdown is enough.
- Does not protect traffic from containers to the host's own addresses (see
  "Known limitations").

## Anti-goals (a failure even if it technically works)

- Silently applying a partial or wrong rule set because of a config typo.
- Touching or removing firewall rules it did not create.
- Leaving rules behind after the service is stopped.
- Giving a false sense of security: the docs must state the limits honestly.

## Constraints

- Language: **Rust** (the maintainer's choice; it reuses the existing GoReleaser +
  cargo-zigbuild pipeline). The `ipnet` crate (or similar) is acceptable for
  CIDR parsing.
- Firewall access: shell out to `iptables` and `ip6tables`. Works on Ubuntu and
  Rocky through the iptables-nft compatibility layer. (Maintainer's call to avoid
  linking firewall libraries; the builder may revisit only with good reason.)
- Targets: Ubuntu Server (primary, most tested). Rocky Linux 9 and newer
  (supported, lightly tested). Rocky 8
  is not a target.
- Architectures: x86_64 and aarch64. The maintainer says aarch64 is "only a build
  step" (an extra target in the build config).
- Runs as root, under systemd.
- License: MIT.
- Naming: package, binary, unit, and config dir are all `docker-fence`. The docs
  must say it is an independent project, not affiliated with Docker, Inc.

## Decisions made

### Behavior

- The tool owns a dedicated chain, `DOCKER-FENCE`, in both `iptables` and
  `ip6tables` (filter table). One jump rule is **inserted at the top** of
  `DOCKER-USER` that sends traffic to `DOCKER-FENCE`.
- **Only new connections are blocked (maintainer's decision).** The first rule in
  `DOCKER-FENCE` returns packets in connection states `ESTABLISHED,RELATED`, so
  replies that containers send on connections started from a protected network
  (for example a management host reaching a published container port) keep
  working. The original script was stateless and rejected these replies too.
  There is no strict (stateless) mode.
- After that rule, for every configured CIDR, there are `REJECT` rules for
  traffic coming in on `docker0` and on `br+` (the same interface matches as
  the current script). Everything not in `ESTABLISHED,RELATED`, including
  `NEW` and `INVALID` packets, is rejected.
- Traffic from the protected networks to containers is never matched, because
  it enters on a physical interface, not a bridge.
- **apply** (start and reload): validate the config first; if valid, rebuild the
  chain so it matches the config exactly. Idempotent: running it twice gives
  the same result.
- **remove** (stop): delete the jump rule and the chain. Nothing else in
  `DOCKER-USER` is changed.
- **Invalid config:** refuse to apply anything, report the error naming the
  file and line, and exit non-zero. Presumed (maintainer's guess, confirm in
  review): on a failed reload, the existing rules stay in place, so a typo never
  removes protection.
- IPv4 and IPv6 entries can be mixed in one file; each goes to the matching
  tool.
- **IPv6 and Docker:** Docker only creates the IPv6 `DOCKER-USER` chain when its
  IPv6 firewalling is enabled. If the chain does not exist, skip IPv6 and log a
  clear notice. This is not an error, because containers then have no IPv6.

### Config

- File: `/etc/docker-fence/docker-fence.conf`.
- One CIDR per line (for example `192.0.2.0/24`, `2001:db8:10::/64`). `#` starts a
  comment. Blank lines are ignored.
- Strict: anything that is not a valid CIDR on a line is an error.

### Service

- systemd unit `docker-fence.service`: `Type=oneshot`, `RemainAfterExit=yes`,
  ordered after and `Requires=`/`PartOf=` `docker.service` (as in the current
  unit). `ExecStart` applies, `ExecReload` applies, `ExecStop` removes.

### Packaging and release

- GoReleaser `nfpms` produces .deb and .rpm, following the maintainer's
  reference project (a `.goreleaser.yaml` and a `release.yaml` workflow). A `v*`
  tag triggers build, then RPM signing, then the GitHub Release, then
  publishing to the APT and YUM repositories. Nothing
  environment-specific appears in the repo: every endpoint and name (signing
  service URL, signing role and secret path, package repository URL and
  repository names) comes from GitHub repository **variables** (`vars.*`), and
  credentials come from repository **secrets**. The workflow and docs name the
  required variables, with placeholder values only.
- Installed files: the binary (`/usr/bin/docker-fence`), the systemd unit, and
  the config file as a config file that package upgrades must not overwrite.
- GitHub org is `PoschLabs`; use it for all owner and homepage values copied
  from the reference project.

### Documentation

- `README.md` is the front page. Detailed pages go in `docs/` (rendered by
  GitHub): install on Ubuntu and Rocky, configuration, how it works, verifying
  the rules, troubleshooting, and the threat model (what it protects and what it
  does not).
- The docs say plainly that Ubuntu is the main tested platform.

## Known limitations (must be in the docs)

- `DOCKER-USER` filters **forwarded** traffic. A container connecting to the
  host's own addresses (for example the host's management IP) goes through the
  `INPUT` chain, which this tool does not touch. Protecting the host itself
  needs host firewall rules. The maintainer has not decided whether to cover this;
  for now it is a documented non-goal.
- The interface matches are `docker0` and `br+`. Docker networks created with a
  custom bridge name that does not start with `br` are not covered.
- Only the filter table's `DOCKER-USER` chain is used. Docker versions that do
  not provide it are unsupported.

## Calls I made (the maintainer should check these)

These are my choices, not decisions the maintainer made:

1. The chain name `DOCKER-FENCE`, and inserting the jump at the **top** of
   `DOCKER-USER`. Docker's default `DOCKER-USER` chain ends with a `RETURN`
   rule, and the original script appends after it, so those rules may never
   match. This should be verified (`iptables -S DOCKER-USER` on a server); the
   new design avoids the problem either way.
2. Config path, file format, and `apply`/`remove` as the subcommands.
3. MIT license (copied from the example repo).
4. On a failed reload, keep the old rules.
5. Skipping IPv6 quietly (with a log notice) when Docker has no IPv6
   `DOCKER-USER` chain.
6. Subnets only, with no option to configure interface patterns.

## Further calls (added after the builder check; also the maintainer's to check)

7. **No protection gap on reload.** Apply must not flush-and-refill the live
   chain. Build the new rule set first, then swap it in (for example a new
   chain plus an atomic jump swap, or `iptables-restore --noflush`). The
   mechanism is the builder's choice; the guarantee is required.
8. **Failure handling in apply.** Validate the config and check that the
   required chains exist before changing anything. A missing IPv4
   `DOCKER-USER` is a hard error (unit fails loudly, nothing applied). A
   missing IPv6 chain is a skip (see above). If a step fails midway, the
   previous state is left or restored; the end state is never half-applied
   silently, and the exit code is non-zero.
9. **Invalid config on start** (not reload): the unit fails loudly and no rules
   are applied. There is no safe "old state" to keep, and the failure is
   visible in `systemctl status`.
10. **Jump position.** Apply re-inserts the jump at the top of `DOCKER-USER` if
    it is missing or displaced. A Docker restart restarts the unit through
    `PartOf=`, so the rules are rebuilt.
11. **Read-only `status` subcommand** that shows whether the chain and jump
    exist and match the config, to support the "verifying the rules" doc page.
12. **Ownership.** `remove` deletes only the `DOCKER-FENCE` chain and the exact
    jump rule it created; nothing else is touched.
13. **Tests.** Unit tests (config parsing, rule generation) are required. An
    integration test against real `iptables`/`ip6tables` in a network namespace
    in CI is also required for pull requests, including a check that a
    blocked destination is actually rejected.
14. **Rocky 9 and firewalld.** Document that Docker with firewalld can
    interact with direct iptables rules. A failing Rocky check does not block a
    release; Ubuntu does.
15. **Release prerequisites.** The maintainer says the packaging
    infrastructure (signing service, package repositories, self-hosted runner)
    is in place. The new repo still needs its own signing role, repository
    variables and secrets; the plan lists these as setup steps for the
    maintainer and does not assume they exist.

16. The `INVALID` state is rejected along with `NEW` (only
    `ESTABLISHED,RELATED` passes). The integration test must cover both
    directions: a container's new connection to a protected subnet is
    rejected, and a reply on a connection started from that subnet is allowed.

## Left to the builder

- Crate layout, error types, logging style, and exit codes.
- Test strategy (unit tests for parsing and rule generation; whether and how to
  run tests against real `iptables`, for example in a container or network
  namespace in CI).
- Package metadata: dependencies (`iptables`; whether `docker` is a hard,
  recommended, or no dependency, given the several Docker package names across
  distros), whether the service is enabled on install (a safe default is to
  install it disabled, with an empty example config), scripts for install and
  removal.
- The behavior for an empty config (suggested: valid, creates an empty chain,
  logs a warning).
- Exact rule options (for example the `REJECT` reject type, comments on rules).
- CI additions beyond the release workflow (build and test on pull requests).
- Doc structure and wording within the page list above.
