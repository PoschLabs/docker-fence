# Docker Fence

**Keep Docker containers out of networks they don't need to reach.**

A lightweight, host-level firewall for restricting container-initiated connections to protected subnets — without blocking legitimate inbound access to published services.

[Quick start](#quick-start) · [How it works](#how-it-works) · [Documentation](#documentation) · [Security boundaries](#security-boundaries)

</div>

---

## Why docker-fence?

A Docker host often has access to networks that its containers should not: management interfaces, storage systems, hypervisors, or other internal infrastructure. Docker's default networking does not automatically enforce those boundaries.

**docker-fence adds a narrowly scoped outbound boundary:** containers attached to supported Docker bridges cannot initiate new connections to the subnets you specify. Clients *inside* those protected networks can still connect to published container ports, and the containers can reply normally.

```text
                     Docker host
              ┌─────────────────────────┐
              │   Docker containers     │
              │   on bridge networks    │
              └────────────┬────────────┘
                           │
                     docker-fence
                           │
           ┌───────────────┼──────────────────┐
           │               │                  │
           ▼               ▼                  ▼
     Public internet   ManagementNet       StorageNet
        ALLOWED           BLOCKED            BLOCKED
                      new outbound        new outbound
                       connections         connections

     Protected-network clients can still initiate connections
     to published container ports; replies remain permitted.
```

### At a glance

| Traffic | Behavior |
| --- | --- |
| Container → protected subnet | **Blocked** for new connections |
| Container → unprotected network or internet | **Unaffected** by docker-fence |
| Container → container | **Unaffected** by docker-fence |
| Protected subnet → published container port | **Allowed** by docker-fence; other firewall rules still apply |
| Container → Docker host's own address | **Not covered** — requires a host firewall |

No container-side agent, per-container configuration, or application changes are needed for supported bridge networks.

## Quick start

### 1. Install

Download the appropriate `.deb` or `.rpm` from [GitHub Releases](https://github.com/PoschLabs/docker-fence/releases).

**Ubuntu / Debian package:**

```bash
sudo apt install ./docker-fence_<version>_amd64.deb
```

**RPM-based systems:**

```bash
sudo dnf install ./docker-fence-<version>-1.x86_64.rpm
```

> [!NOTE]
> Installation does **not** enable the service or block any traffic. You decide which networks to protect before activating it.

### 2. Define protected subnets

Edit `/etc/docker-fence/docker-fence.conf`:

```ini
# Management network
192.0.2.0/24

# Storage network (IPv6 example)
2001:db8:10::/64
```

Each line contains one IPv4 or IPv6 subnet in CIDR notation. Blank lines and `#` comments are supported. **These are documentation-only example ranges**; replace them with networks from your environment.

See [configuration](docs/configuration.md) for complete syntax and validation rules.

### 3. Enable protection

```bash
sudo systemctl enable --now docker-fence
```

### 4. Verify

```bash
sudo docker-fence status
sudo iptables -S DOCKER-FENCE
```

`status` checks whether the installed rules match the configuration. See the [verification guide](docs/verifying.md) for live network tests and IPv6 checks.

## How it works

docker-fence manages one dedicated `DOCKER-FENCE` chain per supported IP family and inserts a jump at the top of Docker's `DOCKER-USER` chain.

1. **Established and related traffic is returned** so replies to connections initiated from protected networks can pass.
2. **New forwarded traffic from supported Docker bridges** to a configured protected subnet is rejected.
3. **Other traffic is left alone** by docker-fence.

Rules are applied using `iptables` / `ip6tables`. The project manages only its own chain and jump, not your entire firewall configuration.

### Update the configuration safely

After changing the subnet list, reload rather than restart:

```bash
sudo systemctl reload docker-fence
sudo docker-fence status
```

A reload reconciles the rules in place. **If the new configuration is invalid, the previous rules remain installed.** Stopping or restarting the service first can remove that protection, so prefer `reload` for configuration changes.

For implementation details, see [how it works](docs/how-it-works.md).

## Command reference

| Command | Purpose |
| --- | --- |
| `sudo docker-fence status` | Compare installed rules with configuration |
| `sudo docker-fence apply` | Install or reconcile firewall rules |
| `sudo docker-fence remove` | Remove docker-fence's firewall rules |
| `sudo docker-fence --config /path/to/file status` | Validate and compare an alternative configuration |

Normally, **systemd handles `apply` on start/reload and `remove` on stop**. Run `docker-fence --help` for all options.

## Platform support

| Requirement | Support |
| --- | --- |
| Operating system | Linux with systemd |
| Primary tested distribution | Ubuntu Server |
| Additional distribution | Rocky Linux 9+ (best effort; lightly tested) |
| Not supported | Rocky Linux 8 |
| Architectures | x86_64, aarch64 |
| Firewall integration | `iptables` / `ip6tables`, Docker `DOCKER-USER` chain |

## Security boundaries

docker-fence is **one layer of network isolation**, not a replacement for a host firewall, container hardening, or network segmentation.

In particular:

- **Forwarded traffic only.** Traffic destined for the Docker host's own IP addresses is not filtered by docker-fence.
- **Supported bridges only.** Rules match `docker0` and interfaces named `br+`. Custom-named bridges outside this pattern are not covered; non-Docker `br*` bridges may also match.
- **Not all Docker network modes.** `host`, macvlan, and ipvlan networking are outside this filtering path.
- **Existing connections remain.** Applying rules does not terminate previously established sessions.
- **Startup and restart gaps exist.** Containers may start before docker-fence rules are reinstalled; Docker `live-restore` also has special implications.
- **Privileged control can bypass the fence.** Host root or processes able to alter the host firewall can remove the restrictions.

**Read the complete [threat model and limitations](docs/threat-model.md) before relying on docker-fence as a security boundary.**

## Documentation

| Guide | What you'll find |
| --- | --- |
| [Installation](docs/install.md) | Package installation, upgrades, and removal |
| [Configuration](docs/configuration.md) | CIDR syntax, validation, and safe reloads |
| [How it works](docs/how-it-works.md) | Chain layout, connection tracking, and lifecycle |
| [Verification](docs/verifying.md) | Confirm the rules with practical network tests |
| [Troubleshooting](docs/troubleshooting.md) | Diagnose setup and firewall problems |
| [Threat model](docs/threat-model.md) | Supported traffic paths and known limitations |
| [Releasing](docs/releasing.md) | Maintainer packaging and release process |

## Contributing

Bug reports and improvement proposals are welcome through [GitHub Issues](https://github.com/PoschLabs/docker-fence/issues). For security-relevant reports, avoid posting sensitive details publicly.

## License

Released under the [MIT License](LICENSE).

<sub>docker-fence is an independent project and is not affiliated with Docker, Inc.</sub>
