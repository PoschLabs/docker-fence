# docker-fence

docker-fence stops Docker containers from opening new connections to subnets you list, for IPv4 and IPv6. It installs a dedicated `DOCKER-FENCE` chain, hooked at the top of Docker's `DOCKER-USER` chain. Replies on connections that were started from a protected network are still allowed, so those networks can keep reaching ports published by your containers. It reconciles its rules on reload and removes everything when the service stops.

An example scenario: a server has a public network, a management network and a storage network. Containers are published on the public side, but they have no business starting connections into the management or storage networks, and a compromised container should not be able to. You list those two subnets in the config file and docker-fence blocks container-initiated traffic to them. Administrators on the management network can still reach published container ports.

This is an independent project, not affiliated with Docker, Inc.

## Quick start

```sh
sudo apt install ./docker-fence_<version>_amd64.deb      # or: sudo dnf install ./docker-fence-<version>-1.x86_64.rpm
sudoedit /etc/docker-fence/docker-fence.conf             # one CIDR per line, e.g. 192.0.2.0/24
sudo systemctl enable --now docker-fence
sudo docker-fence status
sudo iptables -S DOCKER-FENCE
```

The service is installed disabled on purpose: nothing is blocked until you configure and enable it. See [docs/install.md](docs/install.md) for repository-based installation.

## Documentation

- [Installation](docs/install.md)
- [Configuration](docs/configuration.md)
- [How it works](docs/how-it-works.md)
- [Verifying](docs/verifying.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Threat model and limitations](docs/threat-model.md)
- [Releasing (maintainers)](docs/releasing.md)

## Command line

```text
usage: docker-fence [--config PATH] <apply|remove|status>
       docker-fence --help | --version
```

Normally you do not run these directly; the systemd unit does (`apply` on start and reload, `remove` on stop). `status` is for you.

## Supported platforms

- Ubuntu Server: the primary and most tested platform.
- Rocky Linux 9 and newer: best effort, lightly tested.
- Rocky Linux 8: not supported.

Architectures: x86_64 and aarch64. It needs systemd, `iptables`/`ip6tables` and a Docker version that provides the `DOCKER-USER` chain.

docker-fence is not a general firewall. Read [the limitations](docs/threat-model.md) before relying on it; in particular it does not protect the host's own addresses.

## License

MIT. See [LICENSE](LICENSE).
