# Threat model and limitations

docker-fence is a small tool with a narrow job. Do not read more into it than this page says.

## What it protects

It stops containers from opening new connections to the networks you list, for IPv4 and IPv6, when the traffic is forwarded by the host from a Docker bridge. The intent is to limit what a compromised or misbehaving container can reach on your management, storage or similar networks. Replies to connections started from those networks are allowed.

## Known limitations

- **Forwarded traffic only.** `DOCKER-USER` filters forwarded traffic. A container connecting to the host's own addresses, for example the host's management IP, goes through the `INPUT` chain, which docker-fence does not touch. Protecting the host itself needs host firewall rules. This is a documented non-goal for now.
- **Only `docker0` and `br+` bridges.** The interface matches are `docker0` and `br+`. Docker networks created with a custom bridge name that does not start with `br` are not covered.
- **`DOCKER-USER` is required.** Only the filter table's `DOCKER-USER` chain is used. Docker versions that do not provide it are unsupported.
- **Not a general firewall manager.** docker-fence manages only its own `DOCKER-FENCE` chain and the jump to it. It does not manage other rules, does not read other firewall configuration and does not restore rules lost to other tools; run `reload` for that.
- **Docker only.** Other container runtimes are not supported or promised.
- **Platforms.** Ubuntu Server is the main tested platform. Rocky Linux 9+ is best effort; Rocky 8 is unsupported.
- **Docker stopped with `live-restore`.** With Docker `live-restore: true`, `systemctl stop docker` stops docker-fence too (`PartOf=` and `ExecStop=remove`), so the fence is off while containers keep running, until Docker and docker-fence start again. A Docker package-upgrade restart causes the same, shorter gap.
- **Startup window.** At boot and on every Docker restart, containers with restart policies may start before docker-fence applies: `After=docker.service` orders after Docker starts, not after its containers. There is a short window with no fence.
- **Existing connections are not cut.** Connections already ESTABLISHED before the fence was applied, or opened during such a window, stay up; `apply` does not cut them. To cut them, use conntrack tooling as a manual step, for example `conntrack -D -d <cidr>`.
- **`br+` is broad.** `-i br+` matches every interface whose name starts with `br`, including host bridges that are not Docker's (netplan or KVM `br0`, for example). `DOCKER-USER` sees all forwarded traffic, so new connections routed from such a bridge to a protected network are also rejected.
- **Host, macvlan and ipvlan networks.** Containers using `--network host`, macvlan or ipvlan bypass the forwarding path and are not covered.
- **Root can undo it.** Anyone with root on the host, or a container with the capability to change host firewall rules, can remove the rules.

## Reporting problems

Open an issue on the project's repository.
