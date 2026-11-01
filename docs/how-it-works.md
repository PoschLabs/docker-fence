# How it works

## Chain layout

For each address family (`iptables` and `ip6tables`) docker-fence creates one chain, `DOCKER-FENCE`, and one jump to it from `DOCKER-USER`. For a config containing `192.0.2.0/24`, `iptables -S DOCKER-FENCE` shows:

```text
-N DOCKER-FENCE
-A DOCKER-FENCE -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-FENCE -i docker0 -d 192.0.2.0/24 -j REJECT --reject-with icmp-port-unreachable
-A DOCKER-FENCE -i br+ -d 192.0.2.0/24 -j REJECT --reject-with icmp-port-unreachable
```

and `iptables -S DOCKER-USER` begins with the jump:

```text
-N DOCKER-USER
-A DOCKER-USER -j DOCKER-FENCE
-A DOCKER-USER -j RETURN
```

(The exact spelling of the output depends on your iptables version. The IPv6 chain looks the same, using `ip6tables`, with `icmp6-port-unreachable`.)

Rule order in `DOCKER-FENCE`:

1. Packets of established or related connections return immediately.
2. For each configured network, traffic arriving from `docker0` or from any bridge matching `br+` and destined to that network is rejected.

## Why the jump is at the top of DOCKER-USER

Docker's default `DOCKER-USER` chain contains a single `-j RETURN`. Rules appended after it are never reached. docker-fence therefore inserts its jump as rule 1 (`-I DOCKER-USER 1`). If the jump is later found displaced or duplicated, the next `apply` removes the extras and re-inserts one at the top. Rules in `DOCKER-USER` that docker-fence did not create are never modified.

## Why only new connections are blocked

The first rule in `DOCKER-FENCE` lets packets of established and related connections through. A connection started from a protected network to a published container port is established, so the container's replies go out (they leave through a bridge, destined to the protected network, and would otherwise match the reject rules). A connection started by a container towards a protected network is new, so it is rejected.

## Atomic reload

Each family is applied with one `iptables-restore --noflush` transaction that declares and refills `DOCKER-FENCE` and, if needed, fixes the jump. The kernel swaps the new rules in at commit, so there is no moment during a reload where the old rules are gone and the new ones are not yet present. The script never declares `DOCKER-USER`, because declaring an existing chain would flush Docker's own rules.

IPv4 is applied first, then IPv6. The two families are separate transactions.

## Lifecycle

- **start** (`systemctl start`/`enable --now`): runs `docker-fence apply`. The unit is `Type=oneshot` with `RemainAfterExit=yes`, so it shows as active once the rules are in.
- **reload** (`systemctl reload`): runs `docker-fence apply` again, which reconciles the rules with the current config.
- **stop**: runs `docker-fence remove`, which deletes the jump and the chain in each family. Nothing is left behind.
- **Docker restart**: the unit has `Requires=`, `After=` and `PartOf=docker.service`, so stopping or restarting Docker stops or restarts docker-fence too, and the rules are installed again after Docker is back. If Docker is not running, the unit cannot start.

Limits of the lifecycle (see the [threat model](threat-model.md)):

- With `live-restore: true`, stopping Docker stops docker-fence, so the fence is off while containers keep running until both start again.
- At boot and on Docker restarts, containers with restart policies may start before docker-fence applies; `After=docker.service` does not wait for containers.
- `apply` does not cut connections that were already established; use `conntrack -D -d <cidr>` manually if needed.

## Failure handling

- **Invalid config on start:** `apply` exits with status 2 before touching any rule; the unit fails and no rules are installed.
- **Invalid config on reload:** the reload fails and the previously installed rules keep running. Fix the file and reload again.
- **IPv6:** if Docker has no IPv6 `DOCKER-USER` chain (IPv6 not enabled in Docker), or `ip6tables` cannot be used at all (for example `ipv6.disable=1`; the notice includes the error), the IPv6 part is skipped with a notice. If the config contains IPv6 networks the notice is stronger: `WARNING: ip6tables chain DOCKER-USER not found; IPv6 subnets in the config are NOT blocked`.
- **No IPv4 `DOCKER-USER`:** `iptables chain DOCKER-USER not found; is Docker running? (nothing was changed)`, exit status 1.
- **Partial apply:** if IPv4 was installed but IPv6 failed, the error reads `partially applied: iptables rules were installed but ip6tables failed: ...` (exit status 1). The IPv4 rules stay in place; fix the cause and reload.

Exit codes: 0 success, 1 runtime or firewall error (and `status` when something is not as configured), 2 usage or config error.
