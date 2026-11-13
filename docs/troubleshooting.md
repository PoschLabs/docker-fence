# Troubleshooting

## Reading the log

docker-fence prints messages to stderr prefixed with `docker-fence:`; systemd captures them.

```sh
sudo systemctl status docker-fence
sudo journalctl -u docker-fence -e
```

The last lines before a failure state the cause.

## Docker not running, or no DOCKER-USER chain

```text
docker-fence: iptables chain DOCKER-USER not found; is Docker running? (nothing was changed)
```

Start Docker (`sudo systemctl start docker`) and then docker-fence. Docker creates `DOCKER-USER` when it starts. Very old Docker versions do not have the chain and are unsupported. Note that Docker with `"iptables": false` in its daemon config does not manage firewall rules at all, so the chain will not exist.

## iptables is missing

The package depends on `iptables`. If the `iptables` or `iptables-restore` command cannot be run, docker-fence exits with status 1 and prints the error. Install the `iptables` package. On current distributions `iptables` is the nftables-backed compatibility command; that is expected and works.

## The IPv6 notice

```text
docker-fence: ip6tables chain DOCKER-USER not found; skipping IPv6
```

Docker has no IPv6 `DOCKER-USER` chain (IPv6 is not enabled in Docker). This is harmless when your config has no IPv6 networks. If it does, you get a stronger warning, `IPv6 subnets in the config are NOT blocked`. Either enable IPv6 in Docker, or remove the IPv6 lines to silence it. Containers without IPv6 cannot reach IPv6 networks anyway, but do not rely on that if you change Docker's settings later.

The same notice (with `unavailable (...)` and the error text) appears when `ip6tables` cannot list the chain and the kernel has IPv6 disabled. If instead the kernel has IPv6 and your config has IPv6 networks, an `ip6tables` listing error is not tolerated: the IPv4 rules are installed and `apply` exits with status 1 (see Partially applied).

## Rocky Linux and firewalld

On Rocky, the host usually runs firewalld, and Docker with firewalld can interact with rules inserted directly by other tools: firewalld reloads or Docker restarts can reorder or flush chains. docker-fence uses plain `iptables` commands against `DOCKER-USER` and does not talk to firewalld. This works in testing but is best effort and less tested than Ubuntu. After any firewalld reload, run `sudo docker-fence status`; if it reports `missing` or `mismatch`, run `sudo systemctl reload docker-fence`. Rocky 8 is not supported.

## The unit failed after a bad config

```sh
sudo journalctl -u docker-fence -e
```

Look for a line like `docker-fence: /etc/docker-fence/docker-fence.conf:3: invalid network "..."` (or `missing action`, `unknown action`). Fix that line and run:

```sh
sudo systemctl restart docker-fence
```

If the failure happened on a reload, the previous rules are still active; a plain `systemctl reload docker-fence` after the fix is enough. `systemctl reload` on a failed unit may need `restart` instead.

## Partially applied

`partially applied: iptables rules were installed but ip6tables failed: ...` means IPv4 is in effect and IPv6 is not. This includes `ip6tables` failing to list `DOCKER-USER` on a host with IPv6 enabled and IPv6 networks in the config (for example a lock timeout or a missing `ip6tables` binary). Fix the cause shown after the colon and reload.

## status shows mismatch

Someone changed `DOCKER-USER` or the config changed after the last apply. `sudo systemctl reload docker-fence` reconciles it.
