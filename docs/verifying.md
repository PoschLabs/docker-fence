# Verifying

## status

```sh
sudo docker-fence status
```

It compares the installed rules with the config file. One line per family:

```text
ipv4: ok
ipv6: ok
```

Possible values per family:

| Output | Meaning |
| --- | --- |
| `ok` | exactly one jump at the top of `DOCKER-USER`, and the fenced networks match the config |
| `skipped (no DOCKER-USER chain)` | IPv6 only: Docker has no IPv6 `DOCKER-USER` chain and the config has no IPv6 networks |
| `missing` | the chain or its jump is not installed (service not started, or Docker has no such chain) |
| `mismatch (...)` | the jump is duplicated or not first, or the networks differ; the text lists extra and missing networks |

The exit status is 0 when every family is `ok` or `skipped`, otherwise 1 (2 for a config error). After editing the config, `mismatch` is expected until you run `systemctl reload docker-fence`.

## Looking at the rules

```sh
sudo iptables -S DOCKER-FENCE
sudo iptables -S DOCKER-USER      # the jump must be the first rule
sudo ip6tables -S DOCKER-FENCE
```

See [how it works](how-it-works.md#chain-layout) for the expected listing.

## A worked test

Suppose `block 192.0.2.0/24` is in the config and the service is running. Pick an address in that range for the test. (If `192.0.2.0/24` is not routed on your host, the connection is still rejected at the firewall first, which is what you are testing.)

With the fence active, a container cannot open a connection:

```sh
sudo docker run --rm busybox nc -w 3 -z -v 192.0.2.10 22
```

It should fail immediately (unreachable), not time out after the 3 second wait. Watch the counters increase:

```sh
sudo iptables -L DOCKER-FENCE -v -n
```

Then compare with the fence off:

```sh
sudo systemctl stop docker-fence
sudo docker run --rm busybox nc -w 3 -z -v 192.0.2.10 22   # now times out (or connects, if the host exists)
sudo systemctl start docker-fence
```

With the fence off the attempt is not rejected: it times out, or connects if such a host exists. Use a network you actually have to test the opposite direction too: a connection from a protected host to a published container port should still work.
