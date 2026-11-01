# Configuration

The config file is `/etc/docker-fence/docker-fence.conf`. It lists the networks that containers must not open new connections to.

## Format

- One network per line, in CIDR notation.
- IPv4 and IPv6 may be mixed in the same file.
- Blank lines are ignored.
- `#` starts a comment, on its own line or after an entry.

```text
# management network
192.0.2.0/24

# storage network (IPv6)
2001:db8:10::/64   # trailing comment
```

All examples in this documentation use the reserved documentation ranges `192.0.2.0/24` and `2001:db8:10::/64`. Replace them with your own networks.

## Details

- Host bits are normalised: `192.0.2.5/24` becomes `192.0.2.0/24`.
- Exact duplicates (after normalisation) are merged into one.
- A bare address without a prefix length, such as `192.0.2.5`, is rejected. Write `192.0.2.5/32` for a single host.
- An empty file, or one with only comments, is valid. docker-fence logs `no subnets configured; nothing is blocked` and installs a chain that blocks nothing.
- The package ships a sample file with every example commented out, so the default config blocks nothing.

## Errors

Any invalid line stops the whole run, so a typo never leads to a partly applied rule set. The error has the form `<path>:<line>: <message>`:

```text
docker-fence: /etc/docker-fence/docker-fence.conf:2: invalid CIDR "192.0.2.5" (expected e.g. 192.0.2.0/24)
```

An unreadable or missing file is reported as `<path>: cannot read config: ...`. Configuration errors exit with status 2.

## Applying changes

```sh
sudo systemctl reload docker-fence
```

Always use `reload` after editing the config, not `restart` or stop and start. Reload keeps the old rules when the new config is invalid, whereas stop removes the rules first and the following start then fails on a typo, leaving nothing blocked.

Reload re-reads the file and replaces the rules in a single transaction per address family. If the file is invalid the reload fails and the previous rules stay in place. See [how it works](how-it-works.md#failure-handling).

To check a file without changing any rules, point `status` at it: `docker-fence --config /path/to/file status` (it reports config errors with exit status 2 and compares the installed rules with that file).
