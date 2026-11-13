# Configuration

The config file is `/etc/docker-fence/docker-fence.conf`. It lists the networks that containers must not open new connections to.

## Format

One entry per line, in the form `block <network>` or `allow <network>`:

- `block` stops containers from opening new connections to the network.
- `allow` is an exception: containers may still reach that network. It only has an effect inside a larger `block`.
- A network is a CIDR, such as `192.0.2.0/24`, or a single host, such as `192.0.2.10` or `2001:db8::5` (the same as `/32` or `/128`).
- The keywords are lowercase. An entry without one is an error.
- IPv4 and IPv6 may be mixed in the same file.
- Blank lines and surrounding whitespace are ignored.
- `#` starts a comment, on its own line or after an entry.

```text
# management network, except the jump host
block 192.0.2.0/24
allow 192.0.2.10/32

# storage network (IPv6)
block 2001:db8:10::/64   # trailing comment
```

All examples in this documentation use the reserved documentation ranges `192.0.2.0/24` and `2001:db8:10::/64`. Replace them with your own networks.

## Details

- When entries overlap, the most specific one (longest prefix) wins. With the example above, `192.0.2.10` is reachable and the rest of `192.0.2.0/24` is not. Entries with the same prefix length keep their order in the file.
- Replies on connections started from a listed network are always allowed, whatever the entries say.
- Host bits are normalised: `block 192.0.2.5/24` becomes `block 192.0.2.0/24`.
- Exact duplicates (same action and network after normalisation) are merged into one.
- Listing the same network as both `block` and `allow` is an error. The message names both lines.
- An `allow` that is not inside any `block` has no effect. docker-fence reports `allow <network> has no effect: it is not an exception to a block` and continues.
- An empty file, one with only comments, or one with only `allow` entries is valid. docker-fence reports `no block entries configured; nothing is blocked` and installs a chain that blocks nothing.
- The package ships a sample file with every example commented out, so the default config blocks nothing.

## Errors

Any invalid line stops the whole run, so a typo never leads to a partly applied rule set. The error has the form `<path>:<line>: <message>`:

```text
docker-fence: /etc/docker-fence/docker-fence.conf:2: missing action before "192.0.2.0/24" (write `block 192.0.2.0/24` or `allow 192.0.2.0/24`)
```

An unreadable or missing file is reported as `<path>: cannot read config: ...`. Configuration errors exit with status 2.

## Applying changes

```sh
sudo systemctl reload docker-fence
```

Always use `reload` after editing the config, not `restart` or stop and start. Reload keeps the old rules when the new config is invalid, whereas stop removes the rules first and the following start then fails on a typo, leaving nothing blocked.

Reload re-reads the file and replaces the rules in a single transaction per address family. If the file is invalid the reload fails and the previous rules stay in place. See [how it works](how-it-works.md#failure-handling).

To check a file without changing any rules, point `status` at it: `docker-fence --config /path/to/file status` (it reports config errors with exit status 2 and compares the installed rules with that file).
