# Installation

docker-fence is shipped as `.deb` and `.rpm` packages for x86_64 and aarch64. The package depends on `iptables` and installs:

| Path | Purpose |
| --- | --- |
| `/usr/bin/docker-fence` | the binary |
| `/usr/lib/systemd/system/docker-fence.service` | the systemd unit |
| `/etc/docker-fence/docker-fence.conf` | the configuration (see [configuration](configuration.md)) |

## Installing from a package repository

The URLs below are placeholders. Use the repository address published by whoever builds your packages (see [releasing](releasing.md) if that is you).

### Ubuntu (apt)

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://packages.example.org/keys/repository.gpg | sudo tee /etc/apt/keyrings/docker-fence.asc >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/docker-fence.asc] https://packages.example.org/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/docker-fence.list
sudo apt update
sudo apt install docker-fence
```

### Rocky Linux (yum/dnf)

```ini
# /etc/yum.repos.d/docker-fence.repo
[docker-fence]
name=docker-fence
baseurl=https://packages.example.org/yum/
enabled=1
gpgcheck=1
gpgkey=https://packages.example.org/keys/repository.gpg
```

```sh
sudo dnf install docker-fence
```

## Installing a package file manually

Download the `.deb` or `.rpm` from the project's release page, then:

```sh
sudo apt install ./docker-fence_<version>_amd64.deb
# or
sudo dnf install ./docker-fence-<version>-1.x86_64.rpm
```

## The service is installed disabled

Installing the package only reloads systemd so it sees the unit. It does not enable or start it. This is deliberate: until you have written your config and enabled the service, nothing is blocked and nothing in your firewall changes.

```sh
sudoedit /etc/docker-fence/docker-fence.conf
sudo systemctl enable --now docker-fence
sudo docker-fence status
```

The unit requires and starts after `docker.service`, and is restarted when Docker restarts (`PartOf=`). See [how it works](how-it-works.md#lifecycle).

## Upgrading

Upgrading replaces the binary and unit. Your edited `/etc/docker-fence/docker-fence.conf` is preserved (it is marked as a config file that is not replaced). The service is not stopped by the upgrade, so the rules stay in place. Run `sudo systemctl reload docker-fence` if you want the new binary to reconcile the rules.

## Removing

```sh
sudo apt remove docker-fence      # or: sudo dnf remove docker-fence
```

Removal stops and disables the service. Stopping runs `docker-fence remove`, which deletes the jump from `DOCKER-USER` and the `DOCKER-FENCE` chain, so no rules are left behind. Rules not created by docker-fence are not touched. Your config file is kept by the package manager's usual rules (on Debian-based systems, `apt purge` removes it).
