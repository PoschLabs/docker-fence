# Releasing

This page is for maintainers of a fork or a new repository. Users do not need it.

## How a release is triggered

Bump `version` in `Cargo.toml` first, commit it, then push a tag that starts with `v` and equals `v<version>`. The `test` job fails the release if the tag version and `Cargo.toml` differ, so the binary and the packages never carry a stale version.

For example, for version 1.2.3:

```sh
git tag v1.2.3
git push origin v1.2.3
```

The release workflow (`.github/workflows/release.yaml`) then runs these jobs in order:

1. `test`: checks that the tag version matches the `version` in `Cargo.toml`, then runs `cargo test`.
2. `build`: GoReleaser builds the x86_64 and aarch64 musl binaries and the `.deb` and `.rpm` packages (unsigned) and uploads them as a workflow artifact.
3. `sign-release`: signs the RPM packages (not the `.deb` files) using a signing service, creates the GitHub release and attaches the packages. Runs on a self-hosted runner.
4. `publish-packages`: uploads the signed packages to the apt and yum repositories. Runs on a self-hosted runner in a container.

## Repository variables

Set these under Settings, Secrets and variables, Actions, Variables. Values below are placeholders.

| Variable | Used by | Meaning | Example |
| --- | --- | --- | --- |
| `SIGNING_URL` | sign-release | address of the secrets/signing server | `https://signing.example.org` |
| `SIGNING_ROLE` | sign-release | role the workflow logs in as | `docker-fence-release` |
| `SIGNING_AUTH_PATH` | sign-release | auth method mount path on the signing server | `jwt` |
| `SIGNING_OIDC_AUDIENCE` | sign-release | audience requested for the workflow's OIDC token | `https://signing.example.org` |
| `SIGNING_SECRET_PATH` | sign-release | path of the signing key secret | `secret/data/docker-fence/signing` |
| `PACKAGES_URL` | publish-packages | base URL of the package repository manager | `https://packages.example.org` |
| `APT_REPOSITORY` | publish-packages | name of the apt repository to upload `.deb` files to | `apt-docker-fence` |
| `YUM_REPOSITORY` | publish-packages | name of the yum repository to upload `.rpm` files to | `yum-docker-fence` |

The meanings of the signing variables depend on the maintainer's signing setup. Confirm them against the documentation of the signing action used in the workflow before relying on the descriptions above.

## Secrets

| Secret | Meaning |
| --- | --- |
| `PACKAGES_USERNAME` | user with upload rights on the package repository |
| `PACKAGES_PASSWORD` | that user's password |

## Signing role

The signing job requests an OIDC token (`id-token: write`), authenticates to the signing server with `SIGNING_ROLE`, and signs the RPMs with the key stored at `SIGNING_SECRET_PATH`. Configure the role on the signing server to accept tokens only from your repository and only for tag refs, and give it read access to nothing but that key. The public key must be published at your package repository so clients can verify packages (see [install](install.md)).

## Self-hosted runners

`sign-release` and `publish-packages` use `runs-on: self-hosted`, because they need network access to the signing server and package repository. You must register a runner for the repository (or organisation) that can reach those services; the publish job runs in a container, so the runner needs Docker.

Warning: never run untrusted pull-request code on self-hosted runners. A pull request from a fork could execute arbitrary commands on the runner and reach the internal services it can see. These two jobs run only on tag pushes, which only people with write access can create. Do not add pull-request triggers to this workflow, and in the repository settings require approval for workflows from outside contributors. The lint and test workflow (`ci.yaml`) is the place for pull-request checks.
