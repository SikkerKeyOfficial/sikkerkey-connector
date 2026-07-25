# SikkerKey Connector

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/sikkerkey-connector)](https://www.npmjs.com/package/sikkerkey-connector)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)

Use the official SikkerKey Connector to give SikkerKey a private connection to services running inside your network.

The connector can:

- Hold an outbound tunnel between one host and SikkerKey.
- Reach the endpoints you name on that tunnel, and only those.
- Run as a systemd unit on Linux or a launchd agent on macOS.
- Reconnect on its own after a network interruption or a restart.
- Verify every request against SikkerKey's public key before opening a connection.

The connector dials out, so the services it reaches stay closed to inbound connections from the internet. It requires Go 1.22 or newer to build and runs as a single binary.

## Install the connector

Copy the install command from the Tunnels page in your SikkerKey dashboard. One command installs the connector, claims the tunnel for this host, and registers the background service.

To install the binary on its own:

```bash
curl -fsSL https://sikkerkey.com/connector.sh | sh
```

Or with npm:

```bash
npm install -g sikkerkey-connector
```

The installer places the binary at `/usr/local/bin/sikkerkey-connector`, verifies it against the checksums published with the release, confirms it runs on this host, and restarts the service if one is already installed. Running it again upgrades in place.

npm installs the binary under the npm prefix instead. `install` copies it to `/usr/local/bin/sikkerkey-connector`, which is where the background service runs it from.

### Install a specific version

```bash
curl -fsSL https://sikkerkey.com/connector.sh | SIKKERKEY_CONNECTOR_VERSION=1.2.3 sh
```

## Connect your first host

```bash
sudo sikkerkey-connector install <install-token>
```

The connector generates an Ed25519 key pair on this host, registers the public half with SikkerKey, writes its configuration to:

```text
~/.sikkerkey/connector/
```

and starts the background service. The tunnel appears as connected on the Tunnels page.

Install tokens are valid for 24 hours and can be used once. One tunnel binds to one host, so a second machine needs its own tunnel and its own token.

## Choose what SikkerKey can reach

A tunnel reaches a target only after you declare it. Add targets on the Tunnels page in your dashboard, giving each one a name, a host, and a port:

```text
prod-postgres    10.0.4.12    5432
```

Features that use the tunnel refer to the target by name and never handle its address. The host and port are resolved on this machine, so a target can point at an internal DNS name, a private address, or loopback.

Removing a target ends its reachability immediately.

## Run as a background service

`install` registers the service and starts it. On Linux:

```bash
sudo systemctl status sikkerkey-connector
sudo journalctl -u sikkerkey-connector -f
```

On macOS:

```bash
tail -f ~/.sikkerkey/connector/connector.log
```

The service runs as the user who invoked the install rather than as root, and starts again after a reboot. If the tunnel drops, the connector retries with a backoff and reports each attempt in its log.

To run the tunnel in the foreground instead, under your own supervisor:

```bash
sikkerkey-connector run
```

## Inspect the tunnel

```bash
sikkerkey-connector status
```

This prints the tunnel's identity and configuration as stored on this host.

## Remove the connector

```bash
sudo sikkerkey-connector uninstall
```

This stops and removes the background service and leaves the identity in place, so the tunnel can be started again without a new token. To retire the tunnel entirely, delete it on the Tunnels page.

## How each side is authenticated

Both directions are authenticated, and each side generates the key it signs with:

| Direction | Key | Location of the private half |
|---|---|---|
| This host proves its identity | Connector Ed25519 key pair | Stays on this host |
| SikkerKey proves a request | Per-tunnel Ed25519 key pair | Stays with SikkerKey |

Enrollment sends only the connector's public key, so this tunnel's identity cannot be produced anywhere else, including by us. The connector pins SikkerKey's public key for this tunnel and checks every request against it.

Each request to open a connection is signed over the target, a timestamp, and a nonce. The connector rejects a signature that fails verification, a timestamp outside a five minute window, a nonce it has already seen, and any target that is not declared on this tunnel.

## Command reference

| What you want to do | Command |
|---|---|
| Claim a tunnel for this host and run it | `install <token>` |
| Set up the service for an already-enrolled host | `install` |
| Stop and remove the background service | `uninstall` |
| Hold the tunnel open in the foreground | `run` |
| Show this host's tunnel configuration | `status` |
| Print the version | `version` |

## Runtime footprint

A single binary with no runtime dependencies. The connector holds one outbound connection while it is running, and keeps its configuration and private key at:

```text
~/.sikkerkey/connector/
```

### Use a different identity directory

```bash
export SIKKERKEY_HOME=/var/lib/sikkerkey
```

The connector will then use:

```text
/var/lib/sikkerkey/connector/
```

## Supported platforms

Linux and macOS, on x86-64 and arm64.

## Documentation

- [SikkerKey documentation](https://docs.sikkerkey.com)
- [Machine authentication](https://docs.sikkerkey.com/docs/machines/signatures)

## License

The SikkerKey Connector is available under the [MIT License](LICENSE).
