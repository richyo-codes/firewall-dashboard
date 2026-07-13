# Firewall Dashboard

Firewall Dashboard is a single-binary web application for inspecting firewall
traffic, rule counters, and authentication state. It embeds a Svelte frontend
in a Go server and exposes a small HTTP API for operational diagnostics.

PF on FreeBSD and OpenBSD is the primary deployment target. Linux nftables is
supported as an experimental backend and has less feature coverage.

## Highlights

- Embedded web UI and JSON API in one Go binary
- PF traffic, state, and rule-counter visibility on FreeBSD and OpenBSD
- nftables rule and connection inspection on Linux
- Optional OpenID Connect authentication
- Native FreeBSD and cross-platform CI builds
- Linux systemd, FreeBSD rc.d, and FreeBSD Ports packaging assets

## Requirements

- Go 1.25+
- Node.js 20.19+ or 22.12+
- `npm`
- GNU Make

Runtime dependencies depend on the selected backend:

| Platform | Backend | Required commands |
| --- | --- | --- |
| FreeBSD / OpenBSD | `pf` | `pfctl`, `tcpdump` |
| Linux | `nftables` | `nft`, `conntrack` |
| Any | `mock` | None |

## Quick Start

Build the UI and server from the repository root:

```bash
make build
./pf-dashboard
```

Open `http://localhost:8080`.

`make build` runs the frontend build and embeds `ui/dist` into the binary. For
frontend-only development, start Vite separately:

```bash
cd ui
npm ci
npm run dev
```

The Vite development server proxies `/api` requests to the Go server.

## Common Commands

```bash
make build           # build the UI and application binary
make test            # build the UI and run Go tests
make run             # build and start the application
make build-linux     # cross-compile a Linux amd64 binary
make build-freebsd   # cross-compile a FreeBSD amd64 binary
make release-tarball # create a source tarball with embedded UI assets
make docker-test     # run tests in the Docker test stage
make docker-build    # build the release Docker image
```

## Configuration

Configuration precedence is defaults, environment variables, then command-line
flags. Environment variables use the `PFCTL_DASHBOARD_` prefix; nested keys use
underscores, for example `PFCTL_DASHBOARD_SERVER_ADDR` maps to
`server.addr`.

Defaults are OS-aware:

| Operating system | Default backend |
| --- | --- |
| FreeBSD / OpenBSD | `pf` |
| Other platforms | `mock` |

Supported backends:

| Backend | Purpose |
| --- | --- |
| `pf` | FreeBSD and OpenBSD PF integration |
| `nftables` | Linux nftables integration |
| `mock` | In-memory data for local development and testing |

The application exits during startup when a selected backend is unavailable on
the current platform or its required commands are absent.

```bash
# Bind to all interfaces on port 8081.
./pf-dashboard --server.addr=0.0.0.0:8081

# Use the Linux nftables backend.
PFCTL_DASHBOARD_FIREWALL_BACKEND=nftables ./pf-dashboard

# Enable detailed firewall command logging.
./pf-dashboard --firewall.debug

# Change the client traffic refresh interval.
./pf-dashboard --server.refresh.traffic_interval_ms=1000

# Enable HTTP request logging.
./pf-dashboard --server.http_log
```

## Authentication

Authentication defaults to `none`, which assumes an upstream reverse proxy
controls access. Do not expose an unauthenticated instance directly to an
untrusted network.

Set `auth.mode` to `oidc` to use the OpenID Connect authorization-code flow.
OIDC configuration is best supplied through environment variables:

```bash
PFCTL_DASHBOARD_AUTH_MODE=oidc \
PFCTL_DASHBOARD_AUTH_OIDC_PROVIDER_URL=https://id.example.com/realms/main \
PFCTL_DASHBOARD_AUTH_OIDC_CLIENT_ID=pf-dashboard \
PFCTL_DASHBOARD_AUTH_OIDC_CLIENT_SECRET=replace-me \
PFCTL_DASHBOARD_AUTH_OIDC_REDIRECT_URL=https://dashboard.example.com/auth/callback \
./pf-dashboard
```

The required OIDC settings are the provider URL, client ID, client secret, and
redirect URL. Optional settings include scopes and session-cookie controls.

When OIDC is enabled, the application provides `/auth/login`, `/auth/callback`,
and `/auth/logout`. Authentication status is available at `/api/auth/me`.

## Permissions and Platform Setup

The process needs permission to query the firewall and read traffic data. Grant
only the capabilities or device access required by the selected backend.

### Linux nftables

```bash
sudo apt install libcap2-bin
sudo setcap 'cap_net_admin,cap_net_raw+ep' /path/to/pf-dashboard
```

For systemd deployments, configure `AmbientCapabilities=CAP_NET_ADMIN
CAP_NET_RAW` and `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`. Remove
capabilities with `sudo setcap -r /path/to/pf-dashboard`.

### FreeBSD PF

Configure access to PF and BPF devices in `/etc/devfs.conf`:

```text
perm pf 0660
perm bpf* 0660
own pf root:pf
own bpf* root:pf
```

Add the service account to the `pf` group, then apply the configuration with
`service devfs restart`.

## Deployment and Packaging

### Linux packages

GoReleaser builds archives and Debian/RPM packages using the project’s systemd
unit and sample environment file:

```bash
goreleaser release --snapshot --clean
```

Packages install the binary at `/usr/bin/pf-dashboard`, the service unit, and a
sample environment file at `/etc/default/pf-dashboard`. After installation:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pf-dashboard
```

Set deployment-specific configuration in `/etc/default/pf-dashboard` or
`/etc/sysconfig/pf-dashboard`, then restart the service.

### FreeBSD rc.d

Install the supplied rc.d script and enable the service:

```bash
sudo install -m 0555 packaging/freebsd/rc.d/pf_dashboard /usr/local/etc/rc.d/pf_dashboard
sudo sysrc pf_dashboard_enable=YES
sudo service pf_dashboard start
```

Use [packaging/freebsd/rc.conf.sample](packaging/freebsd/rc.conf.sample) as a
starting point for service settings. The rc.d script supports command, flags,
environment, user, and group overrides through `pf_dashboard_*` variables.

### FreeBSD Ports

A local port skeleton and `poudriere` workflow are documented in
[docs/freebsd-porting.md](docs/freebsd-porting.md).

## API and Shell Completion

The HTTP API is documented in [openapi.yaml](openapi.yaml). Key endpoints
include traffic (`/api/blocked`, `/api/passed`, `/api/traffic`), rule counters
(`/api/rules`), refresh configuration (`/api/config/refresh`), and the PF live
traffic stream (`/api/stream/traffic`).

Generate a shell completion script from the built binary:

```bash
./pf-dashboard completion bash > /etc/bash_completion.d/pf-dashboard
./pf-dashboard completion zsh > "${fpath[1]}/_pf-dashboard"
./pf-dashboard completion fish > ~/.config/fish/completions/pf-dashboard.fish
```
