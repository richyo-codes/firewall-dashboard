# Firewall Dashboard

Firewall Dashboard is a Go web application with an embedded Svelte frontend for
viewing firewall traffic, rule counters, and authentication state.

The primary focus is the FreeBSD/OpenBSD PF backend.

The Linux `nftables` backend is currently a learning exercise / experiment and
is not the primary target.

## Overview

- Single Go binary with embedded frontend assets
- PF-focused traffic, unified view, and rule counters
- Optional OIDC authentication
- FreeBSD `rc.d` and Linux `systemd` packaging support

## Project Layout

- `main.go` - Go HTTP server, API handlers, and embedded static assets
- `internal/` - firewall providers, auth, and configuration
- `ui/` - Svelte + Tailwind frontend bundled with Vite
- `packaging/` - service files and packaging assets

## Getting Started

Prerequisites:

- Go 1.21+
- Node.js 18+

Build and run:

```bash
cd ui
npm install
npm run build

cd ..
go build -buildvcs=false -o pf-dashboard .
./pf-dashboard
```

The app runs on `http://localhost:8080` by default.

During frontend development, Vite can proxy `/api` back to the Go server:

```bash
cd ui
npm run dev
```

The frontend build emits assets into `ui/dist`, which are embedded into the Go
binary on the next Go build.

### Using Make

Common tasks are wrapped in the top-level `Makefile`:

```bash
make build       # builds UI assets and Go binary
make test        # runs go test ./...
make run         # builds and launches ./pf-dashboard
make docker-test # runs go test inside the Docker test stage
make build-freebsd # cross-compiles CGO-disabled FreeBSD amd64 binary
```

### Configuration

Configuration uses [koanf](https://github.com/knadh/koanf) with CLI flags and
environment variables (`PFCTL_DASHBOARD_` prefix). Examples:

Default backend selection is OS-aware:

- FreeBSD/OpenBSD: `pf`
- Other platforms: `mock`

```bash
# run with explicit backend on 0.0.0.0:8081
./pf-dashboard --server.addr=0.0.0.0:8081

# switch to nftables backend via env variable
PFCTL_DASHBOARD_FIREWALL_BACKEND=nftables ./pf-dashboard

# enable verbose firewall command logging (PF/nftables)
./pf-dashboard --firewall.debug

# change client auto-refresh interval (ms)
./pf-dashboard --server.refresh.traffic_interval_ms=1000
```

OIDC settings are intended to be configured via environment variables.
`auth.oidc.*` CLI flags remain supported for compatibility but are hidden from
`--help` to keep the CLI surface smaller.

Supported backends:

- `mock` – in-memory test data.
- `pf` – FreeBSD/OpenBSD PF integration (requires a FreeBSD or OpenBSD build).
- `nftables` – Linux nftables integration (requires a Linux build).

When an unsupported provider is requested (e.g., `pf` on Linux), the server
exits at startup with an error.

### Shell Completion

Generate completions from the binary:

```bash
# bash
./pf-dashboard completion bash > /etc/bash_completion.d/pf-dashboard

# zsh
./pf-dashboard completion zsh > "${fpath[1]}/_pf-dashboard"

# fish
./pf-dashboard completion fish > ~/.config/fish/completions/pf-dashboard.fish
```

### API Spec

An OpenAPI 3.0 spec for the current HTTP API is available at `openapi.yaml`.

### Authentication

Supported authentication modes:

- `none` (default) – assume an upstream reverse proxy handles auth. All API
  requests are accepted. `/api/auth/me` reports `authenticated: true` without a
  user payload.
- `oidc` – use OpenID Connect with the authorization-code flow. Required
  settings: `auth.oidc.provider_url`, `auth.oidc.client_id`,
  `auth.oidc.client_secret`, and `auth.oidc.redirect_url`. Optional settings
  include `auth.oidc.scopes`, `auth.oidc.cookie_name`,
  `auth.oidc.cookie_secure`, and `auth.oidc.cookie_domain`.

Example configuration via environment variables:

```bash
PFCTL_DASHBOARD_AUTH_MODE=oidc \
PFCTL_DASHBOARD_AUTH_OIDC_PROVIDER_URL=https://id.example.com/realms/main \
PFCTL_DASHBOARD_AUTH_OIDC_CLIENT_ID=pf-dashboard \
PFCTL_DASHBOARD_AUTH_OIDC_CLIENT_SECRET=<secret> \
PFCTL_DASHBOARD_AUTH_OIDC_REDIRECT_URL=https://dashboard.example.com/auth/callback \
./pf-dashboard
```

OIDC mode adds these routes:

- `GET /auth/login` – redirect users to the identity provider.
- `GET /auth/callback` – handles the redirect URI.
- `POST /auth/logout` (also accepts `GET`) – clears session cookies.
- `GET /api/auth/me` – returns authentication status and user info.
- `GET /api/config/refresh` – returns polling interval hints for the SPA.
- `GET /api/stream/traffic?action=block|pass|rdr` – live tcpdump stream (PF only).

## Least-Privilege Setup

### Linux (nftables)

```bash
sudo apt install libcap2-bin
sudo setcap 'cap_net_admin,cap_net_raw+ep' /path/to/pf-dashboard
```

**systemd**: set `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` and `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`.

Remove capabilities: `sudo setcap -r /path/to/pf-dashboard`.

### FreeBSD (PF)

Adjust `/etc/devfs.conf`:

```
perm pf 0660
perm bpf* 0660
own pf root:pf
own bpf* root:pf
```

Add the service user to group `pf`, then `service devfs restart`.

### HTTP Logging

Enable verbose request logging with:

```bash
./pf-dashboard --server.http_log
```

Each request is logged with method, path, status, byte count, duration, and
remote address (respecting `X-Forwarded-For` / `X-Real-IP` headers).

### Platform Notes

- **FreeBSD / PF**: Requires `pfctl` and `tcpdump` with permission to read
  `/var/log/pflog` and query PF state (`pfctl -s state`). The provider parses
  actual PF rule counters, states, and recent pflog entries.
  If either executable is missing from `PATH`, startup fails with an error.
  Cross-compile from a Linux/macOS dev box with `make build-freebsd`
  (`GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0`).
- **Linux / nftables**: Requires `nft` and `conntrack` binaries. Rule counters
  are read via `nft list ruleset -j`, and active flows via
  `conntrack -L -o json`. If either executable is missing from `PATH`, startup
  fails with an error. Feature coverage is intentionally behind PF.

## Packaging & Services

### GoReleaser + NFPM

The repo ships with `.goreleaser.yaml`, which cross-compiles the dashboard,
creates tarballs, and builds Debian/RPM packages via NFPM (systemd unit and
config file included). Run snapshot builds locally:

```bash
goreleaser release --snapshot --clean
```

Packaging artifacts land in `dist/`. Each `.deb`/`.rpm`:

- installs the binary to `/usr/bin/pf-dashboard`
- drops a sample env file at `/etc/default/pf-dashboard`
- installs a systemd unit (`pf-dashboard.service`)
- creates the `pf-dashboard` user/group via pre-install script

Install + enable on a systemd host:

```bash
sudo dpkg -i dist/pf-dashboard_*_amd64.deb # or rpm -i ...
sudo systemctl daemon-reload
sudo systemctl enable --now pf-dashboard
```

Edit `/etc/default/pf-dashboard` (or `/etc/sysconfig/pf-dashboard`) to set
`PFCTL_DASHBOARD_*` overrides before restarting the service.

### FreeBSD rc.d Script

`packaging/freebsd/rc.d/pf_dashboard` is a ready-to-use `rc.d` helper. Install
and enable it on FreeBSD hosts:

```bash
sudo install -m 0555 packaging/freebsd/rc.d/pf_dashboard /usr/local/etc/rc.d/pf_dashboard
sudo sysrc pf_dashboard_enable=YES
sudo service pf_dashboard start
```

Tunables:

- `pf_dashboard_command` – defaults to `/usr/local/sbin/pf-dashboard`
- `pf_dashboard_flags` – pass CLI flags (e.g., `--firewall.backend=pf`)
- `pf_dashboard_env` – space-separated `KEY=value` pairs exported before the
  daemon starts
- `pf_dashboard_user` / `pf_dashboard_group` – service account (default
  `pf-dashboard`)
- `packaging/freebsd/rc.conf.sample` provides a starting `rc.conf` snippet.

### Linux systemd Unit

Packaging includes:

- `packaging/systemd/pf-dashboard.service`
- `packaging/config/pf-dashboard.env`

The unit reads optional flags/env from `/etc/default/pf-dashboard` and
`/etc/sysconfig/pf-dashboard`.

### FreeBSD Ports Packaging

For a local ports skeleton and `poudriere` workflow, see `docs/freebsd-porting.md`.
