# FreeBSD Porting Guide

This document describes how to produce FreeBSD packages for this project and
prepare a port suitable for submission to the FreeBSD Ports tree (which then
appears on FreshPorts).

## 1) Build a source tarball with embedded UI assets

The application embeds `ui/dist` at build time. Use:

```bash
make release-tarball
```

This creates:

```text
dist/pf-dashboard-<version>-src.tar.gz
```

The tarball includes `ui/dist`, so the port can build the Go binary without
running npm in the ports build environment.

## 2) Port skeleton location

A starter port skeleton is provided at:

```text
packaging/freebsd/ports/security/pf-dashboard/
```

Files:
- `Makefile`
- `pkg-descr`
- `pkg-plist`
- `files/pf_dashboard.in`

Before use, edit `Makefile` values:
- `GH_ACCOUNT`
- `GH_PROJECT`
- `DISTVERSION`

## 3) Local test build with ports tools

From the port directory:

```bash
cd packaging/freebsd/ports/security/pf-dashboard
make makesum
make stage
make package
```

## 4) Test with poudriere (recommended)

Example (adjust names for your environment):

```bash
sudo poudriere ports -c -p local -m null -M /usr/ports
sudo poudriere jail -c -j 14amd64 -v 14.2-RELEASE
sudo poudriere testport -j 14amd64 -p local security/pf-dashboard
```

If using an overlay ports tree, copy `packaging/freebsd/ports/security/pf-dashboard`
into your overlay before running `testport`.

## 5) Submit to FreeBSD Ports

Submit the new port or update through FreeBSD Bugzilla (`Ports & Packages`)
with your patch and `poudriere` results.

After commit to Ports, FreshPorts updates automatically.
