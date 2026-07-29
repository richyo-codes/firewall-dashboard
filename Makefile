# Compatibility shim. The justfile is the build and release source of truth.
BINARY ?= pf-dashboard
VERSION ?= dev
DIST_DIR ?= dist
GOFLAGS ?= -buildvcs=false

export BINARY VERSION DIST_DIR GOFLAGS

.PHONY: all build run test clean tidy ui-install ui-build screenshots docker-test docker-build
.PHONY: build-linux build-freebsd release-tarball

all: build

build run test clean tidy ui-install ui-build screenshots docker-test docker-build:
	@just $@

build-linux build-freebsd release-tarball:
	@just $@
