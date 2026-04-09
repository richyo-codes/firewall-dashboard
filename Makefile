SHELL = /bin/sh

BINARY ?= pf-dashboard
UI_DIR = ui
VERSION ?= dev
DIST_DIR = dist
GOFLAGS ?= -buildvcs=false

.PHONY: all build run test clean tidy ui-install ui-build docker-test docker-build
.PHONY: build-linux build-freebsd release-tarball

all: build

build: ui-build
	go build $(GOFLAGS) -o $(BINARY) .

build-linux: ui-build
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -o $(BINARY)-linux-amd64 .

build-freebsd: ui-build
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -o $(BINARY)-freebsd-amd64 .

release-tarball: ui-build
	@version="$(VERSION)"; \
	if [ "$$version" = "dev" ]; then \
		desc=$$(git describe --tags --dirty --always --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true); \
		if echo "$$desc" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+'; then \
			version=$$(echo "$$desc" | sed -E 's/^v//; s/-([0-9]+)-g([0-9a-f]+)/-\1.g\2/; s/-dirty/.dirty/'); \
		elif [ -n "$$desc" ]; then \
			sanitized=$$(printf '%s' "$$desc" | sed -E 's/[^0-9A-Za-z.+-]+/-/g'); \
			version="0.0.0-dev+$$sanitized"; \
		else \
			version="0.0.0-dev+$$(date +%Y%m%d)"; \
		fi; \
	fi; \
	release_src_dir="$(DIST_DIR)/release-src-$$version"; \
	release_tarball="$(DIST_DIR)/$(BINARY)-$$version-src.tar.gz"; \
	rm -rf "$$release_src_dir"; \
	mkdir -p "$$release_src_dir" "$(DIST_DIR)"; \
	git archive --format=tar HEAD | tar -x -C "$$release_src_dir"; \
	cp -R "$(UI_DIR)/dist" "$$release_src_dir/$(UI_DIR)/"; \
	tar -C "$$release_src_dir" -czf "$$release_tarball" .; \
	echo "created $$release_tarball"

run: build
	./$(BINARY)

test: ui-build
	go test $(GOFLAGS) ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
	rm -rf $(UI_DIR)/dist

ui-install:
	cd $(UI_DIR) && npm install

ui-build:
	@if command -v npm >/dev/null 2>&1; then \
		cd "$(UI_DIR)" && npm install && npm run build; \
	elif [ -d "$(UI_DIR)/dist" ]; then \
		echo "npm not found; using existing $(UI_DIR)/dist"; \
	else \
		echo "npm not found and $(UI_DIR)/dist is missing"; \
		echo "build the UI elsewhere and use make release-tarball, or install npm"; \
		exit 1; \
	fi

docker-test:
	docker build --target test -f Dockerfile -t pf-dashboard:test .

docker-build:
	docker build --target release -f Dockerfile -t pf-dashboard:latest .
