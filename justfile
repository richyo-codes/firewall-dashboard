set shell := ["sh", "-cu"]

binary := env_var_or_default("BINARY", "pf-dashboard")
ui_dir := "ui"
version := env_var_or_default("VERSION", "dev")
dist_dir := env_var_or_default("DIST_DIR", "dist")
goflags := env_var_or_default("GOFLAGS", "-buildvcs=false")

default: build

# Build the embedded frontend and dashboard binary.
build: ui-build
    go build {{ goflags }} -o {{ binary }} .

# Cross-compile release binaries.
build-linux: ui-build
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build {{ goflags }} -o {{ binary }}-linux-amd64 .

build-freebsd: ui-build
    GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build {{ goflags }} -o {{ binary }}-freebsd-amd64 .

# Create a source release with the compiled frontend included.
release-tarball: ui-build
    #!/usr/bin/env sh
    version="{{ version }}"
    if [ "$version" = "dev" ]; then
      desc=$(git describe --tags --dirty --always --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true)
      if echo "$desc" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+'; then
        version=$(echo "$desc" | sed -E 's/^v//; s/-([0-9]+)-g([0-9a-f]+)/-\1.g\2/; s/-dirty/.dirty/')
      elif [ -n "$desc" ]; then
        sanitized=$(printf '%s' "$desc" | sed -E 's/[^0-9A-Za-z.+-]+/-/g')
        version="0.0.0-dev+$sanitized"
      else
        version="0.0.0-dev+$(date +%Y%m%d)"
      fi
    fi
    release_src_dir="{{ dist_dir }}/release-src-$version"
    release_tarball="{{ dist_dir }}/{{ binary }}-$version-src.tar.gz"
    rm -rf "$release_src_dir"
    mkdir -p "$release_src_dir" "{{ dist_dir }}"
    git archive --format=tar HEAD | tar -x -C "$release_src_dir"
    cp -R "{{ ui_dir }}/dist" "$release_src_dir/{{ ui_dir }}/"
    tar -C "$release_src_dir" -czf "$release_tarball" .
    echo "created $release_tarball"

# Start the dashboard locally.
run: build
    ./{{ binary }}

# Build the frontend and run Go tests.
test: ui-build
    go test {{ goflags }} ./...

tidy:
    go mod tidy

clean:
    rm -f {{ binary }}
    rm -rf {{ ui_dir }}/dist

ui-install:
    cd {{ ui_dir }} && npm install

ui-build:
    #!/usr/bin/env sh
    if command -v npm >/dev/null 2>&1; then
      cd "{{ ui_dir }}" && npm install && npm run build
    elif [ -d "{{ ui_dir }}/dist" ]; then
      echo "npm not found; using existing {{ ui_dir }}/dist"
    else
      echo "npm not found and {{ ui_dir }}/dist is missing"
      echo "build the UI elsewhere and use just release-tarball, or install npm"
      exit 1
    fi

# Regenerate deterministic README and marketing screenshots.
screenshots: ui-build
    node scripts/capture-screenshots.mjs

docker-test:
    docker build --target test -f Dockerfile -t pf-dashboard:test .

docker-build:
    docker build --target release -f Dockerfile -t pf-dashboard:latest .
