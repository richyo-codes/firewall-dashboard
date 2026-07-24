set shell := ["/bin/sh", "-cu"]

binary := env_var_or_default("BINARY", "pf-dashboard")

default: build

build: ui-build
    go build -o "{{binary}}" .

build-linux: ui-build
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "{{binary}}-linux-amd64" .

build-freebsd: ui-build
    GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -o "{{binary}}-freebsd-amd64" .

run: build
    ./"{{binary}}"

test:
    go test ./...

tidy:
    go mod tidy

clean:
    rm -f "{{binary}}" "{{binary}}-linux-amd64" "{{binary}}-freebsd-amd64"
    rm -rf ui/dist dist

ui-install:
    cd ui && npm install

ui-build: ui-install
    cd ui && npm run build

docker-test:
    docker build --target test -f Dockerfile -t pf-dashboard:test .

docker-build:
    docker build --target release -f Dockerfile -t pf-dashboard:latest .
