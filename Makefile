GO ?= go
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w -X github.com/example/monitorozo/internal/version.Version=$(VERSION) -X github.com/example/monitorozo/internal/version.Commit=$(COMMIT) -X github.com/example/monitorozo/internal/version.BuildTime=$(BUILD_TIME)

.PHONY: all fmt vet test lint build release clean
all: lint test build

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test -race -cover ./...

lint: fmt vet
	@test -z "$$(git diff -- '*.go')" || (echo "gofmt changed files"; git diff --exit-code; exit 1)

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/monitorozo-agent ./cmd/agent
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/monitorozo-server ./cmd/server

release:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/monitorozo-agent-linux-amd64 ./cmd/agent
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/monitorozo-server-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/monitorozo-agent-linux-arm64 ./cmd/agent
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o dist/monitorozo-server-linux-arm64 ./cmd/server

clean:
	rm -rf bin dist

