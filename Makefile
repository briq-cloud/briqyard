GOOS ?= linux
GOARCH ?= $(shell go env GOARCH)
BIN := bin
LDFLAGS := -s -w -X github.com/briq-cloud/briqyard/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build init cli fleet check test fmt vet e2e clean vm

all: build

## build: every binary for the target OS (default linux, the host's arch)
build: init
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/briqyardd ./cmd/briqyardd
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/briqyard-fleet ./cmd/briqyard-fleet
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/briqyard ./cmd/briqyard

## init: the guest init, always static linux for the guest's arch (same as the host's)
init:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/briqyard-init ./cmd/briqyard-init

## cli: the CLI for the machine you are on
cli:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/briqyard-local ./cmd/briqyard

fmt:
	gofmt -l -w .

vet:
	go vet ./...

test:
	go test ./...

## check: what CI runs
check: vet test
	@test -z "$$(gofmt -l .)" || (echo "gofmt:"; gofmt -l .; exit 1)

## e2e: the end-to-end suite, on a KVM host with briqyardd installed (see docs/DEVELOPMENT.md)
e2e:
	./hack/e2e.sh

## vm: build and run the e2e suite inside the Lima VM "fc" (macOS development)
vm:
	./hack/vm.sh

clean:
	rm -rf $(BIN)
