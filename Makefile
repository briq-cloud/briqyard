CARGO ?= cargo

.PHONY: all build check test fmt clippy e2e vm clean

ARCH ?= $(shell uname -m)

## build: release binaries for the machine you are on (linux for the daemon and the init)
all: build
build: init
	$(CARGO) build --release --workspace --exclude briqyard-init

## init: the guest init, static (musl), for the guest's arch (the host's). Needs the target:
## rustup target add $(ARCH)-unknown-linux-musl
init:
	$(CARGO) build --release -p briqyard-init --target $(ARCH)-unknown-linux-musl

## check: what CI runs
check: fmt-check clippy test

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test:
	$(CARGO) test --workspace

## e2e: the end-to-end suite, on a KVM host with briqyardd installed (see docs/DEVELOPMENT.md)
e2e:
	./hack/e2e.sh

## vm: build and install inside the Lima VM "fc" (macOS development)
vm:
	./hack/vm.sh install

clean:
	$(CARGO) clean
