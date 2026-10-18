# Contributing

Thanks for looking. briqyard is young; the core concepts, the API and the on-disk layout will
change before a stable release.

## Open an issue first

For anything that is not a small fix, open an issue before writing code, so we agree on the
direction before you spend time on it.

## Contributor license agreement

briqyard is AGPL-3.0, and Uplab SAS also runs it as a hosted service. To keep both possible,
every contribution needs a signed CLA that grants Uplab SAS the right to relicense the
contribution. A bot asks you to sign it on your first pull request.

## Development

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). `make check` runs what CI runs: `gofmt`,
`go vet`, the unit tests. The end-to-end suite needs a KVM host: `make e2e`.

## Style

Go, formatted by `gofmt`. Errors carry what failed and what was being done. Nothing in the daemon
prints to stdout but logs, one JSON line per event. A new API field gets its OpenAPI entry in the
same change.
