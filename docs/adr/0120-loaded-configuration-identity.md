# 0120 — Identify the configuration that was loaded

## Context

A configuration file can change after the daemon reads it. Hashing its pathname later cannot identify the input used by the running process. A maintenance operation needs to distinguish that input from a proposed replacement without returning configuration values.

## Decision

`Config::load` reads one buffer, parses and validates it, and retains its SHA-256. Replacing the file afterward does not change this identity. Loading defaults has a distinct identity; a programmatically constructed configuration is unobserved. Configuration input cannot supply the identity.

`briqyardd --config PATH check-config` uses the same parser and validation. It prints only the input identity as JSON, or the fixed error `configuration_invalid` and exit status 1. It runs before tracing and the async runtime, without opening host state, generating certificates, or listening.

## Limits

The digest identifies configuration bytes, not the contents of referenced files. It does not establish which daemon is serving, successful recovery, maintenance eligibility, or permission to replace a configuration. Those require separate observations and admission checks.
