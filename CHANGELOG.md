# Changelog

## 0.1.18 — 2026-11-03

### Documentation

- link contributor release and upgrade procedures ([8d5ef8e6](https://github.com/briq-cloud/briqyard/commit/8d5ef8e6504bb3586c0c4d83537e632a92217a66))

- clarify release and upgrade instructions ([8e7a4b1b](https://github.com/briq-cloud/briqyard/commit/8e7a4b1b0ba820fbd4bddf5e913e10e599c080d2))


### Features

- route sandbox creates through ready unbound slots (#106) ([14446432](https://github.com/briq-cloud/briqyard/commit/14446432eeac33db01c19dcced6a5b4d239ab586))


### Maintenance

- automate changelog preparation ([c409fa19](https://github.com/briq-cloud/briqyard/commit/c409fa19d97ad3e6d45f3e5dd38b771b56a33237))

## 0.1.17 — 2026-11-02

- Add acknowledged, cancellable exec streams across the daemon and guest init.
- Return a stable `unsupported` terminal code when the running guest lacks exec-stream capability.
- Require observed host telemetry before deriving zero-valued period usage.
- Bound stress runs and verify resource ownership.
