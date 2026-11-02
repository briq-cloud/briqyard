# Changelog

## 0.1.17 — 2026-11-02

- Add acknowledged, cancellable exec streams across the daemon and guest init.
- Return a stable `unsupported` terminal code when the running guest lacks exec-stream capability.
- Require observed host telemetry before deriving zero-valued period usage.
- Bound stress runs and verify resource ownership.
