# ADR 0001: A runtime of our own: Firecracker, a daemon per host, Rust, AGPL

Date: 2026-10-18 · Status: accepted

## Context

briq runs on rented microVMs whose terms do not cover resale. briq needs a place of its own to run briqs: any OCI image, a durable disk, a private network per team, sleep and wake on use, raw TCP in.

Research on 2026-10-18 reviewed eight isolation technologies and nine platforms: `../research/2026-10-18-microvm-field-guide.md`.

## Decisions

**Firecracker, driven directly over its socket API.** Proven in production at the scale of large serverless and sandbox platforms. Few devices, fast boot, memory snapshots, a jailer. Cloud Hypervisor has more (hotplug, live migration) but we need none of it yet.

**A daemon per host and a small placement service, not Kubernetes.** Kata and firecracker-containerd make a pod a microVM. A pod is the wrong unit: it is killed and rescheduled by design and keeps no identity. A machine keeps its disk, memory image and address. Sleep, resume, fork and wake on connect are the product; in Kubernetes they are built beside the scheduler, which may undo them. The platforms in this category that publish their design all ended with a daemon per host. One daemon, one fleet process, one JSON registry: fewer moving parts than etcd, kubelet, CSI and CNI.

**Not a fork of an open sandbox stack.** The most mature one is sandbox-shaped: no team network, no durable data volume, no raw TCP. No module system, about 115 merged PRs a month, all from its company's accounts: core changes would not land upstream.

**Rust.** The first version was Go; Sylvain asked for Rust and the Go code was dropped. One workspace; the init is a static musl binary because the guest has no shared libraries of ours.

**A separate repository, AGPL-3.0 from the first commit, private until launch.** Open source for visibility. A CLA so Uplab SAS can run it as a hosted service. The monorepo integrates it through a `Provider` adapter (up-lab/briq#250), beside its current provider.

## Consequences

- Everything above the VMM is ours: image to disk, network, volumes, sleep, snapshots, upgrades, placement.
- No live migration and no GPU until Firecracker ships them. A machine resumes only where its disk is.
- Firecracker's developer-preview features (device hotplug, io_uring) stay out of production paths.
- Reopen: Cloud Hypervisor if briqs need hotplug or live migration; Kubernetes if briq becomes a general PaaS of stateless services.
