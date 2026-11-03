# 0090: The app owns the console it writes to

Status: accepted.

The init gives the app `/dev/console` as stdout and stderr, then drops to the image's user.
`/dev/console` is `crw------- root root` and nothing changes it. An app that re-opens its
stderr by path (`/dev/stderr`, `/proc/self/fd/2`; both re-open the device, the inherited fd
does not help) gets EACCES and exits 1. `nginxinc/nginx-unprivileged:1.28-alpine-slim`
(USER 101) does it: `/var/log/nginx/error.log` links to `/dev/stderr`, and the console shows
`[emerg] open() "/var/log/nginx/error.log" failed (13: Permission denied)` then
`[briqyard] exit code=1`. hack/e2e.sh "its uid, gid and groups" failed on x86_64 because of it.
Any non-root image that logs to `/dev/stdout` or `/dev/stderr` is affected.

Decision: before dropping privileges, `fchown` the console to the app's uid and gid, mode
kept at 0600. Only the app user and root can open it; no world access.

Why this is narrow: the init runs one app. It opens its own console handle once at boot and
keeps writing through that fd, which a root-owned or app-owned node does not affect (root
bypasses the check). Exec sessions use their own pipes or ptys, not the console. An app run
as root gets a no-op chown.

Rejected: mode 0666 (any process in the guest could write to the console, which the host
reads as init output); pipes forwarded by the init (a second copy of every log byte, and
`/dev/stderr` would then be a pipe path, not the console).

Evidence: regression test `console_is_opened_again_by_the_app_user` (root-only, run in CI)
shows EACCES before and success after, and refusal for a third user. hack/e2e.sh stays the
end-to-end check. Why aarch64 passed is not established.
