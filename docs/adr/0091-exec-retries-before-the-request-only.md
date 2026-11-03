# 0091: A guest call is retried before its request is written, never after

Status: accepted.

A stress run (native, hosted KVM) got `500 internal` "Connection reset by peer" from an exec on
a running machine. A reset can surface in two places: during the vsock handshake with
Firecracker, or after the request frame was written.

Decision:
- Before the request is written (`guestc::dial`: connect, `CONNECT`, the `OK` line), a reset
  means nothing reached the guest. The handshake is tried again, 4 attempts with pauses of
  200, 300 and 400 ms (about 0.9 s), then reported as `Unreachable` (409 not_running).
  Whether 0.9 s covers a restore window is not measured.
- After the request is written, a reset (or a broken pipe) is `Closed`, as an end of stream
  is, and answers 409 not_running ("went down during the call"). The command may have
  started, so it is never sent again: an exec runs at most once. This covers exec, put, get,
  file streams and control calls.

Other io errors stay internal errors.
