# Disk limits benchmark (2026-10-21, ADR 0030)

On the Mac (Lima VM `fc`, nested virtualization, the pool a file on the VM's disk): the figures show the limiter at work, not what an NVMe does. Daemon at `feat/disk-limits`, Firecracker v1.17.0, alpine 3.20 guests with `fio`, 1 vCPU, 512 MB, a 4 GB volume, O_DIRECT, 512 MB file laid out first.

| | seq read 1M MB/s | seq write 1M MB/s | 4k rand read IOPS qd 32 | 4k rand write IOPS qd 32 |
|---|---|---|---|---|
| no limit | 99 | 8 | 8,655 | 1,539 |
| 32 MB/s, 4000 IOPS, no burst | 34 | 19 | 4,196 | 1,990 |
| 4 MB/s, 200 IOPS, no burst | 3 | | 206 | |

A second guest's 4k reads at qd 1 (IOPS, p99) while the first floods (64k random read-write, qd 64, 25 s):

| Run | other idle | flood, no limit | flood limited |
|---|---|---|---|
| 1 (limit 32 MB/s, 4000) | 684, 15.8 ms | 456, 35.4 ms | 466, 34.9 ms |
| 2 (limit 4 MB/s, 200) | 238, 8.0 ms | 1,110, 8.0 ms | 1,449, 7.6 ms |

The VM's disk moves by 4× between runs and serves the neighbour faster during a flood: no conclusion on neighbours from it. `dd` with O_DIRECT at 4 MB/s, no burst: 32 MiB written to the volume in 6.2 to 7 s, 16 MiB read from `/dev/vda` in 2.5 s; lifted, 32 MiB read in 0.12 s and written in 0.33 s.

## On a real host

Run the script below on the host (it sets the limits itself; run 2's flood limit is a `set-disk-limits` under the device's figures). Add `fio` on a raw zvol of the pool for the device itself (`zfs create -V 8G byard/bench`, `fio --filename=/dev/zvol/byard/bench …`, then `zfs destroy byard/bench`).

```bash
#!/usr/bin/env bash
# Disk limits benchmark (ADR 0030), on a host against its daemon.
# fio in two alpine guests, each with a 4 GB volume: alone without limits, alone at the
# defaults for 1 vCPU, and a neighbour measured while the other floods its disk.
set -uo pipefail
export BRIQYARD_URL=${BRIQYARD_URL:-http://127.0.0.1:7420}
export PATH=/usr/local/bin:$PATH
T=bench-$$
cleanup() {
  for id in $(briqyard machine ls --tenant "$T" 2>/dev/null | awk 'NR>1{print $1}'); do briqyard machine rm "$id" >/dev/null 2>&1 || true; done
  briqyard tenant rm "$T" >/dev/null 2>&1 || true
}
trap cleanup EXIT
run() { briqyard machine run --image alpine:3.20 --name "$1" --tenant "$T" --memory 512 --volume 4G:/data --disk-bw 0 --disk-iops 0 -- sleep 3600 | jq -r .id; }
A=$(run a); B=$(run b)
for m in $A $B; do briqyard machine exec "$m" -- apk add -q fio >/dev/null; done
# Lay the file out once, so reads read written blocks.
for m in $A $B; do briqyard machine exec "$m" -- fio --name=lay --filename=/data/f --size=512M --bs=1M --rw=write --direct=1 --output-format=terse >/dev/null; done
fio_j() { local m=$1; shift; briqyard machine exec --timeout 5m "$m" -- fio --name=t --filename=/data/f --size=512M --direct=1 --output-format=json "$@"; }
seqw() { fio_j "$1" --bs=1M --rw=write --ioengine=psync --runtime=10 --time_based | jq '.jobs[0].write.bw_bytes/1048576|floor'; }
seqr() { fio_j "$1" --bs=1M --rw=read --ioengine=psync --runtime=10 --time_based | jq '.jobs[0].read.bw_bytes/1048576|floor'; }
randw() { fio_j "$1" --bs=4k --rw=randwrite --ioengine=libaio --iodepth=32 --runtime=10 --time_based | jq '.jobs[0].write.iops|floor'; }
randr() { fio_j "$1" --bs=4k --rw=randread --ioengine=libaio --iodepth=32 --runtime=10 --time_based | jq '.jobs[0].read.iops|floor'; }
# A's IOPS and p99 latency (us) at queue depth 1, the way a database's reads see the disk.
probe() { fio_j "$1" --bs=4k --rw=randread --ioengine=psync --runtime=10 --time_based | jq -r '[(.jobs[0].read.iops|floor), (.jobs[0].read.clat_ns.percentile["99.000000"]/1000|floor)] | @tsv'; }
flood() { fio_j "$1" --bs=64k --rw=randrw --ioengine=libaio --iodepth=64 --runtime=25 --time_based >/dev/null; }

echo "== alone, no limits"
echo "seq write MB/s $(seqw "$A")  seq read MB/s $(seqr "$A")  rand write iops $(randw "$A")  rand read iops $(randr "$A")"
echo "qd1 read (iops, p99 us): $(probe "$A")"

briqyard machine set-disk-limits "$A" --disk-bw 32 --disk-iops 4000 --disk-burst 0 >/dev/null
echo "== alone, 32 MB/s 4000 IOPS"
echo "seq write MB/s $(seqw "$A")  seq read MB/s $(seqr "$A")  rand write iops $(randw "$A")  rand read iops $(randr "$A")"
briqyard machine set-disk-limits "$A" --disk-bw 0 --disk-iops 0 >/dev/null

echo "== B's qd1 reads while A floods (64k randrw, qd 64)"
echo "A idle:           $(probe "$B")"
flood "$A" & sleep 5; echo "A unlimited:      $(probe "$B")"; wait
briqyard machine set-disk-limits "$A" --disk-bw 32 --disk-iops 4000 --disk-burst 0 >/dev/null
flood "$A" & sleep 5; echo "A at 32MB/s 4000: $(probe "$B")"; wait
```
