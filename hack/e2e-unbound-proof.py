"""Read-only native slot proof. No guest calls, activation or process signals."""
import json
from pathlib import Path
import stat
import subprocess
import sys

import yaml


def incarnation(proc, boot):
    return {"pid": int(proc.name),
            "start_ticks": int((proc / "stat").read_text().rsplit(") ", 1)[1].split()[19]),
            "host_boot_id": boot.read_text().strip()}


def credentials(text, uid, gid):
    rows = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key in ("Uid", "Gid", "Groups"):
            assert key not in rows, "duplicate credentials"
            rows[key] = [int(n) for n in value.split()]
    assert rows["Uid"] == [uid] * 4 and rows["Gid"] == [gid] * 4
    assert all(n == gid for n in rows["Groups"]), "foreign supplementary group"


def checked_device(dataset):
    device = (Path("/dev/zvol") / dataset).resolve(strict=True)
    actual = device.stat()
    assert stat.S_ISBLK(actual.st_mode)
    observed = subprocess.check_output(
        ["/usr/lib/udev/zvol_id", str(device)], text=True, timeout=5).strip()
    assert observed == dataset, "zvol device belongs to a different dataset"
    assert device.stat().st_rdev == actual.st_rdev
    return device, actual


def proof(config, machine, phase):
    c = yaml.safe_load(Path(config).read_text())
    record_path = Path(c["data_dir"]) / "state/machines" / (machine + ".json")
    r = json.loads(record_path.read_text())
    assert isinstance(r["boot_identity"], dict) and r["boot_identity"]
    launch = r["launch_identity"]
    assert launch["jailed"] and launch["uid"] > 0 and launch["gid"] > 0
    saved = r["boot_incarnation"]
    proc = Path("/proc") / str(saved["pid"])
    boot = Path("/proc/sys/kernel/random/boot_id")
    assert incarnation(proc, boot) == saved
    args = (proc / "cmdline").read_bytes().split(b"\0")
    assert args[args.index(b"--id") + 1].decode().replace("m-", "m_", 1) == machine
    credentials((proc / "status").read_text(), launch["uid"], launch["gid"])
    stage = r["clone_origin"]["stage"]
    assert stage == {"paused": "unbound_paused", "active": "active"}[phase], stage
    if phase == "paused":
        assert not r["env"] and not r["files"] and not r.get("cmd")
        assert not r["clone_origin"].get("sandbox")
    # The jailed socket path is the one used by fc::process::paths_for.
    socket = proc / "root/run/firecracker.socket"
    info = json.loads(subprocess.check_output(
        ["curl", "--max-time", "5", "--fail", "-sS", "--unix-socket", str(socket), "http://localhost/"], timeout=6))
    assert info["state"] == {"paused": "Paused", "active": "Running"}[phase]
    devices = []
    for disk in ("root", "data"):
        dataset = c["storage"]["pool"] + "/m/" + machine + "/" + disk
        guid = subprocess.check_output(["zfs", "get", "-Hp", "-o", "value", "guid", dataset], text=True, timeout=5).strip()
        device, actual = checked_device(dataset)
        # Positive evidence that this exact VMM has each actual destination disk open.
        opened = False
        for fd in (proc / "fd").iterdir():
            try:
                s = fd.stat()
                opened |= stat.S_ISBLK(s.st_mode) and s.st_rdev == actual.st_rdev
            except FileNotFoundError:
                continue
        assert opened, "VMM does not hold " + disk
        # Recheck after reading the VMM's descriptors to reject device reassignment.
        assert checked_device(dataset)[1].st_rdev == actual.st_rdev
        devices.append({"guid": guid, "rdev": actual.st_rdev})
    group = next(line[3:] for line in (proc / "cgroup").read_text().splitlines() if line.startswith("0::"))
    ceiling = int((Path("/sys/fs/cgroup") / group.lstrip("/") / "memory.max").read_text())
    assert ceiling == (r["size"]["memory_mb"] + 256) * 1024 * 1024
    assert incarnation(proc, boot) == saved
    current = json.loads(record_path.read_text())
    for key in ("boot_incarnation", "boot_identity", "launch_identity"):
        assert current[key] == r[key]
    return {"id": machine, "incarnation": saved, "boot": r["boot_identity"],
            "launch": launch, "devices": devices, "memory_max": ceiling}


if __name__ == "__main__":
    try:
        print(json.dumps(proof(*sys.argv[1:])))
    except Exception:
        # Fixed diagnostic: durable records may carry destination configuration.
        sys.exit("native unbound process/disk proof unavailable or inconsistent")
