# Fleet registry writes at once (2026-10-28)

The run behind ADR 0043's numbers. In the dev VM: a fleet of its own on `127.0.0.1:7451` (`tls: off`, `state_dir` in `/tmp`, `hosts:` the VM's daemon alone), started fresh for each run with the binary under test, then:

```bash
python3 hammer.py http://127.0.0.1:7451 32 50
```

| Answers | v0.1.1+ae2917a | this change |
|---|---|---|
| `POST unpin` 204 | 1531 | 1600 |
| `POST unpin` 500 `registry` | 69 (`File exists`, `No such file or directory`) | 0 |
| `POST machines` 201 / 503 `capacity` | 14 / 18 | 14 / 18 |
| `DELETE machines` 204, `DELETE tenants` 204 | 14, 32 | 14, 32 |

The 18 refusals are the disk a create holds (its volume plus 2 GB, ADR 0044) against the VM's 28 GB free, the same before and after.

`hammer.py`:

```python
# Registry writes at once through a fleet: N threads, each M unpins of its own tenant (a write
# and nothing else), then one create and destroy (with ?tenant=) of a 128 MB machine and the
# tenant's removal. Prints the answers by status, a `registry` refusal apart.
import collections
import json
import sys
import threading
import urllib.error
import urllib.request

url, n, m = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
seen = collections.Counter()
sample = {}
lock = threading.Lock()


def call(method, path, body=None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url + path, method=method, data=data, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            status, text = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    what = path.split("?")[0].split("/")
    kind = what[-1] if what[-1] in ("unpin",) else what[2]
    key = f"{method} {kind} {status}" + (" registry" if '"registry"' in text else "")
    with lock:
        seen[key] += 1
        sample.setdefault(key, text[:160])
    return status, text


def one(i):
    t = f"hammer-{i}"
    for _ in range(m):
        call("POST", f"/v1/tenants/{t}/unpin")
    body = {"tenant": t, "name": "h", "image": "alpine:3.20", "cmd": ["sleep", "120"],
            "size": {"vcpus": 1, "memory_mb": 128}, "sleep": "never"}
    s, text = call("POST", "/v1/machines", body)
    if s == 201:
        mid = json.loads(text)["id"]
        call("DELETE", f"/v1/machines/{mid}?tenant={t}")
    call("DELETE", f"/v1/tenants/{t}")


threads = [threading.Thread(target=one, args=(i,)) for i in range(n)]
for t in threads:
    t.start()
for t in threads:
    t.join()
for k, v in sorted(seen.items()):
    print(f"{v:6} {k}" + (f"  e.g. {sample[k]}" if not k.split()[2].startswith("2") else ""))
```
