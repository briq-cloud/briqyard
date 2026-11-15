# Runtime installation helpers. Kept here because the fleet embeds this standalone script.
checked_bundle() {
  python3 - "$@" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

bundle, arch, destination = sys.argv[1:]
with tarfile.open(bundle, "r:gz") as archive:
    members = archive.getmembers()
    files = {}
    for member in members:
        if not member.isfile() or member.name in files or not re.fullmatch(r"[A-Za-z0-9_.-]+", member.name):
            raise ValueError("unsafe or duplicate runtime package member")
        files[member.name] = archive.extractfile(member).read()
    pin = json.loads(files["pin.json"])
    provenance = json.loads(files["provenance.json"])
    receipt = json.loads(files["receipt.json"])
    required = {"firecracker", "jailer", "seccomp_filter.bpf", "seccomp-source.json",
                "provenance.json", "receipt.json", "pin.json", "series", "uapi-inputs.json",
                "LICENSE", "NOTICE", "THIRD-PARTY"} | {p["path"] for p in pin["series"]}
    if set(files) != required or any(not data for data in files.values()):
        raise ValueError("incomplete runtime package")
    if (provenance["status"] != "static-cli-candidate-built"
            or provenance["architecture"] != arch
            or provenance["target"] != arch + "-unknown-linux-musl"
            or provenance["base"] != pin["base"] or provenance["tree"] != pin["tree"]
            or provenance["series_sha256"] != pin["series_concatenated_sha256"]
            or receipt["status"] != "portable-validation-passed"
            or receipt["architecture"] != arch or receipt["base"] != pin["base"]
            or receipt["tree"] != pin["tree"] or receipt["toolchain"] != pin["toolchain"]):
        raise ValueError("runtime provenance or validation mismatch")
    expected = {name: provenance["binaries"][name] for name in ("firecracker", "jailer")}
    expected.update({"seccomp_filter.bpf": provenance["seccomp"]["compiled"],
                     "seccomp-source.json": provenance["seccomp"]["source"],
                     "uapi-inputs.json": provenance["uapi_inputs"],
                     "series": {"sha256": pin["series_file_sha256"]}})
    expected.update({p["path"]: p for p in pin["series"]})
    for name, record in expected.items():
        data = files[name]
        if hashlib.sha256(data).hexdigest() != record["sha256"] or len(data) != record.get("bytes", len(data)):
            raise ValueError("runtime digest mismatch: " + name)
    patches = pin["series"]
    if (files["series"].decode("ascii").splitlines() != [p["path"] for p in patches]
            or hashlib.sha256(b"".join(files[p["path"]] for p in patches)).hexdigest() != pin["series_concatenated_sha256"]):
        raise ValueError("runtime patch series mismatch")
    # No archive paths, links or modes are used. All checks precede the first write.
    root = Path(destination)
    root.mkdir(mode=0o700)
    for name, data in files.items():
        (root / name).write_bytes(data)
PY
}

# Each cached hash keeps referring to these bytes while an old daemon or builder finishes.
# Never overwrite an existing digest path, even on a same-version reinstall.
immutable_runtime() {
  local source=$1 name=$2 digest target temporary
  digest=$(sha256sum "$source" | awk '{print $1}') || fail "cannot hash runtime input"
  target="$runtime_root/$digest/$name"
  mkdir -p "$runtime_root/$digest" || fail "cannot create runtime directory"
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ ! -L "$target" ] && echo "$digest  $target" | sha256sum -c --quiet - || fail "immutable runtime input differs: $target"
  else
    temporary=$(mktemp "$runtime_root/$digest/.stage.XXXXXX") || fail "cannot stage runtime input"
    install -m 0555 "$source" "$temporary" || { rm -f "$temporary"; fail "cannot install runtime input"; }
    echo "$digest  $temporary" | sha256sum -c --quiet - || { rm -f "$temporary"; fail "staged runtime digest differs"; }
    # A concurrent staging attempt may have installed the same bytes. Never replace them.
    if ! ln "$temporary" "$target" 2>/dev/null; then
      [ ! -L "$target" ] && echo "$digest  $target" | sha256sum -c --quiet - || { rm -f "$temporary"; fail "immutable runtime input differs"; }
    fi
    rm -f "$temporary"
  fi
  echo "$target"
}

runtime_config() {
  python3 - "$@" <<'PYCONFIG'
import json
from pathlib import Path
import sys
import yaml

path = Path(sys.argv[1])
text = path.read_bytes().decode("utf-8")
try:
    config = yaml.compose(text)
    tokens = list(yaml.scan(text))
except yaml.YAMLError:
    raise SystemExit("cannot parse runtime configuration") from None
if not isinstance(config, yaml.MappingNode) or config.flow_style:
    raise SystemExit("runtime paths require a block configuration mapping")
paths = dict(zip(("firecracker", "jailer", "kernel", "init"), sys.argv[2:]))
edits = []
seen = set()
for key, value in config.value:
    if not isinstance(key, yaml.ScalarNode):
        raise SystemExit("runtime configuration has a complex mapping key")
    if key.value == "<<":
        raise SystemExit("runtime paths cannot be updated through a root merge")
    if key.value not in paths:
        continue
    if key.value in seen:
        raise SystemExit("duplicate runtime path in configuration")
    seen.add(key.value)
    start, end = value.start_mark.index, value.end_mark.index
    # Aliases point to a different source span; anchors can be referenced by unrelated
    # fields. Refuse those cases rather than silently changing their meaning.
    if (not isinstance(value, yaml.ScalarNode) or start <= key.end_mark.index
            or "\n" in text[start:end] or "\r" in text[start:end]
            or any(isinstance(t, (yaml.AnchorToken, yaml.AliasToken))
                   and key.start_mark.index <= t.start_mark.index < end for t in tokens)):
        raise SystemExit("runtime paths must be unanchored single-line scalars")
    edits.append((start, end, json.dumps(paths[key.value])))
# Insert absent fields before an explicit document end, preserving every other byte.
missing = "".join(name + ": " + json.dumps(value) + "\n"
                  for name, value in paths.items() if name not in seen)
if missing:
    end = next((t.start_mark.index for t in tokens if isinstance(t, yaml.DocumentEndToken)), len(text))
    edits.append((end, end, ("" if end == 0 or text[end - 1] == "\n" else "\n") + missing))
for start, end, replacement in sorted(edits, reverse=True):
    text = text[:start] + replacement + text[end:]
try:
    yaml.compose(text)
except yaml.YAMLError:
    raise SystemExit("cannot preserve runtime configuration syntax") from None
path.write_bytes(text.encode("utf-8"))
PYCONFIG
}

# Writes the class into the config's `runtime_classes`: the whole block is replaced when it is
# there, appended when not. The class's files are immutable, so a new release is a new path.
runtime_class() {
  python3 - "$@" <<'PYCLASS'
import json
from pathlib import Path
import sys
import yaml

path, name, kernel, modules, release, versions = sys.argv[1:]
text = Path(path).read_bytes().decode("utf-8")
try:
    config = yaml.compose(text)
except yaml.YAMLError:
    raise SystemExit("cannot parse runtime configuration") from None
if not isinstance(config, yaml.MappingNode) or config.flow_style:
    raise SystemExit("runtime classes require a block configuration mapping")
block = "runtime_classes:\n  %s:\n" % name + "".join(
    "    %s: %s\n" % (k, json.dumps(v) if isinstance(v, str) else str(v).lower())
    for k, v in (("kernel", kernel), ("modules", modules), ("release", release),
                 ("versions", versions), ("nested", True)))
spans = [(k.start_mark.index, v.end_mark.index) for k, v in config.value
         if isinstance(k, yaml.ScalarNode) and k.value == "runtime_classes"]
if len(spans) > 1:
    raise SystemExit("duplicate runtime_classes in configuration")
if spans:
    start, end = spans[0]
    after = text[end:]
    text = text[:start] + block.rstrip("\n") + ("" if after.startswith("\n") else "\n") + after
else:
    text += ("" if not text or text.endswith("\n") else "\n") + block
try:
    yaml.compose(text)
except yaml.YAMLError:
    raise SystemExit("cannot preserve runtime configuration syntax") from None
Path(path).write_bytes(text.encode("utf-8"))
PYCLASS
}

runtime_kernel() {
  python3 - "$1" <<'PYKERNEL'
from pathlib import Path
import sys
import yaml

try:
    config = yaml.compose(Path(sys.argv[1]).read_text())
except yaml.YAMLError:
    raise SystemExit("cannot parse runtime configuration") from None
if not isinstance(config, yaml.MappingNode):
    raise SystemExit("configuration must be a mapping")
for key, value in config.value:
    if isinstance(key, yaml.ScalarNode) and key.value == "kernel":
        if not isinstance(value, yaml.ScalarNode):
            raise SystemExit("kernel path must be a scalar")
        print(value.value)
        break
else:
    print("/var/lib/briqyard/vmlinux")
PYKERNEL
}
# Inspect both the installed and candidate roots without opening or changing host state.
# Kept standalone: this gate must also protect stopped daemons and custom data_dir.
runtime_assignment_compatible() {
  python3 - "$@" <<'PYASSIGNMENT'
import json, os, pathlib, selectors, subprocess, sys, time
import yaml

def required(config):
    path = pathlib.Path(config)
    try:
        source = path.read_text()
    except FileNotFoundError:
        if path.is_symlink():
            raise ValueError("dangling configuration")
        return False
    value = yaml.safe_load(source)
    if not isinstance(value, dict):
        raise ValueError("invalid configuration mapping")
    # Do not let duplicate data_dir entries select an apparently empty root.
    node = yaml.compose(source)
    if sum(key.value == "data_dir" for key, _ in node.value) > 1:
        raise ValueError("duplicate data_dir")
    data = value.get("data_dir", "/var/lib/briqyard")
    if not isinstance(data, str) or not pathlib.Path(data).is_absolute():
        raise ValueError("invalid data_dir")
    root = pathlib.Path(data) / "state"
    floor = root / "meta/required-assignment-protocol.json"
    needed = 0
    try:
        marker = json.loads(floor.read_bytes())
    except FileNotFoundError:
        if floor.is_symlink():
            raise ValueError("dangling assignment floor")
    else:
        if marker == {"schema": 1, "protocol": "destination-assignment-v1"} and type(marker["schema"]) is int:
            needed = 1
        elif marker == {"schema": 2, "protocol": "assigned-run-v1"} and type(marker["schema"]) is int:
            needed = 2
        elif marker == {"schema": 3, "protocol": "assigned-run-lifecycle-v1"} and type(marker["schema"]) is int:
            needed = 3
        elif marker == {"schema": 4, "protocol": "assigned-update-v3"} and type(marker["schema"]) is int:
            needed = 4
        elif marker == {"schema": 5, "protocol": "scoped-execution-v1"} and type(marker["schema"]) is int:
            needed = 5
        elif marker == {"schema": 6, "protocol": "scoped-execution-v2"} and type(marker["schema"]) is int:
            needed = 6
        else:
            raise ValueError("invalid assignment protocol floor")
    runs = ("assigned-run-intents", "assigned-runs", "assigned-run-readers")
    for kind in ("unbound-assignments", "unbound-requests", "machines", "assigned-run-updates", "execution-idle-protection", "execution-namespace-fence") + runs:
        try:
            entries = list((root / kind).iterdir())
        except FileNotFoundError:
            if (root / kind).is_symlink():
                raise ValueError("dangling assignment state directory")
            continue
        for entry in entries:
            if entry.suffix != ".json":
                continue
            record = json.loads(entry.read_bytes())
            if not isinstance(record, dict):
                raise ValueError("invalid assignment state record")
            if kind in ("execution-idle-protection", "execution-namespace-fence"):
                if kind == "execution-idle-protection" and "operation_envelope_ms" in record:
                    if type(record["operation_envelope_ms"]) is not int or record["operation_envelope_ms"] != 80000:
                        raise ValueError("unsupported renewable operation envelope")
                    needed = max(needed, 6)
                else:
                    needed = max(needed, 5)
            elif kind == "assigned-run-updates":
                if type(record.get("schema")) is not int or record["schema"] not in (1, 2, 3):
                    raise ValueError("unsupported assigned update evidence schema")
                needed = max(needed, 4 if record["schema"] == 3 else 3)
            elif kind in runs:
                if type(record.get("schema")) is not int or record["schema"] not in (1, 3):
                    raise ValueError("unsupported assigned run evidence schema")
                needed = max(needed, 3 if record["schema"] == 3 else 2)
            elif kind != "machines":
                receipt = record.get("receipt") if kind == "unbound-assignments" else record
                if not isinstance(receipt, dict) or type(receipt.get("schema")) is not int or receipt["schema"] != 1:
                    raise ValueError("invalid assignment receipt schema")
                needed = max(needed, 1)
            elif record.get("assigned_run") is not None:
                run = record["assigned_run"]
                if (not isinstance(run, dict) or set(run) != {"schema", "sequence", "phase"}
                        or type(run.get("schema")) is not int or run["schema"] not in (1, 3)
                        or type(run.get("sequence")) is not int or run["sequence"] <= 0
                        or run.get("phase") not in (("reserved", "observed", "settled") if run["schema"] == 3 else ("reserved", "observed"))):
                    raise ValueError("unsupported assigned run record link")
                needed = max(needed, 3 if run["schema"] == 3 else 2)
            elif record.get("launch_identity") is not None:
                warm = record.get("warm_slot")
                if warm is not None and not isinstance(warm, dict):
                    raise ValueError("invalid warm slot")
                if isinstance(warm, dict) and warm.get("claimed") is not None:
                    needed = max(needed, 1)
    return needed

def probe(binary, command, expected):
    child = subprocess.Popen([binary, command], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        output = b""
        deadline = time.monotonic() + 5
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise ValueError("assignment capability probe timeout")
            chunk = os.read(child.stdout.fileno(), 128 - len(output))
            if not chunk:
                break
            output += chunk
            if len(output) >= 128:
                raise ValueError("assignment capability output too long")
        if output != expected or child.wait(timeout=max(.001, deadline - time.monotonic())) != 0:
            raise ValueError("candidate lacks destination assignment support")
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        selector.close()
try:
    # Evaluate every root even after one requires support: malformed roots fail closed.
    states = [required(config) for config in sys.argv[2:] if config]
    # Every managed replacement needs the complete current protocol. State can
    # advance after this inspection, including while the daemon starts or restarts.
    probe(sys.argv[1], "assignment-capabilities", b"destination-assignment-v1\n")
    probe(sys.argv[1], "assigned-run-capabilities", b"assigned-run-v1\n")
    probe(sys.argv[1], "assigned-run-lifecycle-capabilities", b"assigned-run-lifecycle-v1\n")
    probe(sys.argv[1], "assigned-update-capabilities", b"assigned-update-v3\n")
    probe(sys.argv[1], "scoped-execution-capabilities", b"scoped-execution-v2\n")
except Exception:
    print("assignment compatibility inspection/probe refused replacement", file=sys.stderr)
    sys.exit(1)
PYASSIGNMENT
}
# A failed activation restores installed executables before leaving the old daemon running.
# The verified rollback directory also remains available for an explicit later rollback.
cleanup_runtime_install() {
  local result=$? b restored=1 retained_sha
  trap - EXIT
  if [ "$result" != 0 ] && [ "$activation_pending" = 1 ] && [ "$rollback_ready" = 1 ]; then
    retained_sha=$(sha256sum "$rollback/briqyardd" | awk '{print $1}') || retained_sha=""
    if [ -z "$retained_sha" ] || ! runtime_assignment_compatible "$rollback/briqyardd" "$config_path" "$rollback/config.yaml" ||
       ! echo "$retained_sha  $rollback/briqyardd" | sha256sum -c --quiet -; then
      echo "   activation failed; retained daemon is incompatible with current state; compatible replacement left installed ($rollback)" >&2
      [ -z "$new" ] || rm -rf "$new"
      [ -z "$candidate" ] || rm -f "$candidate"
      exit "$result"
    fi
    for b in briqyard briqyard-fleet briqyardd; do
      if [ -f "$rollback/$b" ]; then
        cp -p "$rollback/$b" "$binary_dir/$b.rollback" && mv -f "$binary_dir/$b.rollback" "$binary_dir/$b" || restored=0
      fi
    done
    if ! cmp -s "$rollback/config.yaml" "$config_path"; then
      cp -p "$rollback/config.yaml" "$config_path.rollback" && mv -f "$config_path.rollback" "$config_path" || restored=0
    fi
    if [ "$restored" = 0 ]; then
      echo "   activation failed; automatic restoration incomplete: retained rollback at $rollback" >&2
    else
      echo "   activation failed; previous executables and configuration restored ($rollback)" >&2
    fi
  fi
  [ -z "$new" ] || rm -rf "$new"
  [ -z "$candidate" ] || rm -f "$candidate"
  if [ -n "$rollback" ] && [ "$rollback_ready" = 0 ]; then rm -rf "$rollback"; fi
  exit "$result"
}
# One bounded, root-private preparation per host, protected by runtime-install.lock.
# Receipt hashes bind the verified local files and config; they are not release signatures.
prepared_receipt() {
  python3 - "$1" "$prepared" "$prepare_id" "$RELEASE" "$ARCH" "$NESTED" "$KERNEL_URL" "$KERNEL_SHA256" <<'PYPREPARED'
import hashlib, json, os, pathlib, re, stat, sys, time
operation, directory, identity, *settings = sys.argv[1:]
root = pathlib.Path(directory)
config = root.parent / "config.yaml"
def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()
def files():
    result = {}
    for path in root.rglob("*"):
        info = path.lstat()
        if path.is_symlink() or not (path.is_dir() or path.is_file()) or info.st_uid != os.geteuid():
            raise ValueError("unsafe prepared file")
        if path.is_file() and path != root / "receipt.json":
            result[str(path.relative_to(root))] = digest(path)
    return result
try:
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("unsafe preparation directory")
    receipt = root / "receipt.json"
    if operation == "write":
        value = dict(schema=1, identity=identity, settings=settings, config=digest(config),
                     created=time.time(), files=files())
        receipt.write_text(json.dumps(value))
        receipt.chmod(0o600)
    else:
        if receipt.is_symlink():
            raise ValueError("unsafe receipt")
        value = json.loads(receipt.read_bytes())
        if (set(value) != {"schema", "identity", "settings", "config", "created", "files"}
              or type(value["schema"]) is not int or value["schema"] != 1
              or not isinstance(value["identity"], str) or not re.fullmatch("[a-f0-9]{32}", value["identity"])
              or not isinstance(value["settings"], list) or len(value["settings"]) != 5
              or not all(isinstance(setting, str) for setting in value["settings"])
              or value["config"] != digest(config) or value["files"] != files()):
            raise ValueError("incomplete or changed preparation")
        age = time.time() - value["created"]
        if operation == "expire":
            if not 3600 < age:
                raise ValueError("another preparation owns host mutation; wait or explicitly discard it")
        elif (value["schema"] != 1 or value["identity"] != identity
              or value["settings"] != settings or value["config"] != digest(config)
              or not 0 <= age <= 3600 or value["files"] != files()):
            raise ValueError("stale or changed preparation")
except Exception as error:
    raise SystemExit("prepared upgrade refused: " + str(error)) from None
PYPREPARED
}
# End runtime installation helpers.
