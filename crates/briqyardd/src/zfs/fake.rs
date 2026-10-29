use super::*;

/// A stand-in for `zfs`, with a directory as its state: a directory per parent
/// dataset, a file per volume or snapshot, and `<clone>.origin` naming the snapshot a
/// clone was made from (a filesystem, made with a mountpoint, is a directory; `promote` moves that snapshot and the source's older ones, in the
/// order `snapshots.order` keeps, to the clone and makes the source the clone's clone, as
/// ZFS does). Every call is appended to `calls`, one line each;
/// `get` answers come from `answer.<property>` files when there is one, else `origin` and
/// `clones` from the `.origin` files, and `list -p` (space) from `answer.space`; `busy` holds how many destroys still answer
/// "dataset is busy"; a command waits while a `hold.<command>` file is there and its test
/// process runs (a test binary that exits runs no destructor: the file stays). A stream is
/// one line naming its snapshot and its base; a receive makes the dataset and the snapshot, and refuses
/// an increment whose base the dataset lacks, as ZFS does; `load-key` takes the line on its
/// stdin when it is the `key` file's and answers `keystatus` `available` from then on;
/// `change-key` needs the dataset. A volume's file holds its `volsize`: set by `create -V`
/// and `set volsize=`, kept by its snapshots, clones and streams, answered by `get`.
/// Error texts are the real ones,
/// since the code matches on them.
const FAKE: &str = r#"#!/bin/sh
DEV="__DEV__"
printf '%s\n' "$*" >> "__LOG__"
while [ -f "$DEV/hold.$1" ] && kill -0 "$PPID" 2>/dev/null; do sleep 0.02; done
for a in "$@"; do last="$a"; done
missing() { echo "cannot open '$1': dataset does not exist" >&2; exit 1; }
# Renames the entries of the creation order that start with $1 to start with $2.
reorder() {
  [ -f "$DEV/snapshots.order" ] || return 0
  awk -v a="$1" -v b="$2" 'index($0, a) == 1 { $0 = b substr($0, length(a) + 1) } 1' \
"$DEV/snapshots.order" > "$DEV/order.tmp" && mv "$DEV/order.tmp" "$DEV/snapshots.order"
}
# The clones of snapshot $1, comma-separated, or nothing.
clones_of() {
  find "$DEV" -name '*.origin' -exec grep -lxF "$1" {} + 2>/dev/null | sed "s|^$DEV/||; s|\.origin$||" | sort | paste -sd, -
}
case "$1" in
  list)
if [ "$3" = "-t" ] && [ "$6" = "name,clones" ]; then
  [ -e "$DEV/$last" ] || missing "$last"
  [ -f "$DEV/snapshots.order" ] || exit 0
  awk '!seen[$0]++' "$DEV/snapshots.order" | while read -r s; do
    [ -e "$DEV/$s" ] || continue
    case "$s" in "$last"@*|"$last"/*) ;; *) continue;; esac
    c=$(clones_of "$s")
    printf '%s\t%s\n' "$s" "${c:--}"
  done
  exit 0
fi
if [ "$3" = "-p" ]; then
  [ -f "$DEV/answer.space" ] && cat "$DEV/answer.space"
  exit 0
fi
if [ "$3" = "-t" ]; then
  [ -e "$DEV/$last" ] || missing "$last"
  { ls -d "$DEV/$last"@* 2>/dev/null; [ -d "$DEV/$last" ] && find "$DEV/$last" -name '*@*'; } | sed "s|^$DEV/||" | sort
  exit 0
fi
if [ "$6" = "volume" ]; then
  [ -e "$DEV/$last" ] || missing "$last"
  find "$DEV/$last" -type f -not -name '*@*' -not -name '*.origin' | sed "s|^$DEV/||" | sort
  exit 0
fi
if [ "$6" = "filesystem,volume" ]; then
  [ -e "$DEV/$last" ] || missing "$last"
  echo "$last"
  find "$DEV/$last" -mindepth 1 -maxdepth 1 -not -name '*@*' -not -name '*.origin' | sed "s|^$DEV/||" | sort
  exit 0
fi
case "$last" in *boom*) echo "cannot open '$last': permission denied" >&2; exit 1;; esac
if [ "$last" = "__POOL__" ] || [ -e "$DEV/$last" ]; then echo "$last"; exit 0; fi
missing "$last";;
  create)
case "$*" in *mountpoint=*) mkdir -p "$DEV/$last"; exit 0;; esac
if [ "$2" = "-p" ]; then mkdir -p "$DEV/$last"; exit 0; fi
size=; [ "$3" = "-V" ] && size="$4"
mkdir -p "$(dirname "$DEV/$last")"; printf '%s' "$size" > "$DEV/$last"; exit 0;;
  set)
case "$2" in volsize=*)
  [ -f "$DEV/$last" ] || missing "$last"; printf '%s' "${2#volsize=}" > "$DEV/$last";;
esac; exit 0;;
  clone)
[ -e "$DEV/$2" ] || missing "$2"
mkdir -p "$(dirname "$DEV/$3")"; cat "$DEV/$2" > "$DEV/$3" 2>/dev/null || : > "$DEV/$3"
echo "$2" > "$DEV/$3.origin"; exit 0;;
  snapshot)
shift
for t in "$@"; do
  if [ -e "$DEV/$t" ]; then echo "cannot create snapshot '$t': dataset already exists" >&2; echo "no snapshots were created" >&2; exit 1; fi
done
for t in "$@"; do
  if [ -f "$DEV/${t%@*}" ]; then cat "$DEV/${t%@*}" > "$DEV/$t"; else : > "$DEV/$t"; fi
  echo "$t" >> "$DEV/snapshots.order"
done; exit 0;;
  rename)
[ -e "$DEV/$2" ] || missing "$2"
if [ -e "$DEV/$3" ]; then echo "cannot create '$3': dataset already exists" >&2; exit 1; fi
mkdir -p "$(dirname "$DEV/$3")"; mv "$DEV/$2" "$DEV/$3"
[ -f "$DEV/$2.origin" ] && mv "$DEV/$2.origin" "$DEV/$3.origin"
for f in "$DEV/$2"@*; do [ -e "$f" ] && mv "$f" "$DEV/$3@${f##*@}"; done
find "$DEV" -name '*.origin' | while read -r f; do
  o=$(cat "$f"); case "$o" in "$2"@*) echo "$3@${o#*@}" > "$f";; esac
done
reorder "$2@" "$3@"; exit 0;;
  rollback)
[ -e "$DEV/$2" ] || missing "$2"
ds="${2%@*}"; seen=0
while read -r s; do
  [ "$s" = "$2" ] && { seen=1; continue; }
  case "$s" in "$ds"@*) if [ $seen = 1 ] && [ -e "$DEV/$s" ]; then
    echo "cannot rollback to '$2': more recent snapshots or bookmarks exist" >&2; exit 1; fi;; esac
done < "$DEV/snapshots.order"
exit 0;;
  promote)
[ -e "$DEV/$2" ] || missing "$2"
if [ -f "$DEV/$2.origin" ]; then
  o=$(cat "$DEV/$2.origin"); src="${o%@*}"; snap="${o#*@}"
  # The origin snapshot and every snapshot of the source made before it move to the
  # clone, as in ZFS; clones of those follow them.
  for s in $(awk '!seen[$0]++' "$DEV/snapshots.order" 2>/dev/null); do
    case "$s" in "$src"@*) ;; *) continue;; esac
    [ -e "$DEV/$s" ] || continue
    mv "$DEV/$s" "$DEV/$2@${s#*@}"; reorder "$s" "$2@${s#*@}"
    find "$DEV" -name '*.origin' -exec grep -lxF "$s" {} + | while read -r c; do echo "$2@${s#*@}" > "$c"; done
    [ "$s" = "$o" ] && break
  done
  # The clone takes the source's origin; the source becomes the clone's clone.
  if [ -f "$DEV/$src.origin" ]; then mv "$DEV/$src.origin" "$DEV/$2.origin"; else rm -f "$DEV/$2.origin"; fi
  echo "$2@$snap" > "$DEV/$src.origin"
fi
exit 0;;
  destroy)
if [ -f "$DEV/busy" ] && [ "$(cat "$DEV/busy")" -gt 0 ]; then
  echo $(($(cat "$DEV/busy") - 1)) > "$DEV/busy"
  echo "cannot destroy '$last': dataset is busy" >&2; exit 1
fi
case "$last" in *boom*) echo "cannot destroy '$last': permission denied" >&2; exit 1;; esac
[ -e "$DEV/$last" ] || missing "$last"
# Refused while a clone outside what goes depends on it, as in ZFS.
for f in $(find "$DEV" -name '*.origin'); do
  o=$(cat "$f"); c="${f%.origin}"
  case "$o" in "$last"|"$last"@*|"$last"/*) ;; *) continue;; esac
  case "$c" in "$DEV/$last"/*) continue;; esac
  echo "cannot destroy '$last': it has dependent clones" >&2; exit 1
done
rm -rf "${DEV:?}/${last:?}" "$DEV/$last.origin" "$DEV/$last"@*; exit 0;;
  send)
base=-; [ "$3" = "-i" ] && base="${4#@}"
if [ "$base" != - ] && [ ! -e "$DEV/${last%@*}@$base" ]; then
  echo "cannot send '$last': incremental source $base is not a snapshot of it" >&2; exit 1
fi
echo "stream ${last#*@} $base $(cat "$DEV/$last" 2>/dev/null)"; exit 0;;
  receive)
read -r _ snap base size
if [ "$base" != - ] && [ ! -e "$DEV/$last@$base" ]; then
  echo "cannot receive incremental stream: most recent snapshot of $last does not match incremental source" >&2; exit 1
fi
mkdir -p "$(dirname "$DEV/$last")"; printf '%s' "$size" > "$DEV/$last"; printf '%s' "$size" > "$DEV/$last@$snap"
echo "$last@$snap" >> "$DEV/snapshots.order"; exit 0;;
  load-key)
read -r key
if [ "$key" != "$(cat "$DEV/key" 2>/dev/null)" ]; then
  echo "Key load error: Incorrect key provided for '$last'." >&2; exit 255
fi
[ "$2" = -n ] || echo available > "$DEV/answer.keystatus"; exit 0;;
  change-key)
[ -e "$DEV/$last" ] || missing "$last"; exit 0;;
  get)
for a in "$@"; do prop="$last_but_one"; last_but_one="$a"; done
if [ -f "$DEV/answer.$prop" ]; then cat "$DEV/answer.$prop"; exit 0; fi
case "$prop" in
  origin)
    [ -e "$DEV/$last" ] || missing "$last"
    if [ -f "$DEV/$last.origin" ]; then cat "$DEV/$last.origin"; else echo "-"; fi; exit 0;;
  clones)
    [ -e "$DEV/$last" ] || missing "$last"
    find "$DEV" -name '*.origin' -exec grep -lx "$last" {} + 2>/dev/null | sed "s|^$DEV/||; s|\.origin$||" | sort | paste -sd, -
    exit 0;;
  volsize)
    [ -f "$DEV/$last" ] || missing "$last"
    cat "$DEV/$last"; echo; exit 0;;
esac
exit 0;;
esac
exit 0
"#;

/// Stand-ins for the kernel's devices and udev's links, over the fake's state: a volume's
/// device is `devs/zd<inode>`, a hard link to its file, so it stays the same device through
/// a rename and outlives a destroy until udev next looks. `zvol_id` names the volume whose
/// file a device is. Every `udevadm` call first makes the devices of new volumes (the
/// kernel's part); `settle` then links every device at its volume's name, unless
/// `udev.drop` is in the state (udev dropped the events); `trigger` links the device given,
/// or all of them, dropped or not. A device whose volume is gone loses its links and goes.
/// Each waits while `hang.udevadm` (`hang.zvol_id`) is in the state, a udevd wedged, and
/// its test process runs.
const FAKE_UDEVADM: &str = r#"#!/bin/sh
DEV="__DEV__"; LINKS="__LINKS__"; DEVS="__DEVS__"
printf 'udevadm %s\n' "$*" >> "__LOG__"
while [ -f "$DEV/hang.udevadm" ] && kill -0 "$PPID" 2>/dev/null; do sleep 0.1; done
for a in "$@"; do last="$a"; done
# Each volume's inode and name; the kernel's part: a device for each volume that has none.
find "$DEV" -mindepth 2 -type f ! -name '*@*' ! -name '*.origin' -exec ls -i {} + |
  awk -v d="$DEV/" '{ sub(d, "", $2); print $1, $2 }' > "$DEVS.$$"
trap 'rm -f "$DEVS.$$"' EXIT
while read -r i n; do [ -e "$DEVS/zd$i" ] || ln "$DEV/$n" "$DEVS/zd$i" 2>/dev/null; done < "$DEVS.$$"
name_of() { awk -v i="${1##*/zd}" '$1 == i { print $2; exit }' "$DEVS.$$"; }
# udev's part for one device: linked at its volume's name only, or gone with its volume.
link() {
  n=$(name_of "$1")
  find "$LINKS" -type l | while read -r l; do
[ "$l" -ef "$1" ] && [ "${l#$LINKS/}" != "$n" ] && rm -f "$l"
  done
  if [ -z "$n" ]; then rm -f "$1"; return 0; fi
  mkdir -p "$LINKS/${n%/*}"; ln -sfn "$1" "$LINKS/$n"
}
case "$1" in
  settle)
[ -f "$DEV/udev.drop" ] && exit 0
while read -r i n; do
  [ "$LINKS/$n" -ef "$DEVS/zd$i" ] || { mkdir -p "$LINKS/${n%/*}"; ln -sfn "$DEVS/zd$i" "$LINKS/$n"; }
done < "$DEVS.$$"
find "$LINKS" -type l | sed "s|^$LINKS/||" | awk 'NR == FNR { v[$2]; next } !($0 in v)' "$DEVS.$$" - |
  while read -r l; do rm -f "$LINKS/$l"; done
ls "$DEVS" | sed 's/^zd//' | awk 'NR == FNR { v[$1]; next } !($0 in v)' "$DEVS.$$" - |
  while read -r i; do rm -f "$DEVS/zd$i"; done;;
  trigger)
case "$last" in
  --sysname-match=*) for d in "$DEVS"/zd*; do [ -e "$d" ] && link "$d"; done;;
  *) link "$last";;
esac;;
esac
exit 0
"#;

const FAKE_ZVOL_ID: &str = r#"#!/bin/sh
DEV="__DEV__"
while [ -f "$DEV/hang.zvol_id" ] && kill -0 "$PPID" 2>/dev/null; do sleep 0.1; done
i=$(ls -i "$1" 2>/dev/null | awk '{ print $1 }')
n=$(find "$DEV" -mindepth 2 -type f ! -name '*@*' ! -name '*.origin' -exec ls -i {} + |
  awk -v i="$i" -v d="$DEV/" '$1 == i { sub(d, "", $2); print $2; exit }')
[ -n "$i" ] && [ -n "$n" ] || { echo "$1: No such device or address" >&2; exit 1; }
echo "$n"
"#;

pub(crate) struct Fake {
    dir: tempfile::TempDir,
    pub(crate) zfs: Zfs,
}

/// The fake binaries, the state and where links and devices go, before the pool is opened.
pub(crate) struct Scripts {
    dir: tempfile::TempDir,
    pub(crate) zfs: PathBuf,
    pub(crate) udevadm: PathBuf,
    pub(crate) zvol_id: PathBuf,
    pub(crate) dev: PathBuf,
    pub(crate) links: PathBuf,
    pub(crate) jail: PathBuf,
}

impl Scripts {
    pub(crate) fn new() -> Scripts {
        let dir = tempfile::tempdir().unwrap();
        // Canonical, as the links the daemon resolves are (macOS's /var is /private/var).
        let root = dir.path().canonicalize().unwrap();
        let (dev, links, devs) = (root.join("dev"), root.join("links"), root.join("devs"));
        for d in [&dev, &links, &devs] {
            std::fs::create_dir_all(d).unwrap();
        }
        let log = root.join("calls");
        let zfs = root.join("zfs");
        let udevadm = root.join("udevadm");
        let zvol_id = root.join("zvol_id");
        for (bin, script) in [
            (&zfs, FAKE),
            (&udevadm, FAKE_UDEVADM),
            (&zvol_id, FAKE_ZVOL_ID),
        ] {
            let script = script
                .replace("__DEV__", dev.to_str().unwrap())
                .replace("__LINKS__", links.to_str().unwrap())
                .replace("__DEVS__", devs.to_str().unwrap())
                .replace("__LOG__", log.to_str().unwrap())
                .replace("__POOL__", "byard");
            std::fs::write(bin, script).unwrap();
        }
        let jail = dir.path().join("jail");
        Scripts {
            dir,
            zfs,
            udevadm,
            zvol_id,
            dev,
            links,
            jail,
        }
    }

    /// The pool opened, its layout made: the image and jail filesystems in the temp dir.
    pub(crate) async fn open(self, pool: &str) -> Result<Fake> {
        let zfs = self.pool(pool).await?;
        zfs.layout(&[
            ("images", &self.dir.path().join("images")),
            ("jail", &self.jail),
        ])
        .await?;
        Ok(Fake { dir: self.dir, zfs })
    }

    /// The pool opened, nothing made.
    pub(crate) async fn pool(&self, pool: &str) -> Result<Zfs> {
        let tools = Tools {
            zfs: Tool::script(&self.zfs),
            udevadm: Tool::script(&self.udevadm),
            zvol_id: Tool::script(&self.zvol_id),
        };
        Zfs::with_paths(pool, &tools, &self.links).await
    }

    pub(crate) fn answer(&self, prop: &str, value: &str) {
        std::fs::write(self.dev.join(format!("answer.{prop}")), value).unwrap();
    }
}

impl Fake {
    pub(crate) async fn open(pool: &str) -> Result<Fake> {
        Scripts::new().open(pool).await
    }

    pub(crate) fn dev(&self) -> PathBuf {
        self.dir.path().join("dev")
    }

    /// Where udev's links are.
    pub(crate) fn links(&self) -> PathBuf {
        self.dir.path().join("links")
    }

    pub(crate) fn jail(&self) -> String {
        self.dir.path().join("jail").display().to_string()
    }

    pub(crate) fn images(&self) -> String {
        self.dir.path().join("images").display().to_string()
    }

    /// The calls so far, then forgets them.
    pub(crate) fn calls(&self) -> Vec<String> {
        let path = self.dir.path().join("calls");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        text.lines().map(String::from).collect()
    }

    pub(crate) fn answer(&self, prop: &str, value: &str) {
        std::fs::write(self.dev().join(format!("answer.{prop}")), value).unwrap();
    }
}

pub(crate) const SETTLE: &str = "udevadm settle --timeout=5";

/// Whether `dev` is the device of the fake's volume file `file`: the same inode.
pub(crate) fn device_of(dev: &Path, file: PathBuf) -> bool {
    use std::os::unix::fs::MetadataExt;
    let ino = |p: &Path| std::fs::metadata(p).unwrap().ino();
    dev.file_name().unwrap().to_str().unwrap().starts_with("zd") && ino(dev) == ino(&file)
}
