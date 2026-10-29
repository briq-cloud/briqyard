use super::*;

impl Zfs {
    /// Starts `zfs send` of a snapshot (incremental from `from` when given), raw: the blocks
    /// as the pool holds them, encrypted under its key and compressed (ADR 0035); the caller
    /// reads the stream from the child's stdout and waits for it.
    pub fn send(
        &self,
        name: &str,
        snap: &str,
        from: Option<&str>,
    ) -> Result<tokio::process::Child> {
        let target = format!("{}@{snap}", self.ds(name));
        let mut cmd = self.tools.zfs.command();
        cmd.arg("send").arg("-w");
        if let Some(f) = from {
            cmd.arg("-i").arg(format!("@{f}"));
        }
        cmd.arg(&target)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        cmd.spawn().with_context(|| format!("zfs send {target}"))
    }

    /// Starts `zfs receive` into a dataset (made or overwritten); the caller writes the stream
    /// to the child's stdin and waits for it.
    pub fn receive(&self, name: &str) -> Result<tokio::process::Child> {
        let mut cmd = self.tools.zfs.command();
        cmd.args(["receive", "-F", "-u", &self.ds(name)])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        cmd.spawn()
            .with_context(|| format!("zfs receive {}", self.ds(name)))
    }

    /// Waits for a send or receive child and turns a failure into its stderr.
    pub async fn finish(child: tokio::process::Child, what: &str) -> Result<()> {
        let out = child.wait_with_output().await.context(what.to_string())?;
        if !out.status.success() {
            return Err(anyhow!(
                "{what}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }

    /// What each filesystem and volume under `name` takes, in one call.
    pub async fn space_under(&self, name: &str) -> Result<Vec<Space>> {
        let out = self
            .run(&[
                "list",
                "-H",
                "-p",
                "-o",
                "name,volsize,usedbydataset,usedbysnapshots",
                "-r",
                "-t",
                "filesystem,volume",
                &self.ds(name),
            ])
            .await?;
        space_lines(&out, &format!("{}/", self.pool))
    }

    /// What was written to a dataset since one of its snapshots (`written@<snap>`), in bytes.
    pub async fn written_since(&self, name: &str, snap: &str) -> Result<u64> {
        let out = self
            .run(&[
                "get",
                "-H",
                "-p",
                "-o",
                "value",
                &format!("written@{snap}"),
                &self.ds(name),
            ])
            .await?;
        out.trim()
            .parse()
            .map_err(|_| anyhow!("zfs written@{snap} of {name}: {:?}", out.trim()))
    }

    pub async fn used(&self, name: &str) -> Result<u64> {
        let out = self
            .run(&["get", "-H", "-p", "-o", "value", "used", &self.ds(name)])
            .await?;
        Ok(out.trim().parse().unwrap_or(0))
    }

    pub async fn free(&self) -> Result<u64> {
        let out = self
            .run(&["get", "-H", "-p", "-o", "value", "available", &self.pool])
            .await?;
        Ok(out.trim().parse().unwrap_or(0))
    }

    /// The pool's used and free space, in one call. Unlike `free`, a value that does not
    /// parse is an error: the host's conditions are decided on it (ADR 0021).
    pub async fn pool(&self) -> Result<Pool> {
        let out = self
            .run(&[
                "get",
                "-H",
                "-p",
                "-o",
                "value",
                "used,available",
                &self.pool,
            ])
            .await?;
        let v: Vec<u64> = out
            .split_whitespace()
            .map(|v| v.parse())
            .collect::<Result<_, _>>()
            .map_err(|_| anyhow!("zfs get used,available {}: {out:?}", self.pool))?;
        match v[..] {
            [used, free] => Ok(Pool { used, free }),
            _ => Err(anyhow!("zfs get used,available {}: {out:?}", self.pool)),
        }
    }
}

/// The pool's space, in bytes: what its datasets take and what is left for them.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Pool {
    pub used: u64,
    pub free: u64,
}

impl Pool {
    pub fn size(&self) -> u64 {
        self.used + self.free
    }
}

/// What one dataset takes.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Space {
    /// Relative to the pool (`m/<id>/root`).
    pub name: String,
    /// A volume's allocated size; 0 for a filesystem.
    pub volsize: u64,
    /// What its own blocks take (`usedbydataset`).
    pub data: u64,
    /// What only its snapshots hold (`usedbysnapshots`).
    pub snapshots: u64,
}

/// `zfs list -H -p -o name,volsize,usedbydataset,usedbysnapshots` output; `-` is 0.
fn space_lines(out: &str, prefix: &str) -> Result<Vec<Space>> {
    let num = |v: &str| -> Result<u64> {
        match v {
            "-" => Ok(0),
            v => v
                .parse()
                .map_err(|_| anyhow!("zfs list: {v:?} is not a size")),
        }
    };
    let mut all = Vec::new();
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        let [name, volsize, data, snapshots] = f[..] else {
            return Err(anyhow!("zfs list: {line:?}: want four fields"));
        };
        all.push(Space {
            name: name.strip_prefix(prefix).unwrap_or(name).to_string(),
            volsize: num(volsize)?,
            data: num(data)?,
            snapshots: num(snapshots)?,
        });
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zfs::fake::Fake;

    #[tokio::test]
    async fn written_since_a_snapshot_is_a_count_or_an_error() {
        let f = Fake::open("byard").await.unwrap();
        f.answer("written@bk-1", "0\n");
        f.calls();
        assert_eq!(f.zfs.written_since("m/x/root", "bk-1").await.unwrap(), 0);
        assert_eq!(
            f.calls(),
            vec!["get -H -p -o value written@bk-1 byard/m/x/root"]
        );
        f.answer("written@bk-1", "8192\n");
        assert_eq!(f.zfs.written_since("m/x/root", "bk-1").await.unwrap(), 8192);
        // Unreadable is not "nothing written": the caller backs up rather than skip.
        f.answer("written@bk-1", "-\n");
        assert!(f.zfs.written_since("m/x/root", "bk-1").await.is_err());
    }

    #[tokio::test]
    async fn used_and_free_parse_bytes() {
        let f = Fake::open("byard").await.unwrap();
        f.answer("used", "123456789\n");
        f.answer("available", "  42 \n");
        f.calls();
        assert_eq!(f.zfs.used("m/x").await.unwrap(), 123_456_789);
        assert_eq!(f.zfs.free().await.unwrap(), 42);
        assert_eq!(
            f.calls(),
            vec![
                "get -H -p -o value used byard/m/x",
                "get -H -p -o value available byard"
            ]
        );
        // What does not parse reads as zero rather than failing a status page.
        f.answer("used", "-\n");
        assert_eq!(f.zfs.used("m/x").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn the_pool_is_read_in_one_call_and_never_guessed() {
        let f = Fake::open("byard").await.unwrap();
        f.answer("used,available", "300\n700\n");
        f.calls();
        let p = f.zfs.pool().await.unwrap();
        assert_eq!((p.used, p.free, p.size()), (300, 700, 1000));
        assert_eq!(f.calls(), vec!["get -H -p -o value used,available byard"]);
        // What does not parse is an error, not an empty pool under pressure.
        for bad in ["-\n700\n", "300\n", ""] {
            f.answer("used,available", bad);
            let err = f.zfs.pool().await.unwrap_err();
            assert!(err.to_string().contains("used,available byard"), "{err}");
        }
    }

    #[tokio::test]
    async fn space_is_read_for_every_dataset_at_once() {
        let f = Fake::open("byard").await.unwrap();
        f.answer(
            "space",
            "byard/m\t-\t24576\t0\n\
             byard/m/m_1\t-\t12288\t0\n\
             byard/m/m_1/root\t8589934592\t52428800\t1048576\n",
        );
        f.calls();
        assert_eq!(
            f.zfs.space_under("m").await.unwrap(),
            [
                Space {
                    name: "m".into(),
                    volsize: 0,
                    data: 24576,
                    snapshots: 0
                },
                Space {
                    name: "m/m_1".into(),
                    volsize: 0,
                    data: 12288,
                    snapshots: 0
                },
                Space {
                    name: "m/m_1/root".into(),
                    volsize: 8 << 30,
                    data: 50 << 20,
                    snapshots: 1 << 20
                },
            ]
        );
        assert_eq!(
            f.calls(),
            ["list -H -p -o name,volsize,usedbydataset,usedbysnapshots -r -t filesystem,volume byard/m"]
        );
        // What is not a size is an error, not a zero: a wrong figure would be reported as usage.
        assert!(space_lines("byard/m\tx\t0\t0\n", "byard/").is_err());
        assert!(space_lines("byard/m\t0\t0\n", "byard/").is_err());
        assert!(space_lines("", "byard/").unwrap().is_empty());
    }
}
