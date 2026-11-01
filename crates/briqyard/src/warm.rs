use super::*;

#[derive(Subcommand)]
pub(super) enum WarmCmd {
    /// List paused template pools and their actual slot counts.
    Ls { namespace: String },
    /// Set the desired ready count of one immutable qualified template.
    Put {
        namespace: String,
        name: String,
        #[arg(long)]
        source: String,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        desired: u16,
    },
    /// Claim an existing paused slot; empty returns pool_empty, without a fresh boot.
    Claim {
        namespace: String,
        pool: String,
        #[arg(long)]
        name: String,
        /// Reuse exactly this key after a timeout; it cannot consume a second slot.
        #[arg(long)]
        request_id: String,
        /// Return pool_empty immediately when the allocation turn is busy or empty.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        fail_fast: bool,
    },
    /// Drain unused slots. Already claimed machines remain ordinary owned machines.
    Rm { namespace: String, name: String },
}

pub(super) async fn run(c: &Client, cmd: WarmCmd) -> Result<()> {
    use reqwest::Method;
    let validate = |namespace: &str, name: Option<&str>| -> Result<()> {
        if !api::valid_id(namespace) || name.is_some_and(|n| !api::valid_name(n)) {
            bail!("namespace/pool name is invalid");
        }
        Ok(())
    };
    match cmd {
        WarmCmd::Ls { namespace } => {
            validate(&namespace, None)?;
            print_json(
                &c.call::<Vec<api::WarmPool>>(
                    Method::GET,
                    &format!("/v1/namespaces/{namespace}/warm-pools"),
                    NONE,
                )
                .await?,
            );
        }
        WarmCmd::Put {
            namespace,
            name,
            source,
            snapshot,
            desired,
        } => {
            validate(&namespace, Some(&name))?;
            let request = api::PutWarmPoolRequest {
                source_machine: source,
                snapshot,
                desired,
            };
            print_json(
                &c.call::<api::WarmPool>(
                    Method::PUT,
                    &format!("/v1/namespaces/{namespace}/warm-pools/{name}"),
                    Some(&request),
                )
                .await?,
            );
        }
        WarmCmd::Claim {
            namespace,
            pool,
            name,
            request_id,
            fail_fast,
        } => {
            validate(&namespace, Some(&pool))?;
            let request = api::ClaimWarmPoolRequest {
                name,
                request_id,
                fail_fast,
            };
            print_json(
                &c.call::<api::Machine>(
                    Method::POST,
                    &format!("/v1/namespaces/{namespace}/warm-pools/{pool}/claims"),
                    Some(&request),
                )
                .await?,
            );
        }
        WarmCmd::Rm { namespace, name } => {
            validate(&namespace, Some(&name))?;
            c.raw(
                Method::DELETE,
                &format!("/v1/namespaces/{namespace}/warm-pools/{name}"),
                NONE,
            )
            .await?;
        }
    }
    Ok(())
}
