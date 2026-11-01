//! Firecracker: one process per machine, configured over its Unix socket API with a small
//! HTTP/1.1 client of our own (the requests are tiny and the socket is local).

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use briqyard_api::{self as api, guest};
use serde::Serialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::watch;

mod balloon;
mod balloon_metrics;
mod client;
mod clone;
mod incarnation;
mod process;
#[cfg(test)]
mod tests;
mod vmm;

pub use balloon::*;
pub use balloon_metrics::*;
pub use client::*;
pub use clone::*;
pub use incarnation::*;
pub use process::*;
pub use vmm::*;
