//! Durable receiver state: an append-only JSONL journal plus an atomic
//! checkpoint file. Every accepted batch is journaled and fsynced before the
//! signed receipt is returned, so a response-loss retry can be answered
//! idempotently from durable state.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Checkpoint {
    pub deployment_id: String,
    /// "genesis" or "batch".
    pub checkpoint_kind: String,
    pub last_sequence: i64,
    /// Chain hash at `last_sequence` (genesis: the empty-chain head hash).
    pub last_hash: String,
    pub batch_digest: String,
    pub accepted_batches: i64,
    pub accepted_events: i64,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub struct Store {
    dir: PathBuf,
    checkpoint: Option<Checkpoint>,
}

impl Store {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).context("receiver data directory")?;
        let path = dir.join("checkpoint.json");
        let checkpoint = if path.exists() {
            let mut content = String::new();
            File::open(&path)
                .context("read checkpoint")?
                .read_to_string(&mut content)
                .context("read checkpoint")?;
            Some(serde_json::from_str(&content).context("parse checkpoint")?)
        } else {
            None
        };
        Ok(Self { dir, checkpoint })
    }

    pub fn checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoint.as_ref()
    }

    /// Persist the journal entry and advance the checkpoint, fsyncing the
    /// journal, the checkpoint file and the directory before returning.
    pub fn record(&mut self, journal_entry: &[u8], next: Checkpoint) -> Result<()> {
        let journal_path = self.dir.join("journal.jsonl");
        let mut journal = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal_path)
            .context("open journal")?;
        journal.write_all(journal_entry)?;
        journal.write_all(b"\n")?;
        journal.sync_data().context("fsync journal")?;
        drop(journal);

        let checkpoint_path = self.dir.join("checkpoint.json");
        let tmp_path = self.dir.join("checkpoint.json.tmp");
        let mut tmp = File::create(&tmp_path).context("create checkpoint tmp")?;
        tmp.write_all(&serde_json::to_vec(&next)?)?;
        tmp.sync_all().context("fsync checkpoint tmp")?;
        drop(tmp);
        std::fs::rename(&tmp_path, &checkpoint_path).context("rename checkpoint")?;
        fsync_dir(&self.dir)?;
        self.checkpoint = Some(next);
        Ok(())
    }
}

fn fsync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .context("fsync receiver directory")
}
