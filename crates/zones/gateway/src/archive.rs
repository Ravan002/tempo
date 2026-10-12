//! Independent durable history. Publication precedes contiguous watermark advancement.
use crate::store::ArchivedEvent;
use alloy_primitives::B256;
use eyre::{Context, Result, bail};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub(crate) struct DirectoryArchive {
    root: PathBuf,
    domain: B256,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Watermark {
    pub offset: u64,
    pub hash: B256,
    pub domain: B256,
}

impl DirectoryArchive {
    pub(crate) fn new(root: &Path, domain: B256) -> Result<Self> {
        let root = root.join(alloy_primitives::hex::encode(domain));
        fs::create_dir_all(&root)?;
        File::open(&root)?.sync_all()?;
        if let Some(parent) = root.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self { root, domain })
    }
    fn locked(&self, exclusive: bool) -> Result<File> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join("archive.lock"))?;
        if exclusive {
            FileExt::lock_exclusive(&file)?;
        } else {
            FileExt::lock_shared(&file)?;
        }
        Ok(file)
    }
    fn event_path(&self, offset: u64) -> PathBuf {
        self.root.join(format!("{offset:020}.json"))
    }
    fn read_watermark(&self) -> Result<Watermark> {
        match fs::read(self.root.join("watermark.json")) {
            Ok(bytes) => {
                let mark: Watermark = serde_json::from_slice(&bytes)?;
                if mark.domain != self.domain {
                    bail!("archive domain mismatch");
                }
                Ok(mark)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Watermark {
                offset: 0,
                hash: B256::ZERO,
                domain: self.domain,
            }),
            Err(e) => Err(e.into()),
        }
    }
    fn read_event(&self, offset: u64) -> Result<ArchivedEvent> {
        let bytes = fs::read(self.event_path(offset)).wrap_err("archived event missing")?;
        let event: ArchivedEvent = serde_json::from_slice(&bytes)?;
        if event.offset != offset || event.domain_key != self.domain {
            bail!("archive event identity mismatch");
        }
        event.validate_hash()?;
        Ok(event)
    }
    fn temp_path(&self, kind: &str) -> PathBuf {
        self.root.join(format!(".{kind}.{}", uuid::Uuid::new_v4()))
    }
    fn clean_staging(&self) -> Result<()> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if (name.starts_with(".event.") || name.starts_with(".watermark."))
                && entry.file_type()?.is_file()
            {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
    fn publish_event(&self, event: &ArchivedEvent) -> Result<()> {
        let bytes = serde_json::to_vec(event)?;
        let final_path = self.event_path(event.offset);
        if final_path.exists() {
            if fs::read(&final_path)? != bytes {
                bail!("conflicting archive event at {}", event.offset);
            }
            return Ok(());
        }
        let tmp = self.temp_path("event");
        let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        match fs::hard_link(&tmp, &final_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if fs::read(&final_path)? != bytes {
                    let _ = fs::remove_file(&tmp);
                    bail!("conflicting archive event at {}", event.offset);
                }
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e.into());
            }
        }
        fs::remove_file(tmp)?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn write_watermark(&self, mark: &Watermark) -> Result<()> {
        let tmp = self.temp_path("watermark");
        let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        file.write_all(&serde_json::to_vec(mark)?)?;
        file.sync_all()?;
        fs::rename(tmp, self.root.join("watermark.json"))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    pub(crate) fn publish(&self, events: &[ArchivedEvent]) -> Result<Watermark> {
        let _lock = self.locked(true)?;
        self.clean_staging()?;
        let mut mark = self.read_watermark()?;
        if mark.offset > 0 && self.read_event(mark.offset)?.hash != mark.hash {
            bail!("archive watermark hash mismatch");
        }
        for event in events {
            event.validate_hash()?;
            if event.domain_key != self.domain {
                bail!("archive domain mismatch");
            }
            if event.offset <= mark.offset {
                if self.read_event(event.offset)?.hash != event.hash {
                    bail!("archive and database history diverge");
                }
                continue;
            }
            if event.offset
                != mark
                    .offset
                    .checked_add(1)
                    .ok_or_else(|| eyre::eyre!("archive offset overflow"))?
                || event.previous_hash != mark.hash
            {
                bail!("archive history gap");
            }
            self.publish_event(event)?;
            mark = Watermark {
                offset: event.offset,
                hash: event.hash,
                domain: self.domain,
            };
            self.write_watermark(&mark)?;
        }
        Ok(mark)
    }
    pub(crate) fn covered(&self) -> Result<(Watermark, Vec<ArchivedEvent>)> {
        let _lock = self.locked(false)?;
        let mark = self.read_watermark()?;
        let mut events = Vec::new();
        let mut previous = B256::ZERO;
        for offset in 1..=mark.offset {
            let event = self.read_event(offset)?;
            if event.previous_hash != previous {
                bail!("archive history hash gap");
            }
            previous = event.hash;
            events.push(event);
        }
        if previous != mark.hash {
            bail!("archive watermark hash mismatch");
        }
        Ok((mark, events))
    }
}
