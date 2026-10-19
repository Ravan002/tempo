//! On-disk record of outstanding preconfirmations, so a restarted sequencer keeps its promises.
//!
//! Two append-only files alternate by the parity of the block a batch will be included in:
//! entries for block `n` go to file `n % 2`. Once block `n` is built, every entry in file
//! `(n + 1) % 2` belongs to a block that is already built, so that file is truncated and reused
//! for block `n + 1`. Writes are not synced; a host failure is covered by replication to the
//! other sequencers.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read as _, Write as _},
    path::Path,
};

const ENTRY_HEADER_LEN: usize = 8 + 4;

/// A journaled transaction and the block number promised for it.
pub(super) struct Entry {
    pub(super) include_by: u64,
    pub(super) transaction: Vec<u8>,
}

pub(super) struct Journal {
    files: [File; 2],
    /// Highest block each file holds entries for.
    generations: [u64; 2],
}

impl Journal {
    /// Opens or creates the journal in `directory` and returns its entries ordered by promised
    /// block, then by write order. A partially written trailing entry is discarded.
    pub(super) fn open(directory: &Path) -> io::Result<(Self, Vec<Entry>)> {
        std::fs::create_dir_all(directory)?;
        let mut entries = Vec::new();
        let mut generations = [0; 2];
        let mut open = |slot: usize| -> io::Result<File> {
            let mut file = OpenOptions::new()
                .create(true)
                .read(true)
                .append(true)
                .open(directory.join(format!("preconfirmations.{slot}")))?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let mut rest = bytes.as_slice();
            while let Some((header, body)) = rest.split_at_checked(ENTRY_HEADER_LEN) {
                let include_by = u64::from_be_bytes(header[..8].try_into().expect("8 bytes"));
                let len = u32::from_be_bytes(header[8..].try_into().expect("4 bytes")) as usize;
                let Some((transaction, next)) = body.split_at_checked(len) else {
                    break;
                };
                generations[slot] = generations[slot].max(include_by);
                entries.push(Entry {
                    include_by,
                    transaction: transaction.to_vec(),
                });
                rest = next;
            }
            // Drop a partially written entry so later appends stay readable.
            file.set_len((bytes.len() - rest.len()) as u64)?;
            Ok(file)
        };
        let files = [open(0)?, open(1)?];
        entries.sort_by_key(|entry| entry.include_by);
        Ok((Self { files, generations }, entries))
    }

    /// Appends entries to the file for block `slot`.
    pub(super) fn append<'a>(
        &mut self,
        slot: u64,
        entries: impl IntoIterator<Item = (u64, &'a [u8])>,
    ) -> io::Result<()> {
        let mut bytes = Vec::new();
        for (include_by, transaction) in entries {
            bytes.extend_from_slice(&include_by.to_be_bytes());
            bytes.extend_from_slice(&(transaction.len() as u32).to_be_bytes());
            bytes.extend_from_slice(transaction);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let index = (slot % 2) as usize;
        self.files[index].write_all(&bytes)?;
        self.generations[index] = self.generations[index].max(slot);
        Ok(())
    }

    /// Empties the file for block `slot`.
    pub(super) fn truncate(&mut self, slot: u64) -> io::Result<()> {
        let index = (slot % 2) as usize;
        self.files[index].set_len(0)?;
        self.generations[index] = 0;
        Ok(())
    }

    /// Empties the file for block `slot` if it only holds entries for blocks up to
    /// `canonical_head`, which are already built.
    pub(super) fn retire_built(&mut self, slot: u64, canonical_head: u64) -> io::Result<()> {
        let generation = self.generations[(slot % 2) as usize];
        if generation < slot && generation <= canonical_head {
            self.truncate(slot)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reopening_returns_live_entries_in_promise_order() {
        let directory = std::env::temp_dir().join(format!(
            "zone-preconfirmation-journal-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&directory);

        let (mut journal, entries) = Journal::open(&directory).unwrap();
        assert!(entries.is_empty());
        journal.append(5, [(5, &b"a"[..]), (5, b"bb")]).unwrap();
        journal.append(4, [(4, &b"c"[..])]).unwrap();
        // Building block 5 retires block 4's file, which then receives block 6.
        journal.truncate(6).unwrap();
        journal.append(6, [(6, &b"d"[..])]).unwrap();
        // A crash mid-write leaves a truncated trailing entry.
        journal.files[1].write_all(&7u64.to_be_bytes()).unwrap();
        drop(journal);

        let (mut journal, _) = Journal::open(&directory).unwrap();
        journal.append(7, [(7, &b"e"[..])]).unwrap();
        drop(journal);

        let (_, entries) = Journal::open(&directory).unwrap();
        let entries: Vec<_> = entries
            .iter()
            .map(|entry| (entry.include_by, entry.transaction.as_slice()))
            .collect();
        assert_eq!(entries, [(5, &b"a"[..]), (5, b"bb"), (6, b"d"), (7, b"e")]);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
