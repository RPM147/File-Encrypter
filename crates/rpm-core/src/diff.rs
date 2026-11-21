//! Compare authenticated file manifests in memory, from A to B.
use std::collections::BTreeMap;

use crate::{CryptoError, FileManifestEntry, VaultMetadata};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangedEntry {
    pub before: FileManifestEntry,
    pub after: FileManifestEntry,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct VaultDiff {
    pub added: Vec<FileManifestEntry>,
    pub removed: Vec<FileManifestEntry>,
    pub changed: Vec<ChangedEntry>,
    pub unchanged: Vec<FileManifestEntry>,
}

fn index(metadata: &VaultMetadata) -> Result<BTreeMap<&str, &FileManifestEntry>, CryptoError> {
    let mut entries = BTreeMap::new();
    for entry in &metadata.files {
        if entries.insert(entry.path.as_str(), entry).is_some() {
            return Err(CryptoError::InvalidFormat(format!(
                "duplicate manifest path: {}",
                entry.path
            )));
        }
    }
    Ok(entries)
}

/// Match exact archive paths. Each category is ordered lexicographically by path.
pub fn diff_metadata(a: &VaultMetadata, b: &VaultMetadata) -> Result<VaultDiff, CryptoError> {
    let mut remaining = index(b)?;
    let mut diff = VaultDiff::default();
    for (path, before) in index(a)? {
        match remaining.remove(path) {
            None => diff.removed.push(before.clone()),
            Some(after) if before == after => diff.unchanged.push(after.clone()),
            Some(after) => diff.changed.push(ChangedEntry {
                before: before.clone(),
                after: after.clone(),
            }),
        }
    }
    diff.added.extend(remaining.into_values().cloned());
    Ok(diff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_legacy_timestamp_compares_as_zero() {
        let old: VaultMetadata = serde_json::from_value(serde_json::json!({
            "filename": "a", "source_type": "file", "original_size": 1, "file_count": 1,
            "created_at": "", "compressed": false, "files": [{"path":"a", "size":1}]
        }))
        .unwrap();
        let mut new = old.clone();
        new.files[0].modified_unix = 42;
        let diff = diff_metadata(&old, &new).unwrap();
        assert_eq!(diff.changed[0].before.modified_unix, 0);
        assert_eq!(diff.changed[0].after.modified_unix, 42);
    }
}
