use rpm_core::{diff_metadata, FileManifestEntry, VaultMetadata};

fn manifest(items: &[(&str, u64, u64)]) -> VaultMetadata {
    VaultMetadata {
        filename: "vault".into(),
        source_type: "folder".into(),
        original_size: 0,
        file_count: items.len() as u64,
        created_at: String::new(),
        compressed: false,
        files: items
            .iter()
            .map(|&(path, size, modified_unix)| FileManifestEntry {
                path: path.into(),
                size,
                modified_unix,
            })
            .collect(),
    }
}

#[test]
fn diff_is_sorted_directional_and_metadata_only() {
    let a = manifest(&[
        ("timestamp", 1, 2),
        ("gone", 5, 5),
        ("same", 1, 3),
        ("size", 3, 2),
    ]);
    let mut b = manifest(&[
        ("z", 1, 1),
        ("timestamp", 1, 4),
        ("a", 9, 1),
        ("same", 1, 3),
        ("size", 1, 2),
    ]);
    let diff = diff_metadata(&a, &b).unwrap();
    assert_eq!(diff.added, [b.files[2].clone(), b.files[0].clone()]);
    assert_eq!(diff.removed, [a.files[1].clone()]);
    assert_eq!(diff.unchanged, [a.files[2].clone()]);
    assert_eq!(diff.changed.len(), 2);
    assert_eq!(diff.changed[0].before, a.files[3]);
    assert_eq!(diff.changed[0].after, b.files[4]);
    assert_eq!(diff.changed[1].after, b.files[1]);
    b.files.reverse();
    assert_eq!(diff, diff_metadata(&a, &b).unwrap());
    assert!(diff_metadata(&manifest(&[]), &manifest(&[]))
        .unwrap()
        .added
        .is_empty());
}

#[test]
fn duplicate_manifest_paths_are_ambiguous() {
    let duplicate = manifest(&[("a", 1, 0), ("a", 2, 0)]);
    let empty = manifest(&[]);
    assert!(diff_metadata(&duplicate, &empty).is_err());
    assert!(diff_metadata(&empty, &duplicate).is_err());
}
