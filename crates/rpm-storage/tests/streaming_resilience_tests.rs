use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use rand::{rngs::StdRng, RngCore, SeedableRng};
use rpm_core::{Auth, EncryptOptions, KdfParams};
use rpm_storage::packager::unpack_vault_stream_selected;
use rpm_storage::{
    decrypt_vault_selected_v5, decrypt_vault_v5, encrypt_sources_v5, StorageError, UnpackLimits,
};

fn only_entry(dir: &Path) -> std::path::PathBuf {
    let entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "unexpected files under {}", dir.display());
    entries.into_iter().next().unwrap()
}

#[test]
fn late_stream_errors_leave_existing_and_new_destinations_clean() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("bundle");
    fs::create_dir(&source).unwrap();
    let mut bytes = vec![0; 384 * 1024 + 37];
    StdRng::seed_from_u64(412).fill_bytes(&mut bytes);
    fs::write(source.join("large.bin"), &bytes).unwrap();
    fs::write(source.join("note.txt"), b"small entry").unwrap();

    let existing = dir.path().join("existing");
    let prior = existing.join("bundle");
    fs::create_dir_all(&prior).unwrap();
    let sentinel = prior.join("note.txt");
    fs::write(&sentinel, b"prior contents").unwrap();
    let fresh = dir.path().join("fresh");
    let vault = dir.path().join("bundle.vault");
    let cancel = Arc::new(AtomicBool::new(false));
    let auth = || Auth::Password {
        password: b"test",
        keyfile_hash: None,
    };
    for compressed in [false, true] {
        let options = EncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: rpm_core::constants::MIN_CHUNK_SIZE,
            compressed,
            ..Default::default()
        };
        let (summary, _) = encrypt_sources_v5(
            std::slice::from_ref(&source),
            &vault,
            b"test",
            &options,
            Arc::new(|_, _| {}),
            cancel.clone(),
            |_| {},
        )
        .unwrap();
        assert!(summary.chunks_written > 8);
        let good = fs::read(&vault).unwrap();
        for damaged in [&good[..good.len() - 1], &[good.as_slice(), &[0]].concat()] {
            fs::write(&vault, damaged).unwrap();
            for destination in [&existing, &fresh] {
                let full = decrypt_vault_v5(
                    &vault,
                    destination,
                    auth(),
                    Arc::new(|_, _| {}),
                    cancel.clone(),
                );
                assert!(full.is_err());
                let selected = decrypt_vault_selected_v5(
                    &vault,
                    destination,
                    auth(),
                    &["bundle/large.bin".into()],
                    Arc::new(|_, _| {}),
                    cancel.clone(),
                );
                assert!(selected.is_err());
                assert!(!fresh.exists());
                assert_eq!(only_entry(&existing), prior);
                assert_eq!(only_entry(&prior), sentinel);
                assert_eq!(fs::read(&sentinel).unwrap(), b"prior contents");
            }
        }
        // A clean retry through the same pipeline must still restore both files.
        fs::write(&vault, good).unwrap();
        let restored =
            decrypt_vault_v5(&vault, &fresh, auth(), Arc::new(|_, _| {}), cancel.clone()).unwrap();
        assert_eq!(restored.files_extracted, 2);
        assert_eq!(
            fs::read(restored.output_path.join("large.bin")).unwrap(),
            bytes
        );
        assert_eq!(
            fs::read(restored.output_path.join("note.txt")).unwrap(),
            b"small entry"
        );
        fs::remove_dir_all(&fresh).unwrap();
    }
}

#[test]
fn selected_extraction_counts_skipped_members_toward_the_stream_limit() {
    let mut archive = tar::Builder::new(Vec::new());
    for name in ["skipped", "selected"] {
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o600);
        archive
            .append_data(&mut header, name, &b"entry"[..])
            .unwrap();
    }
    let data = archive.into_inner().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result = unpack_vault_stream_selected(
        data.as_slice(),
        dir.path(),
        false,
        &["selected".into()],
        UnpackLimits {
            max_total_bytes: 9,
            ..Default::default()
        },
        None,
    );
    assert!(matches!(result, Err(StorageError::LimitExceeded(_))));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}
