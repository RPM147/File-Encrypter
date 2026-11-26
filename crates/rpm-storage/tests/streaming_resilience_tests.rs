use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use rand::{rngs::StdRng, RngCore, SeedableRng};
use rpm_core::constants::MIN_CHUNK_SIZE;
use rpm_core::{encrypt_stream, Auth, CryptoError, EncryptOptions, KdfParams, VaultMetadata};
use rpm_storage::packager::unpack_vault_stream_selected;
use rpm_storage::{
    check_vault_integrity_with_parts_and_threads, decrypt_vault_selected_v5, decrypt_vault_v5,
    decrypt_vault_v5_with_stealth_kdf_and_threads, encrypt_sources_v5,
    encrypt_sources_v5_with_threads, extract_entry_to_memory_v5,
    extract_entry_to_memory_v5_with_stealth_kdf_and_threads, repair_vault_v5_with_threads,
    StorageError, UnpackLimits,
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

#[test]
fn uncompressed_tar_trailing_chunks_drain_and_authenticate_through_eof() {
    // Build a valid uncompressed tar archive followed by > 8 chunks of zero record padding
    // after the tar EOF marker so `unpack_vault_stream` returns before the final AEAD chunk.
    let mut builder = tar::Builder::new(Vec::new());
    let payload = b"authenticated trailing padding test";
    let mut header = tar::Header::new_gnu();
    header.set_size(payload.len() as u64);
    header.set_mode(0o600);
    builder
        .append_data(&mut header, "note.txt", &payload[..])
        .unwrap();
    let mut archive = builder.into_inner().unwrap();
    archive.resize(archive.len() + 12 * MIN_CHUNK_SIZE as usize, 0);

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("padded_tar.vault");
    let meta = VaultMetadata {
        filename: "note.txt".into(),
        source_type: "file".into(),
        original_size: payload.len() as u64,
        file_count: 1,
        created_at: String::new(),
        compressed: false,
        files: vec![],
    };
    let summary = encrypt_stream(
        &mut archive.as_slice(),
        &mut fs::File::create(&vault).unwrap(),
        &meta,
        b"DrainPw!1",
        &EncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        |_| {},
        None,
    )
    .unwrap();
    assert!(summary.chunks_written > 10);

    let auth = || Auth::Password {
        password: b"DrainPw!1",
        keyfile_hash: None,
    };
    let cancel = Arc::new(AtomicBool::new(false));

    // 1. Valid vault: drain loop must prevent BrokenPipe on full, selective, and RAM preview.
    let out_full = dir.path().join("full");
    let dec = decrypt_vault_v5(
        &vault,
        &out_full,
        auth(),
        Arc::new(|_, _| {}),
        cancel.clone(),
    )
    .expect("valid uncompressed tar with trailing zero chunks must succeed");
    assert_eq!(fs::read(&dec.output_path).unwrap(), payload);

    let out_sel = dir.path().join("sel");
    let sel = decrypt_vault_selected_v5(
        &vault,
        &out_sel,
        auth(),
        &["note.txt".into()],
        Arc::new(|_, _| {}),
        cancel.clone(),
    )
    .expect("selective extract with trailing zero chunks must succeed");
    assert_eq!(fs::read(&sel.output_path).unwrap(), payload);

    let mem = extract_entry_to_memory_v5(
        &vault,
        auth(),
        "note.txt",
        256,
        Arc::new(|_, _| {}),
        cancel.clone(),
    )
    .expect("RAM preview with trailing zero chunks must succeed");
    assert_eq!(mem.as_slice(), payload);

    // 2. Tamper final chunk tag: drain loop must keep pipe open so AEAD failure wins & rolls back.
    let mut tampered = fs::read(&vault).unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(&vault, tampered).unwrap();

    let bad_full = dir.path().join("bad_full");
    assert!(matches!(
        decrypt_vault_v5(
            &vault,
            &bad_full,
            auth(),
            Arc::new(|_, _| {}),
            cancel.clone()
        ),
        Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
    ));
    assert!(!bad_full.exists());

    let bad_sel = dir.path().join("bad_sel");
    assert!(matches!(
        decrypt_vault_selected_v5(
            &vault,
            &bad_sel,
            auth(),
            &["note.txt".into()],
            Arc::new(|_, _| {}),
            cancel.clone(),
        ),
        Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
    ));
    assert!(!bad_sel.exists());

    assert!(matches!(
        extract_entry_to_memory_v5(&vault, auth(), "note.txt", 256, Arc::new(|_, _| {}), cancel),
        Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
    ));
}

#[test]
fn gzip_bounded_pipe_parallel_aead_and_rs_round_trip_across_thread_counts() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = dir.path().join("data");
    fs::create_dir(&src_dir).unwrap();

    // Mix compressible and incompressible files totaling > 5 MiB to exercise multi-chunk
    // gzip streaming through bounded_pipe(8) + parallel AEAD + parallel RS batches.
    let mut rng = StdRng::seed_from_u64(0x621B_919E);
    let mut random_blob = vec![0u8; 3 * 1024 * 1024 + 911];
    rng.fill_bytes(&mut random_blob);
    let text_blob = b"RPM Encrypter multi-core parallel AEAD + RS streaming line.\n".repeat(40_000);
    fs::write(src_dir.join("random.bin"), &random_blob).unwrap();
    fs::write(src_dir.join("notes.txt"), &text_blob).unwrap();

    let vault = dir.path().join("compressed_rs.vault");
    let opts = EncryptOptions {
        reed_solomon: true,
        compressed: true,
        kdf: KdfParams::fast_test(),
        chunk_size: 256 * 1024,
        ..Default::default()
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let (summary, _meta) = encrypt_sources_v5_with_threads(
        std::slice::from_ref(&src_dir),
        &vault,
        b"GzipPipe!1",
        &opts,
        8,
        Arc::new(|_, _| {}),
        cancel.clone(),
        |_| {},
    )
    .unwrap();
    assert!(summary.chunks_written > 10);

    // Corrupt a 512-byte sector in the middle of the compressed RS vault.
    let mut wire = fs::read(&vault).unwrap();
    let mid_off = 48 + 30 * 16_320 + 25;
    for b in &mut wire[mid_off..mid_off + 512] {
        *b ^= 0x5A;
    }
    fs::write(&vault, &wire).unwrap();

    for threads in [1usize, 4, 8, rpm_core::MAX_PIPELINE_THREADS] {
        let (irep, _) = check_vault_integrity_with_parts_and_threads(&vault, threads).unwrap();
        assert!(irep.ok);
        assert_eq!(irep.rs_repaired_bytes, 512);

        let auth = Auth::Password {
            password: b"GzipPipe!1",
            keyfile_hash: None,
        };
        let preview = extract_entry_to_memory_v5_with_stealth_kdf_and_threads(
            &vault,
            auth,
            "data/notes.txt",
            text_blob.len() + 1024,
            &KdfParams::fast_test(),
            threads,
            Arc::new(|_, _| {}),
            cancel.clone(),
        )
        .unwrap();
        assert_eq!(preview.as_slice(), text_blob.as_slice());

        let out_dir = dir.path().join(format!("out_{threads}"));
        let dec = decrypt_vault_v5_with_stealth_kdf_and_threads(
            &vault,
            &out_dir,
            Auth::Password {
                password: b"GzipPipe!1",
                keyfile_hash: None,
            },
            None,
            &KdfParams::fast_test(),
            threads,
            Arc::new(|_, _| {}),
            cancel.clone(),
        )
        .unwrap();
        assert_eq!(
            fs::read(dec.output_path.join("random.bin")).unwrap(),
            random_blob
        );
        assert_eq!(
            fs::read(dec.output_path.join("notes.txt")).unwrap(),
            text_blob
        );
    }

    let repaired_path = dir.path().join("repaired.vault");
    let rrep = repair_vault_v5_with_threads(&vault, Some(&repaired_path), 8, cancel).unwrap();
    assert_eq!(rrep.repaired_bytes, 512);
    let (clean_rep, _) = check_vault_integrity_with_parts_and_threads(&repaired_path, 4).unwrap();
    assert!(clean_rep.ok);
    assert_eq!(clean_rep.rs_repaired_bytes, 0);
}
