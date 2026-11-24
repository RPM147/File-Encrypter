use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rpm_core::constants::MIN_CHUNK_SIZE;
use rpm_core::{
    entropy_to_mnemonic, generate_recovery_entropy, hash_keyfile_reader,
    inspect_header_seekable_with_kdf, mnemonic_to_entropy, Auth, EncryptOptions,
    HiddenEncryptOptions, KdfParams,
};
use rpm_storage::{
    check_vault_integrity, check_vault_integrity_with_parts, decrypt_vault_selected_v5,
    decrypt_vault_v5, decrypt_vault_v5_with_stealth_kdf, discover_split_parts,
    encrypt_hidden_sources_v5, encrypt_hidden_sources_v5_split, encrypt_sources_v5,
    encrypt_sources_v5_split, extract_entry_to_memory_v5, is_vault_or_split_filename,
    join_vault_parts, open_vault_reader, parse_split_part_path, rekey_vault_v5, repair_vault_v5,
    split_part_path, split_vault_file, unique_split_base, vault_display_stem, EncryptProfile,
    SplitDiscoveryCache, SplitVolumePart, SplitVolumeReader, SplitVolumeSet, StorageError,
    MIN_SPLIT_PART_SIZE,
};

fn deterministic_bytes(len: usize, seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u32 = u32::from(seed).wrapping_mul(0x9E37_79B1) ^ 0x1357_9BDF;
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state & 0xFF) as u8);
    }
    out
}

fn has_temp_artifacts(dir: &Path) -> bool {
    fs::read_dir(dir).unwrap().any(|entry| {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        name.starts_with(".rpm_tmp_") || name.starts_with(".rpm_bak_") || name.ends_with(".part")
    })
}

#[test]
fn split_path_parsing_stems_and_non_split_numeric_extensions() {
    assert_eq!(
        parse_split_part_path(Path::new("Archive.vault.001")),
        Some((PathBuf::from("Archive.vault"), 1))
    );
    assert_eq!(
        parse_split_part_path(Path::new("/tmp/Archive.vault.042")),
        Some((PathBuf::from("/tmp/Archive.vault"), 42))
    );
    assert_eq!(
        parse_split_part_path(Path::new("Archive.vault.1000")),
        Some((PathBuf::from("Archive.vault"), 1000))
    );
    // Non-canonical or too-short suffixes must be rejected
    assert_eq!(parse_split_part_path(Path::new("Archive.vault.000")), None);
    assert_eq!(parse_split_part_path(Path::new("Archive.vault.01")), None);
    assert_eq!(parse_split_part_path(Path::new("Archive.vault.0001")), None);
    assert_eq!(parse_split_part_path(Path::new("Archive.vault")), None);

    assert!(is_vault_or_split_filename(Path::new("foo.vault")));
    assert!(is_vault_or_split_filename(Path::new("foo.VAULT.001")));
    assert!(is_vault_or_split_filename(Path::new("foo.vault.012")));
    assert!(!is_vault_or_split_filename(Path::new("report.2026")));
    assert!(!is_vault_or_split_filename(Path::new("opaque.bin.001")));

    assert_eq!(vault_display_stem(Path::new("Archive.vault")), "Archive");
    assert_eq!(
        vault_display_stem(Path::new("Archive.vault.001")),
        "Archive"
    );
    assert_eq!(
        vault_display_stem(Path::new("Archive.vault.007")),
        "Archive"
    );
    assert_eq!(vault_display_stem(Path::new("stealth.bin.001")), "stealth");

    // Ordinary file ending in `.2026` without `.001` companion must NOT be treated as split
    let dir = tempfile::tempdir().unwrap();
    let numeric_file = dir.path().join("report.2026");
    fs::write(&numeric_file, b"ordinary annual report").unwrap();
    assert_eq!(discover_split_parts(&numeric_file).unwrap(), None);

    // unique_split_base avoids colliding with existing `.001` without falsely dodging plain `.vault`
    let base = dir.path().join("backup.vault");
    fs::write(&base, b"single").unwrap();
    assert_eq!(unique_split_base(&base), base);
    fs::write(split_part_path(&base, 1), b"part1").unwrap();
    assert_eq!(unique_split_base(&base), dir.path().join("backup_1.vault"));
}

#[test]
fn split_volume_reader_seek_cross_boundary_and_zero_byte_part() {
    let dir = tempfile::tempdir().unwrap();
    let p1 = dir.path().join("data.bin.001");
    let p2 = dir.path().join("data.bin.002");
    let p3 = dir.path().join("data.bin.003");
    let p4 = dir.path().join("data.bin.004");

    let b1 = deterministic_bytes(100, 1);
    let b2: Vec<u8> = Vec::new(); // zero-byte part edge case
    let b3 = deterministic_bytes(73, 2);
    let b4 = deterministic_bytes(45, 3);
    fs::write(&p1, &b1).unwrap();
    fs::write(&p2, &b2).unwrap();
    fs::write(&p3, &b3).unwrap();
    fs::write(&p4, &b4).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(&b1);
    expected.extend_from_slice(&b2);
    expected.extend_from_slice(&b3);
    expected.extend_from_slice(&b4);

    let set = SplitVolumeSet {
        base: dir.path().join("data.bin"),
        parts: vec![
            SplitVolumePart {
                path: p1,
                len: b1.len() as u64,
            },
            SplitVolumePart { path: p2, len: 0 },
            SplitVolumePart {
                path: p3,
                len: b3.len() as u64,
            },
            SplitVolumePart {
                path: p4,
                len: b4.len() as u64,
            },
        ],
        total_len: expected.len() as u64,
    };

    let mut reader = SplitVolumeReader::new(set);
    let mut full = Vec::new();
    reader.read_to_end(&mut full).unwrap();
    assert_eq!(full, expected);

    // Seek backwards across part boundary and read slice spanning p1 -> (empty p2) -> p3 -> p4
    assert_eq!(reader.seek(SeekFrom::Start(90)).unwrap(), 90);
    let mut span = vec![0u8; 95];
    reader.read_exact(&mut span).unwrap();
    assert_eq!(span, expected[90..185]);

    // Seek from End and Current
    assert_eq!(
        reader.seek(SeekFrom::End(-20)).unwrap(),
        expected.len() as u64 - 20
    );
    let mut tail = Vec::new();
    reader.read_to_end(&mut tail).unwrap();
    assert_eq!(tail, expected[expected.len() - 20..]);

    assert_eq!(
        reader.seek(SeekFrom::Current(-10)).unwrap(),
        expected.len() as u64 - 10
    );
    assert!(reader.seek(SeekFrom::Start(0)).is_ok());
    assert!(reader.seek(SeekFrom::Current(-1)).is_err());
    assert!(reader
        .seek(SeekFrom::End(-(expected.len() as i64) - 1))
        .is_err());
}

#[test]
fn standard_split_encrypt_virtual_read_preview_selective_rekey_and_gap_detection() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = dir.path().join("src");
    fs::create_dir_all(src_dir.join("sub")).unwrap();
    // Incompressible random-like payloads force >=3 parts at 64 KiB each
    let blob_a = deterministic_bytes(110 * 1024, 11);
    let blob_b = deterministic_bytes(95 * 1024, 22);
    let note_txt = b"Split volume virtual RAM preview note!";
    fs::write(src_dir.join("blob_a.bin"), &blob_a).unwrap();
    fs::write(src_dir.join("sub/blob_b.bin"), &blob_b).unwrap();
    fs::write(src_dir.join("note.txt"), note_txt).unwrap();

    let out_dir = dir.path().join("out");
    fs::create_dir(&out_dir).unwrap();
    let base = out_dir.join("Archive.vault");
    let cancel = Arc::new(AtomicBool::new(false));
    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };

    let (_summary, meta, parts) = encrypt_sources_v5_split(
        &[
            src_dir.join("blob_a.bin"),
            src_dir.join("note.txt"),
            src_dir.join("sub"),
        ],
        &base,
        MIN_SPLIT_PART_SIZE,
        b"SplitPass!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(meta.file_count, 3);
    assert!(parts.len() >= 3, "expected >=3 parts, got {}", parts.len());
    for part in &parts[..parts.len() - 1] {
        assert_eq!(fs::metadata(part).unwrap().len(), MIN_SPLIT_PART_SIZE);
    }
    assert!(!has_temp_artifacts(&out_dir));

    // Integrity check works from both .001 and middle part .002
    let rep1 = check_vault_integrity(&parts[0]).unwrap();
    let rep2 = check_vault_integrity(&parts[1]).unwrap();
    assert!(rep1.ok && !rep1.sha256_only);
    assert_eq!(rep1.sha256_hex, rep2.sha256_hex);
    assert_eq!(rep1.file_size, rep2.file_size);

    // Header inspect works via open_vault_reader
    let mut vr = open_vault_reader(&parts[0]).unwrap();
    assert!(vr.is_split());
    assert_eq!(vr.part_count(), parts.len());
    let info = inspect_header_seekable_with_kdf(
        &mut vr,
        Auth::Password {
            password: b"SplitPass!1",
            keyfile_hash: None,
        },
        &KdfParams::fast_test(),
    )
    .unwrap();
    assert_eq!(info.metadata.file_count, 3);
    drop(vr);

    // RAM-only preview reads virtually across split parts
    let previewed = extract_entry_to_memory_v5(
        &parts[0],
        Auth::Password {
            password: b"SplitPass!1",
            keyfile_hash: None,
        },
        "note.txt",
        1024 * 1024,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(&*previewed, note_txt);

    // Selective extraction works virtually across split parts
    let sel_out = dir.path().join("sel_out");
    let sel_summary = decrypt_vault_selected_v5(
        &parts[1],
        &sel_out,
        Auth::Password {
            password: b"SplitPass!1",
            keyfile_hash: None,
        },
        &["sub/blob_b.bin".into()],
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(sel_summary.files_extracted, 1);
    assert_eq!(fs::read(sel_out.join("sub/blob_b.bin")).unwrap(), blob_b);

    // Full decrypt uses clean display stem (`Archive`, NOT `Archive.vault`)
    let dec_out = dir.path().join("dec_out");
    let dec_summary = decrypt_vault_v5(
        &parts[0],
        &dec_out,
        Auth::Password {
            password: b"SplitPass!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(dec_summary.files_extracted, 3);
    assert_eq!(dec_summary.output_path, dec_out.join("Archive"));
    assert_eq!(
        fs::read(dec_out.join("Archive/blob_a.bin")).unwrap(),
        blob_a
    );
    assert_eq!(
        fs::read(dec_out.join("Archive/note.txt")).unwrap(),
        note_txt
    );
    assert_eq!(
        fs::read(dec_out.join("Archive/sub/blob_b.bin")).unwrap(),
        blob_b
    );

    // In-place rekey preserves split volume layout and rotates password + keyfile
    let kf = hash_keyfile_reader(&mut Cursor::new(b"new-split-keyfile")).unwrap();
    rekey_vault_v5(
        &parts[0],
        b"SplitPass!1",
        b"RotatedPass!2",
        None,
        Some(&kf),
        Some(KdfParams::fast_test()),
        Some(&cancel),
    )
    .unwrap();
    assert!(!has_temp_artifacts(&out_dir));
    assert!(decrypt_vault_v5(
        &parts[0],
        &dir.path().join("dec_old"),
        Auth::Password {
            password: b"SplitPass!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .is_err());
    let dec_new = dir.path().join("dec_new");
    decrypt_vault_v5(
        &parts[0],
        &dec_new,
        Auth::Password {
            password: b"RotatedPass!2",
            keyfile_hash: Some(&kf),
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(
        fs::read(dec_new.join("Archive/blob_a.bin")).unwrap(),
        blob_a
    );

    // Missing middle part detection fails fast with clear error
    let backup_p2 = fs::read(&parts[1]).unwrap();
    fs::remove_file(&parts[1]).unwrap();
    let gap_err = open_vault_reader(&parts[0]).err().expect("gap must fail");
    assert!(
        gap_err.to_string().contains("missing split volume part"),
        "unexpected gap error: {gap_err}"
    );
    fs::write(&parts[1], backup_p2).unwrap();

    // Missing .001 detection when user opens .002
    fs::remove_file(&parts[0]).unwrap();
    let head_err = open_vault_reader(&parts[1])
        .err()
        .expect("missing .001 must fail");
    assert!(
        head_err.to_string().contains("missing split volume part"),
        "unexpected missing .001 error: {head_err}"
    );
}

#[test]
fn hidden_rs_and_stealth_split_volumes_and_in_place_split_repair() {
    let dir = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));

    // 1) Hidden + Padded split volume
    let decoy = dir.path().join("decoy.txt");
    let secret = dir.path().join("secret.txt");
    fs::write(&decoy, b"public decoy text").unwrap();
    fs::write(&secret, b"top secret hidden text").unwrap();
    let hidden_base = dir.path().join("hidden_split.vault");
    let hidden_opts = HiddenEncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        container_size_bytes: 256 * 1024,
        ..Default::default()
    };
    let (_, _, _, hidden_parts) = encrypt_hidden_sources_v5_split(
        &[decoy],
        &[secret],
        &hidden_base,
        MIN_SPLIT_PART_SIZE,
        b"DecoyPw!1",
        b"HiddenPw!2",
        &hidden_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(hidden_parts.len(), 4);

    let out_decoy = dir.path().join("out_decoy");
    decrypt_vault_v5(
        &hidden_parts[0],
        &out_decoy,
        Auth::Password {
            password: b"DecoyPw!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(
        fs::read(out_decoy.join("decoy.txt")).unwrap(),
        b"public decoy text"
    );

    let out_hidden = dir.path().join("out_hidden");
    decrypt_vault_v5(
        &hidden_parts[2],
        &out_hidden,
        Auth::Password {
            password: b"HiddenPw!2",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(
        fs::read(out_hidden.join("secret.txt")).unwrap(),
        b"top secret hidden text"
    );

    // 2) Reed-Solomon split volume: corrupt part .002, repair in place, verify decrypt!
    let rs_src = dir.path().join("rs_payload.bin");
    let rs_data = deterministic_bytes(160 * 1024, 77);
    fs::write(&rs_src, &rs_data).unwrap();
    let rs_base = dir.path().join("rs_split.vault");
    let rs_opts = EncryptOptions {
        reed_solomon: true,
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };
    let (_, _, rs_parts) = encrypt_sources_v5_split(
        &[rs_src],
        &rs_base,
        MIN_SPLIT_PART_SIZE,
        b"RsPass!1",
        &rs_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(rs_parts.len() >= 3);

    // Corrupt 64 contiguous bytes inside part .002
    let mut part2_bytes = fs::read(&rs_parts[1]).unwrap();
    for b in &mut part2_bytes[1000..1064] {
        *b ^= 0xFF;
    }
    fs::write(&rs_parts[1], &part2_bytes).unwrap();

    let damaged_rep = check_vault_integrity(&rs_parts[0]).unwrap();
    assert!(damaged_rep.ok);
    assert!(damaged_rep.has_reed_solomon);
    assert_eq!(damaged_rep.rs_repaired_bytes, 64);

    // Repair in place (preserves split parts)
    let repair_rep = repair_vault_v5(&rs_parts[0], None, Arc::clone(&cancel)).unwrap();
    assert_eq!(repair_rep.repaired_bytes, 64);
    let clean_rep = check_vault_integrity(&rs_parts[0]).unwrap();
    assert_eq!(clean_rep.rs_repaired_bytes, 0);

    let rs_out = dir.path().join("rs_out");
    decrypt_vault_v5(
        &rs_parts[0],
        &rs_out,
        Auth::Password {
            password: b"RsPass!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(rs_out.join("rs_payload.bin")).unwrap(), rs_data);

    // Also test repairing a split RS vault into a single explicit output file
    let single_repaired = dir.path().join("single_repaired.vault");
    let rep_single =
        repair_vault_v5(&rs_parts[0], Some(&single_repaired), Arc::clone(&cancel)).unwrap();
    assert!(rep_single.blocks_checked > 0);
    assert!(check_vault_integrity(&single_repaired).unwrap().ok);

    // 3) Stealth split volume written INSIDE source directory (tests recursive exclusion + zero .rpm_tmp_)
    let stealth_dir = dir.path().join("stealth_src");
    fs::create_dir(&stealth_dir).unwrap();
    let stealth_payload = deterministic_bytes(140 * 1024, 99);
    fs::write(stealth_dir.join("data.bin"), &stealth_payload).unwrap();
    let stealth_base = stealth_dir.join("opaque.bin");
    let stealth_opts = EncryptOptions {
        stealth: true,
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };
    let (_, _, stealth_parts) = encrypt_sources_v5_split(
        std::slice::from_ref(&stealth_dir),
        &stealth_base,
        MIN_SPLIT_PART_SIZE,
        b"StealthSplit!1",
        &stealth_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(stealth_parts.len() >= 2);
    assert!(!has_temp_artifacts(&stealth_dir));

    let stealth_integrity = check_vault_integrity(&stealth_parts[0]).unwrap();
    assert!(stealth_integrity.sha256_only);
    assert!(stealth_integrity.ok);

    let stealth_out = dir.path().join("stealth_out");
    decrypt_vault_v5_with_stealth_kdf(
        &stealth_parts[0],
        &stealth_out,
        Auth::Password {
            password: b"StealthSplit!1",
            keyfile_hash: None,
        },
        None,
        &KdfParams::fast_test(),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(
        fs::read(stealth_out.join("stealth_src/data.bin")).unwrap(),
        stealth_payload
    );
}

#[test]
fn standalone_split_join_byte_identity_and_cancel_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("payload.bin");
    let payload = deterministic_bytes(180 * 1024, 42);
    fs::write(&src, &payload).unwrap();

    let orig_vault = dir.path().join("single.vault");
    let cancel = Arc::new(AtomicBool::new(false));
    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };
    encrypt_sources_v5(
        &[src],
        &orig_vault,
        b"SplitJoin!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    let orig_bytes = fs::read(&orig_vault).unwrap();

    // Split existing single vault into parts
    let split_dir = dir.path().join("parts");
    fs::create_dir(&split_dir).unwrap();
    let parts = split_vault_file(
        &orig_vault,
        Some(&split_dir),
        MIN_SPLIT_PART_SIZE,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert!(parts.len() >= 3);
    assert!(!has_temp_artifacts(&split_dir));

    // Double-splitting an already split part must be rejected
    assert!(split_vault_file(
        &parts[0],
        Some(&split_dir),
        MIN_SPLIT_PART_SIZE,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .is_err());

    // Join cannot overwrite one of its own input parts
    assert!(join_vault_parts(
        &parts[0],
        Some(&parts[0]),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .is_err());

    // Join parts back into a single file and verify byte-for-byte identity
    let rejoined_path = dir.path().join("rejoined.vault");
    let (written_path, written_len) = join_vault_parts(
        &parts[1],
        Some(&rejoined_path),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(written_path, rejoined_path);
    assert_eq!(written_len as usize, orig_bytes.len());
    assert_eq!(fs::read(&rejoined_path).unwrap(), orig_bytes);

    // Cancellation during split leaves zero orphan parts or temp files
    let cancel_dir = dir.path().join("cancel_split");
    fs::create_dir(&cancel_dir).unwrap();
    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_clone = Arc::clone(&cancel_flag);
    let err = split_vault_file(
        &orig_vault,
        Some(&cancel_dir),
        MIN_SPLIT_PART_SIZE,
        Arc::new(move |_, _| cancel_clone.store(true, Ordering::Relaxed)),
        Arc::clone(&cancel_flag),
    )
    .unwrap_err();
    assert!(matches!(err, StorageError::Cancelled));
    assert_eq!(fs::read_dir(&cancel_dir).unwrap().count(), 0);
}

#[test]
fn split_commit_rollback_on_readonly_locked_and_directory_collisions() {
    let dir = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));

    let src = dir.path().join("payload.bin");
    let data = deterministic_bytes(110 * 1024, 33);
    fs::write(&src, &data).unwrap();

    // 1) In-place rekey rollback when `.002` is ReadOnly: neither `.001` nor `.002` may change.
    let rekey_dir = dir.path().join("rekey_ro");
    fs::create_dir(&rekey_dir).unwrap();
    let base = rekey_dir.join("ro.vault");
    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };
    let (_, _, parts) = encrypt_sources_v5_split(
        std::slice::from_ref(&src),
        &base,
        MIN_SPLIT_PART_SIZE,
        b"OldPass!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(parts.len(), 2);
    let orig_p1 = fs::read(&parts[0]).unwrap();
    let orig_p2 = fs::read(&parts[1]).unwrap();

    let mut perms = fs::metadata(&parts[1]).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&parts[1], perms).unwrap();

    let err = rekey_vault_v5(
        &parts[0],
        b"OldPass!1",
        b"NewPass!2",
        None,
        None,
        Some(KdfParams::fast_test()),
        Some(&cancel),
    )
    .unwrap_err();
    assert!(
        matches!(err, StorageError::Io(_)),
        "expected I/O error on ReadOnly .002, got {err:?}"
    );
    assert_eq!(fs::read(&parts[0]).unwrap(), orig_p1);
    assert_eq!(fs::read(&parts[1]).unwrap(), orig_p2);
    assert!(!has_temp_artifacts(&rekey_dir));

    // Clear ReadOnly so temp cleanup & further tests work cleanly.
    #[allow(clippy::permissions_set_readonly_false)]
    {
        let mut perms = fs::metadata(&parts[1]).unwrap().permissions();
        perms.set_readonly(false);
        fs::set_permissions(&parts[1], perms).unwrap();
    }

    // Still decryptable with the original password.
    let dec_ro = dir.path().join("dec_ro");
    decrypt_vault_v5(
        &parts[0],
        &dec_ro,
        Auth::Password {
            password: b"OldPass!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(dec_ro.join("payload.bin")).unwrap(), data);

    // 2) Windows-locked `.002` (opened with FILE_SHARE_READ=1, without FILE_SHARE_DELETE)
    //    allows `rekey_stream` to read both parts and reach `SplitVolumeWriter::commit` Step B,
    //    where `.001` is moved to `.rpm_bak` and `.002` fails rename -> `.001` MUST be rolled back.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 1;
        let _lock = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&parts[1])
            .unwrap();
        let locked_err = rekey_vault_v5(
            &parts[0],
            b"OldPass!1",
            b"LockedPass!3",
            None,
            None,
            Some(KdfParams::fast_test()),
            Some(&cancel),
        );
        assert!(
            matches!(locked_err, Err(StorageError::Io(_))),
            "rekey must fail in commit Step B when .002 lacks FILE_SHARE_DELETE; got {locked_err:?}"
        );
        drop(_lock);
        assert_eq!(fs::read(&parts[0]).unwrap(), orig_p1);
        assert_eq!(fs::read(&parts[1]).unwrap(), orig_p2);
        assert!(!has_temp_artifacts(&rekey_dir));
    }

    // 3) In-place RS split repair rollback when `.002` is ReadOnly.
    let rs_dir = dir.path().join("rs_ro");
    fs::create_dir(&rs_dir).unwrap();
    let rs_base = rs_dir.join("rs.vault");
    let rs_opts = EncryptOptions {
        reed_solomon: true,
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };
    let (_, _, rs_parts) = encrypt_sources_v5_split(
        std::slice::from_ref(&src),
        &rs_base,
        MIN_SPLIT_PART_SIZE,
        b"RsRo!1",
        &rs_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(rs_parts.len() >= 2);
    let mut p2_mut = fs::read(&rs_parts[1]).unwrap();
    for b in &mut p2_mut[200..232] {
        *b ^= 0x55;
    }
    fs::write(&rs_parts[1], &p2_mut).unwrap();
    let rs_p1_before = fs::read(&rs_parts[0]).unwrap();
    let rs_p2_before = fs::read(&rs_parts[1]).unwrap();

    let mut perms = fs::metadata(&rs_parts[1]).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&rs_parts[1], perms).unwrap();

    assert!(repair_vault_v5(&rs_parts[0], None, Arc::clone(&cancel)).is_err());
    assert_eq!(fs::read(&rs_parts[0]).unwrap(), rs_p1_before);
    assert_eq!(fs::read(&rs_parts[1]).unwrap(), rs_p2_before);
    assert!(!has_temp_artifacts(&rs_dir));

    #[allow(clippy::permissions_set_readonly_false)]
    {
        let mut perms = fs::metadata(&rs_parts[1]).unwrap().permissions();
        perms.set_readonly(false);
        fs::set_permissions(&rs_parts[1], perms).unwrap();
    }

    // 4) Fresh split write where `.002` collides with an existing directory must leave ZERO `.001`.
    let fresh_dir = dir.path().join("fresh_collide");
    fs::create_dir(&fresh_dir).unwrap();
    let collide_base = fresh_dir.join("fresh.vault");
    fs::create_dir(split_part_path(&collide_base, 2)).unwrap();
    let res = encrypt_sources_v5_split(
        std::slice::from_ref(&src),
        &collide_base,
        MIN_SPLIT_PART_SIZE,
        b"Fresh!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    );
    assert!(res.is_err());
    assert!(
        !split_part_path(&collide_base, 1).exists(),
        "failed fresh split write must not leave orphan .001"
    );
    assert!(split_part_path(&collide_base, 2).is_dir());
    assert!(!has_temp_artifacts(&fresh_dir));
}

#[test]
fn unique_split_base_avoids_orphan_parts_and_dangling_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("backup.vault");

    // Plain single `.vault` is NOT dodged.
    fs::write(&base, b"single").unwrap();
    assert_eq!(unique_split_base(&base), base);

    // Orphan `.002` without `.001` MUST force `_1`.
    fs::write(split_part_path(&base, 2), b"orphan2").unwrap();
    let cand1 = unique_split_base(&base);
    assert_eq!(cand1, dir.path().join("backup_1.vault"));

    // Orphan `.003` on `_1` MUST force `_2`.
    fs::write(split_part_path(&cand1, 3), b"orphan3").unwrap();
    let cand2 = unique_split_base(&base);
    assert_eq!(cand2, dir.path().join("backup_2.vault"));

    // Directory named `backup_2.vault.001` MUST force `_3`.
    fs::create_dir(split_part_path(&cand2, 1)).unwrap();
    let cand3 = unique_split_base(&base);
    assert_eq!(cand3, dir.path().join("backup_3.vault"));

    // Dangling symlink at `backup_3.vault.001` MUST force `_4` when platform allows creating symlinks.
    let dangling_target = dir.path().join("does_not_exist_target");
    let link_path = split_part_path(&cand3, 1);
    #[cfg(unix)]
    let link_res = std::os::unix::fs::symlink(&dangling_target, &link_path);
    #[cfg(windows)]
    let link_res = std::os::windows::fs::symlink_file(&dangling_target, &link_path);
    if link_res.is_ok() {
        assert!(!link_path.exists());
        assert_eq!(unique_split_base(&base), dir.path().join("backup_4.vault"));
    }
}

#[test]
fn in_source_non_stealth_excludes_temp_files_and_stealth_preserves_existing_numbered_files() {
    let dir = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };

    let check_no_rpm_tmp = |root: &Path| {
        for entry in fs::read_dir(root).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.starts_with(".rpm_tmp_") && !name.ends_with(".part"),
                "temp artifact leaked into archive: {name}"
            );
        }
    };

    // 1) Non-stealth single vault written INSIDE source directory.
    let src_single = dir.path().join("ns_single");
    fs::create_dir(&src_single).unwrap();
    let payload = deterministic_bytes(90 * 1024, 51);
    fs::write(src_single.join("doc.bin"), &payload).unwrap();
    let out_single = src_single.join("inside.vault");
    encrypt_sources_v5(
        std::slice::from_ref(&src_single),
        &out_single,
        b"Inside!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    let dec_single = dir.path().join("dec_ns_single");
    decrypt_vault_v5(
        &out_single,
        &dec_single,
        Auth::Password {
            password: b"Inside!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    check_no_rpm_tmp(&dec_single.join("ns_single"));
    assert_eq!(
        fs::read(dec_single.join("ns_single/doc.bin")).unwrap(),
        payload
    );

    // 2) Non-stealth split vault written INSIDE source directory.
    let src_split = dir.path().join("ns_split");
    fs::create_dir(&src_split).unwrap();
    let big_payload = deterministic_bytes(160 * 1024, 52);
    fs::write(src_split.join("big.bin"), &big_payload).unwrap();
    let out_split_base = src_split.join("inside_split.vault");
    let (_, _, split_parts) = encrypt_sources_v5_split(
        std::slice::from_ref(&src_split),
        &out_split_base,
        MIN_SPLIT_PART_SIZE,
        b"InsideSplit!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(split_parts.len() >= 3);
    let dec_split = dir.path().join("dec_ns_split");
    decrypt_vault_v5(
        &split_parts[0],
        &dec_split,
        Auth::Password {
            password: b"InsideSplit!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    check_no_rpm_tmp(&dec_split.join("ns_split"));
    assert_eq!(
        fs::read(dec_split.join("ns_split/big.bin")).unwrap(),
        big_payload
    );

    // 3) Non-stealth Hidden (single & split) written INSIDE decoy source directory.
    let decoy_dir = dir.path().join("ns_hidden_decoy");
    let hidden_dir = dir.path().join("ns_hidden_secret");
    fs::create_dir(&decoy_dir).unwrap();
    fs::create_dir(&hidden_dir).unwrap();
    fs::write(decoy_dir.join("decoy.txt"), b"decoy-body").unwrap();
    fs::write(hidden_dir.join("secret.txt"), b"secret-body").unwrap();
    let hidden_opts = HiddenEncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        container_size_bytes: 256 * 1024,
        ..Default::default()
    };

    let hidden_single_out = decoy_dir.join("hid_single.vault");
    encrypt_hidden_sources_v5(
        std::slice::from_ref(&decoy_dir),
        std::slice::from_ref(&hidden_dir),
        &hidden_single_out,
        b"HidDecoy!1",
        b"HidSecret!2",
        &hidden_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    let dec_hid_single = dir.path().join("dec_hid_single");
    decrypt_vault_v5(
        &hidden_single_out,
        &dec_hid_single,
        Auth::Password {
            password: b"HidDecoy!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    check_no_rpm_tmp(&dec_hid_single.join("ns_hidden_decoy"));
    fs::remove_file(&hidden_single_out).unwrap();

    let hidden_split_out = hidden_dir.join("hid_split.vault");
    let (_, _, _, hid_parts) = encrypt_hidden_sources_v5_split(
        std::slice::from_ref(&decoy_dir),
        std::slice::from_ref(&hidden_dir),
        &hidden_split_out,
        MIN_SPLIT_PART_SIZE,
        b"HidDecoy!1",
        b"HidSecret!2",
        &hidden_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(hid_parts.len(), 4);
    let dec_hid_split = dir.path().join("dec_hid_split");
    decrypt_vault_v5(
        &hid_parts[0],
        &dec_hid_split,
        Auth::Password {
            password: b"HidSecret!2",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    check_no_rpm_tmp(&dec_hid_split.join("ns_hidden_secret"));

    // 4) Single (non-split) Stealth inside source directory MUST NOT skip pre-existing `<base>.001`.
    let stealth_dir = dir.path().join("stealth_preserve");
    fs::create_dir(&stealth_dir).unwrap();
    let user_numbered = stealth_dir.join("opaque.bin.001");
    fs::write(&user_numbered, b"precious user file 001").unwrap();
    fs::write(stealth_dir.join("other.txt"), b"other").unwrap();
    let stealth_out = stealth_dir.join("opaque.bin");
    let stealth_opts = EncryptOptions {
        stealth: true,
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };
    let skipped_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let skipped_clone = Arc::clone(&skipped_count);
    let (_, meta) = encrypt_sources_v5(
        std::slice::from_ref(&stealth_dir),
        &stealth_out,
        b"StealthPreserve!1",
        &stealth_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        move |_| {
            skipped_clone.fetch_add(1, Ordering::Relaxed);
        },
    )
    .unwrap();
    assert_eq!(meta.file_count, 2);
    assert_eq!(skipped_count.load(Ordering::Relaxed), 0);

    let dec_stealth = dir.path().join("dec_stealth_preserve");
    decrypt_vault_v5_with_stealth_kdf(
        &stealth_out,
        &dec_stealth,
        Auth::Password {
            password: b"StealthPreserve!1",
            keyfile_hash: None,
        },
        None,
        &KdfParams::fast_test(),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(
        fs::read(dec_stealth.join("stealth_preserve/opaque.bin.001")).unwrap(),
        b"precious user file 001"
    );
    assert!(!dec_stealth.join("stealth_preserve/opaque.bin").exists());

    // 5) Split Stealth inside source directory MUST NOT skip pre-existing `<base>.NNN` user files
    //    (both in a nested subdir and a non-colliding sibling index `.005`), and creating a brand-new
    //    nested output directory inside a source directory MUST NOT archive that newly created dir.
    let split_stealth_dir = dir.path().join("split_stealth_preserve");
    fs::create_dir_all(split_stealth_dir.join("sub")).unwrap();
    let big_user = deterministic_bytes(90 * 1024, 53);
    fs::write(split_stealth_dir.join("big.bin"), &big_user).unwrap();
    fs::write(
        split_stealth_dir.join("sub/opaque.bin.001"),
        b"nested user 001",
    )
    .unwrap();
    fs::write(
        split_stealth_dir.join("opaque.bin.005"),
        b"sibling user 005",
    )
    .unwrap();
    let split_stealth_base = split_stealth_dir.join("opaque.bin");
    let (_, split_meta, ss_parts) = encrypt_sources_v5_split(
        std::slice::from_ref(&split_stealth_dir),
        &split_stealth_base,
        MIN_SPLIT_PART_SIZE,
        b"SplitStealthPreserve!1",
        &stealth_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(split_meta.file_count, 3);
    assert_eq!(ss_parts.len(), 2);
    // Copy the 2 split parts out (since `opaque.bin.005` lives in the same dir) and verify full decrypt.
    let ss_isolated = dir.path().join("ss_isolated");
    fs::create_dir(&ss_isolated).unwrap();
    for p in &ss_parts {
        fs::copy(p, ss_isolated.join(p.file_name().unwrap())).unwrap();
    }
    let dec_ss = dir.path().join("dec_ss");
    decrypt_vault_v5_with_stealth_kdf(
        &ss_isolated.join("opaque.bin.001"),
        &dec_ss,
        Auth::Password {
            password: b"SplitStealthPreserve!1",
            keyfile_hash: None,
        },
        None,
        &KdfParams::fast_test(),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(
        fs::read(dec_ss.join("split_stealth_preserve/sub/opaque.bin.001")).unwrap(),
        b"nested user 001"
    );
    assert_eq!(
        fs::read(dec_ss.join("split_stealth_preserve/opaque.bin.005")).unwrap(),
        b"sibling user 005"
    );

    // 6) Non-stealth output targeting a brand-new nested directory inside the source folder
    //    must not pack the newly created empty directory or any `.rpm_tmp_*` files.
    let new_sub_src = dir.path().join("new_sub_src");
    fs::create_dir(&new_sub_src).unwrap();
    fs::write(new_sub_src.join("keep.txt"), b"keep-me").unwrap();
    let nested_out = new_sub_src.join("brand_new_out").join("vault.vault");
    encrypt_sources_v5(
        std::slice::from_ref(&new_sub_src),
        &nested_out,
        b"NewSub!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    let dec_new_sub = dir.path().join("dec_new_sub");
    decrypt_vault_v5(
        &nested_out,
        &dec_new_sub,
        Auth::Password {
            password: b"NewSub!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(
        fs::read(dec_new_sub.join("new_sub_src/keep.txt")).unwrap(),
        b"keep-me"
    );
    assert!(
        !dec_new_sub.join("new_sub_src/brand_new_out").exists(),
        "newly created output directory must not be archived"
    );
}

#[test]
fn repair_and_join_reject_split_set_conflicts_directories_and_zero_byte_volumes() {
    let dir = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));

    let src = dir.path().join("rs_in.bin");
    fs::write(&src, deterministic_bytes(140 * 1024, 61)).unwrap();
    let rs_base = dir.path().join("Guard.vault");
    let rs_opts = EncryptOptions {
        reed_solomon: true,
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };
    let (_, _, parts) = encrypt_sources_v5_split(
        &[src],
        &rs_base,
        MIN_SPLIT_PART_SIZE,
        b"GuardPass!1",
        &rs_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(parts.len() >= 3);

    // `repair_vault_v5` with explicit `Some(out)` must reject ANY existing part or new part of same set
    for part in &parts {
        assert!(
            repair_vault_v5(&parts[0], Some(part), Arc::clone(&cancel)).is_err(),
            "repair -o must reject overwriting {}",
            part.display()
        );
    }
    let next_part = split_part_path(&rs_base, parts.len() + 1);
    assert!(repair_vault_v5(&parts[0], Some(&next_part), Arc::clone(&cancel)).is_err());

    // `repair -o <existing_dir>` and non-file vault path must fail cleanly early
    let existing_dir = dir.path().join("existing_dir");
    fs::create_dir(&existing_dir).unwrap();
    assert!(repair_vault_v5(&parts[0], Some(&existing_dir), Arc::clone(&cancel)).is_err());
    assert!(repair_vault_v5(&existing_dir, None, Arc::clone(&cancel)).is_err());
    assert!(repair_vault_v5(&dir.path().join("missing.vault"), None, Arc::clone(&cancel)).is_err());

    // `join_vault_parts` must reject writing a new `.NNN` part under the same split set
    assert!(join_vault_parts(
        &parts[0],
        Some(&next_part),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .is_err());

    #[cfg(windows)]
    {
        let upper_next = dir
            .path()
            .join(format!("GUARD.VAULT.{:03}", parts.len() + 1));
        assert!(repair_vault_v5(&parts[0], Some(&upper_next), Arc::clone(&cancel)).is_err());
        assert!(join_vault_parts(
            &parts[0],
            Some(&upper_next),
            Arc::new(|_, _| {}),
            Arc::clone(&cancel),
        )
        .is_err());
    }

    // `join_vault_parts` and `repair_vault_v5` must also reject non-existent parent traversal
    // (`new_sub/../Guard.vault.NNN`) that would create `new_sub` and write into the split set!
    let traversal_next = dir
        .path()
        .join("new_sub_traversal")
        .join("..")
        .join(format!("Guard.vault.{:03}", parts.len() + 1));
    let traversal_p1 = dir
        .path()
        .join("new_sub_traversal")
        .join("..")
        .join("Guard.vault.001");
    assert!(repair_vault_v5(&parts[0], Some(&traversal_next), Arc::clone(&cancel)).is_err());
    assert!(repair_vault_v5(&parts[0], Some(&traversal_p1), Arc::clone(&cancel)).is_err());
    assert!(join_vault_parts(
        &parts[0],
        Some(&traversal_next),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .is_err());
    assert!(join_vault_parts(
        &parts[0],
        Some(&traversal_p1),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .is_err());
    assert!(!dir.path().join("new_sub_traversal").exists());

    // `rekey_vault_v5` on a directory fails cleanly without creating temp artifacts
    assert!(rekey_vault_v5(&existing_dir, b"a", b"b", None, None, None, Some(&cancel),).is_err());
    assert!(!has_temp_artifacts(dir.path()));

    // 0-byte split `.001` must be rejected by `join_vault_parts` (consistent with `split_vault_file`)
    let empty_part = dir.path().join("empty.vault.001");
    fs::write(&empty_part, b"").unwrap();
    assert!(join_vault_parts(
        &empty_part,
        Some(&dir.path().join("empty_out.vault")),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .is_err());
}

#[test]
fn turkish_unicode_case_numeric_extensions_single_non_vault_and_dot_escape_guards() {
    let dir = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let src = dir.path().join("icerik.bin");
    let data = deterministic_bytes(110 * 1024, 71);
    fs::write(&src, &data).unwrap();
    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };

    // 1) Turkish characters in `.vault` split and Stealth split (`Şifre.vault.001` / `Özel.bin.001`)
    let tr_dir = dir.path().join("turkish");
    fs::create_dir(&tr_dir).unwrap();
    let tr_base = tr_dir.join("Şifre.vault");
    let (_, _, tr_parts) = encrypt_sources_v5_split(
        std::slice::from_ref(&src),
        &tr_base,
        MIN_SPLIT_PART_SIZE,
        b"Turkce!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(tr_parts.len(), 2);

    let stealth_tr_base = tr_dir.join("Özel.bin");
    let stealth_opts = EncryptOptions {
        stealth: true,
        ..opts.clone()
    };
    let (_, _, stealth_tr_parts) = encrypt_sources_v5_split(
        std::slice::from_ref(&src),
        &stealth_tr_base,
        MIN_SPLIT_PART_SIZE,
        b"TurkceStealth!1",
        &stealth_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(stealth_tr_parts.len(), 2);

    #[cfg(windows)]
    {
        // Querying with lowercase Turkish `ş`/`ö` finds the uppercase `Ş`/`Ö` parts on Windows!
        let lower_tr = tr_dir.join("şifre.vault.001");
        let set = discover_split_parts(&lower_tr).unwrap().unwrap();
        assert_eq!(set.part_count(), 2);
        assert_eq!(set.first_part(), tr_parts[0]);

        let lower_stealth = tr_dir.join("özel.bin.001");
        let stealth_set = discover_split_parts(&lower_stealth).unwrap().unwrap();
        assert_eq!(stealth_set.part_count(), 2);
        assert_eq!(stealth_set.first_part(), stealth_tr_parts[0]);

        let dec_tr = dir.path().join("dec_tr");
        decrypt_vault_v5_with_stealth_kdf(
            &lower_stealth,
            &dec_tr,
            Auth::Password {
                password: b"TurkceStealth!1",
                keyfile_hash: None,
            },
            None,
            &KdfParams::fast_test(),
            Arc::new(|_, _| {}),
            Arc::clone(&cancel),
        )
        .unwrap();
        assert_eq!(fs::read(dec_tr.join("icerik.bin")).unwrap(), data);

        // NTFS keeps U+0130 (`İ`) and ASCII `i` as distinct files; ensure they never collide.
        let i_dir = dir.path().join("dotted_i");
        fs::create_dir(&i_dir).unwrap();
        fs::write(i_dir.join("İ.vault.001"), b"dotted").unwrap();
        fs::write(i_dir.join("i.vault.002"), b"ascii-two").unwrap();
        let dotted_set = discover_split_parts(&i_dir.join("İ.vault.001"))
            .unwrap()
            .unwrap();
        assert_eq!(dotted_set.part_count(), 1);
    }

    // 2) `report.001` + `report.2026` in same directory MUST NOT lock out `report.2026`!
    let num_dir = dir.path().join("numeric_coexist");
    fs::create_dir(&num_dir).unwrap();
    fs::write(num_dir.join("report.001"), b"ordinary file 001").unwrap();
    let report_2026 = num_dir.join("report.2026");
    encrypt_sources_v5(
        std::slice::from_ref(&src),
        &report_2026,
        b"YearPass!2026",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(discover_split_parts(&report_2026).unwrap(), None);
    assert_eq!(
        discover_split_parts(&num_dir.join("report.001")).unwrap(),
        None
    );
    let dec_2026 = dir.path().join("dec_2026");
    decrypt_vault_v5(
        &report_2026,
        &dec_2026,
        Auth::Password {
            password: b"YearPass!2026",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(dec_2026.join("icerik.bin")).unwrap(), data);

    // 3) Single non-`.vault` `.001` (`photo.001`, `stealth.001`) is NOT a split volume:
    //    - `discover_split_parts` returns `Ok(None)`
    //    - `split_vault_file` CAN split single Stealth `stealth.001`
    //    - 1-part `.001` (both non-vault `single.001` and `.vault.001`) rekey with larger KDF stays 1 part!
    let single_dir = dir.path().join("single_001");
    fs::create_dir(&single_dir).unwrap();
    let photo_001 = single_dir.join("photo.001");
    fs::write(&photo_001, b"single camera photo").unwrap();
    assert_eq!(discover_split_parts(&photo_001).unwrap(), None);

    let stealth_single_001 = single_dir.join("stealth.001");
    encrypt_sources_v5(
        std::slice::from_ref(&src),
        &stealth_single_001,
        b"StealthSingle!1",
        &stealth_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(discover_split_parts(&stealth_single_001).unwrap(), None);
    let split_out = dir.path().join("split_stealth_001");
    fs::create_dir(&split_out).unwrap();
    let splitted = split_vault_file(
        &stealth_single_001,
        Some(&split_out),
        MIN_SPLIT_PART_SIZE,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert!(splitted.len() >= 2);

    // 1-part `.vault.001` rekeyed with larger KDF digits MUST stay 1 file (no `.002` created!)
    let one_part_dir = dir.path().join("one_part_vault");
    fs::create_dir(&one_part_dir).unwrap();
    let one_base = one_part_dir.join("one.vault");
    let small_kdf = KdfParams::fast_test();
    let larger_kdf = KdfParams {
        memory_kib: 16_384,
        iterations: 1,
        parallelism: 10,
    };
    let one_opts = EncryptOptions {
        kdf: small_kdf,
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };
    let (_, _, one_parts) = encrypt_sources_v5_split(
        std::slice::from_ref(&src),
        &one_base,
        1024 * 1024, // 1 MiB -> fits in 1 part (> 64 KiB)
        b"OnePart!1",
        &one_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(one_parts.len(), 1);
    rekey_vault_v5(
        &one_parts[0],
        b"OnePart!1",
        b"OnePart!2",
        None,
        None,
        Some(larger_kdf),
        Some(&cancel),
    )
    .unwrap();
    assert!(!split_part_path(&one_base, 2).exists());
    assert_eq!(
        discover_split_parts(&one_parts[0])
            .unwrap()
            .unwrap()
            .part_count(),
        1
    );

    // 4) `sub/..001`, `sub/...001`, and all-dot `sub/....001` must be rejected by `parse_split_part_path`!
    assert_eq!(parse_split_part_path(Path::new("sub/..001")), None);
    assert_eq!(parse_split_part_path(Path::new("sub/...001")), None);
    assert_eq!(parse_split_part_path(Path::new("sub/....001")), None);
    assert_eq!(parse_split_part_path(Path::new("..001")), None);
    assert_eq!(parse_split_part_path(Path::new("...001")), None);
    assert_eq!(parse_split_part_path(Path::new("....001")), None);

    let sub = dir.path().join("sub_escape");
    fs::create_dir(&sub).unwrap();
    let dot_001 = sub.join("..001");
    let dot_002 = sub.join("..002");
    fs::write(&dot_001, b"aaa").unwrap();
    fs::write(&dot_002, b"bbb").unwrap();
    assert_eq!(discover_split_parts(&dot_001).unwrap(), None);
    assert!(join_vault_parts(&dot_001, None, Arc::new(|_, _| {}), Arc::clone(&cancel),).is_err());

    // 5) Stealth split missing middle part (`.001` + `.003`, `.002` deleted) AND missing `.001`
    //    (`.002` + `.003`) MUST report `missing split volume part` (never silently return `Ok(None)`!).
    let stealth_gap = dir.path().join("stealth_gap");
    fs::create_dir(&stealth_gap).unwrap();
    let sg1 = stealth_gap.join("opaque.bin.001");
    let sg3 = stealth_gap.join("opaque.bin.003");
    let sg4 = stealth_gap.join("opaque.bin.004");
    fs::write(&sg1, b"p1").unwrap();
    fs::write(&sg3, b"p3").unwrap();
    for probe in [&sg1, &sg3] {
        let err = discover_split_parts(probe).expect_err("missing .002 in Stealth split must fail");
        assert!(
            err.to_string().contains("opaque.bin.002"),
            "unexpected error for {}: {err}",
            probe.display()
        );
    }
    fs::write(&sg4, b"p4").unwrap();
    for probe in [&sg1, &sg3, &sg4] {
        let err = discover_split_parts(probe)
            .expect_err("missing .002 in 4-part Stealth split must fail");
        assert!(err.to_string().contains("opaque.bin.002"), "{err}");
    }
    // Missing `.001` when `.002` + `.003` exist
    let stealth_head_gap = dir.path().join("stealth_head_gap");
    fs::create_dir(&stealth_head_gap).unwrap();
    let sh2 = stealth_head_gap.join("opaque.bin.002");
    let sh3 = stealth_head_gap.join("opaque.bin.003");
    fs::write(&sh2, b"p2").unwrap();
    fs::write(&sh3, b"p3").unwrap();
    for probe in [&sh2, &sh3] {
        let err =
            discover_split_parts(probe).expect_err("missing .001 when .002+.003 exist must fail");
        assert!(err.to_string().contains("opaque.bin.001"), "{err}");
    }

    // 6) Adjacent 4-digit non-vault files (`report.2025` + `report.2026`), mid-range 3-digit
    //    files (`photo.100` + `photo.101`), AND 2-part Stealth `report.001`+`report.002` alongside
    //    unrelated `report.2026` must all work without false lockouts!
    let years_dir = dir.path().join("years_coexist");
    fs::create_dir(&years_dir).unwrap();
    let y25 = years_dir.join("report.2025");
    let y26 = years_dir.join("report.2026");
    fs::write(&y25, b"2025 report").unwrap();
    fs::write(&y26, b"2026 report").unwrap();
    assert_eq!(discover_split_parts(&y25).unwrap(), None);
    assert_eq!(discover_split_parts(&y26).unwrap(), None);

    let ph100 = years_dir.join("photo.100");
    let ph101 = years_dir.join("photo.101");
    fs::write(&ph100, b"img100").unwrap();
    fs::write(&ph101, b"img101").unwrap();
    assert_eq!(discover_split_parts(&ph100).unwrap(), None);
    assert_eq!(discover_split_parts(&ph101).unwrap(), None);

    // Add 2-part Stealth split `report.001` + `report.002` in the same dir as `report.2025` + `report.2026`
    let r1 = years_dir.join("report.001");
    let r2 = years_dir.join("report.002");
    fs::write(&r1, b"part1").unwrap();
    fs::write(&r2, b"part2").unwrap();
    let r_set = discover_split_parts(&r1).unwrap().unwrap();
    assert_eq!(r_set.part_count(), 2);
    assert_eq!(discover_split_parts(&r2).unwrap().unwrap().part_count(), 2);
    assert_eq!(discover_split_parts(&y26).unwrap(), None);
    assert_eq!(discover_split_parts(&y25).unwrap(), None);

    // 7) Mixed-casing Windows in-place rekey (`Şifre.vault.001` + `şifre.vault.002`)
    #[cfg(windows)]
    {
        let mix_dir = dir.path().join("tr_mixed_case");
        fs::create_dir(&mix_dir).unwrap();
        let mix_base = mix_dir.join("Şifre.vault");
        let (_, _, mix_parts) = encrypt_sources_v5_split(
            std::slice::from_ref(&src),
            &mix_base,
            MIN_SPLIT_PART_SIZE,
            b"MixPw!1",
            &opts,
            Arc::new(|_, _| {}),
            Arc::clone(&cancel),
            |_| {},
        )
        .unwrap();
        assert_eq!(mix_parts.len(), 2);
        // Rename `.002` to lowercase Turkish `ş` via temp name so NTFS updates its directory entry casing.
        let tmp_rename = mix_dir.join("tmp_case_swap");
        let lower_p2 = mix_dir.join("şifre.vault.002");
        fs::rename(&mix_parts[1], &tmp_rename).unwrap();
        fs::rename(&tmp_rename, &lower_p2).unwrap();

        rekey_vault_v5(
            &lower_p2,
            b"MixPw!1",
            b"MixPw!2",
            None,
            None,
            Some(KdfParams::fast_test()),
            Some(&cancel),
        )
        .unwrap();
        assert!(!has_temp_artifacts(&mix_dir));
        let dec_mix = dir.path().join("dec_mix");
        decrypt_vault_v5(
            &mix_parts[0],
            &dec_mix,
            Auth::Password {
                password: b"MixPw!2",
                keyfile_hash: None,
            },
            Arc::new(|_, _| {}),
            Arc::clone(&cancel),
        )
        .unwrap();
        assert_eq!(fs::read(dec_mix.join("icerik.bin")).unwrap(), data);
    }
}

#[test]
fn rekey_missing_tail_kdf_part_count_changes_long_names_four_digit_and_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let small_kdf = KdfParams::fast_test();
    let larger_kdf = KdfParams {
        memory_kib: 16_384,
        iterations: 1,
        parallelism: 10,
    };

    // 1) Missing tail part must be rejected by `rekey_vault_v5` without touching earlier parts
    let tail_dir = dir.path().join("missing_tail");
    fs::create_dir(&tail_dir).unwrap();
    let src = dir.path().join("tail_src.bin");
    let data = deterministic_bytes(140 * 1024, 81);
    fs::write(&src, &data).unwrap();
    let tail_base = tail_dir.join("tail.vault");
    let opts = EncryptOptions {
        kdf: small_kdf,
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };
    let (_, _, tail_parts) = encrypt_sources_v5_split(
        std::slice::from_ref(&src),
        &tail_base,
        MIN_SPLIT_PART_SIZE,
        b"TailPw!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(tail_parts.len() >= 3);
    let orig_tail_p1 = fs::read(&tail_parts[0]).unwrap();
    let tail_last = tail_parts.last().unwrap().clone();
    fs::remove_file(&tail_last).unwrap();
    assert!(rekey_vault_v5(
        &tail_parts[0],
        b"TailPw!1",
        b"TailPw!2",
        None,
        None,
        Some(larger_kdf),
        Some(&cancel),
    )
    .is_err());
    assert_eq!(fs::read(&tail_parts[0]).unwrap(), orig_tail_p1);
    assert!(!tail_last.exists());
    assert!(!has_temp_artifacts(&tail_dir));

    // 2) Multi-part split `rekey` changing part count: 2 parts -> 3 parts (KDF growth) -> 2 parts (KDF shrink)
    let kdf_dir = dir.path().join("kdf_resize");
    fs::create_dir(&kdf_dir).unwrap();
    let single_exact = kdf_dir.join("exact_src.vault");
    encrypt_sources_v5(
        std::slice::from_ref(&src),
        &single_exact,
        b"ResizePw!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    let exact_bytes = fs::read(&single_exact).unwrap();
    assert!(exact_bytes.len() as u64 >= 2 * MIN_SPLIT_PART_SIZE);
    // Split into 2 parts where part1 + part2 fit exact_bytes snugly (part2 == part_size if even, or 1 byte less)
    let half_part_size = (exact_bytes.len() as u64).div_ceil(2);
    let resize_base = kdf_dir.join("resize.vault");
    let p1_path = split_part_path(&resize_base, 1);
    let p2_path = split_part_path(&resize_base, 2);
    let p3_path = split_part_path(&resize_base, 3);
    // Make part 1 = half_part_size and part 2 = remainder; if odd, we test 2 -> 3 when growth exceeds 1 byte!
    // Header growth from `memory_kib: 8192, parallelism: 1` -> `memory_kib: 16384, parallelism: 10` is +2 bytes (> 1)!
    let big_digit_kdf = KdfParams {
        memory_kib: 16_384,
        iterations: 1,
        parallelism: 10,
    };
    fs::write(&p1_path, &exact_bytes[..half_part_size as usize]).unwrap();
    fs::write(&p2_path, &exact_bytes[half_part_size as usize..]).unwrap();
    assert_eq!(
        discover_split_parts(&p1_path)
            .unwrap()
            .unwrap()
            .part_count(),
        2
    );

    // Grow KDF (+2 bytes in JSON header) -> spills into `.003` (2 parts -> 3 parts)!
    rekey_vault_v5(
        &p1_path,
        b"ResizePw!1",
        b"ResizePw!2",
        None,
        None,
        Some(big_digit_kdf),
        Some(&cancel),
    )
    .unwrap();
    assert_eq!(
        discover_split_parts(&p1_path)
            .unwrap()
            .unwrap()
            .part_count(),
        3
    );
    assert!(p3_path.is_file());
    assert!(!has_temp_artifacts(&kdf_dir));

    let dec_grown = dir.path().join("dec_grown");
    decrypt_vault_v5(
        &p1_path,
        &dec_grown,
        Auth::Password {
            password: b"ResizePw!2",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(dec_grown.join("tail_src.bin")).unwrap(), data);

    // ReadOnly obsolete `.003` blocks shrinking rekey and keeps all 3 parts intact!
    let mut perms = fs::metadata(&p3_path).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&p3_path, perms).unwrap();
    assert!(rekey_vault_v5(
        &p1_path,
        b"ResizePw!2",
        b"ResizePw!3",
        None,
        None,
        Some(small_kdf),
        Some(&cancel),
    )
    .is_err());
    assert!(p3_path.is_file());
    assert!(!has_temp_artifacts(&kdf_dir));

    #[allow(clippy::permissions_set_readonly_false)]
    {
        let mut perms = fs::metadata(&p3_path).unwrap().permissions();
        perms.set_readonly(false);
        fs::set_permissions(&p3_path, perms).unwrap();
    }

    // Shrink KDF back (-2 bytes) -> shrinks from 3 parts back to 2 parts and deletes obsolete `.003`!
    rekey_vault_v5(
        &p1_path,
        b"ResizePw!2",
        b"ResizePw!3",
        None,
        None,
        Some(small_kdf),
        Some(&cancel),
    )
    .unwrap();
    assert!(!p3_path.exists());
    assert_eq!(
        discover_split_parts(&p1_path)
            .unwrap()
            .unwrap()
            .part_count(),
        2
    );
    assert!(!has_temp_artifacts(&kdf_dir));
    let dec_shrunk = dir.path().join("dec_shrunk");
    decrypt_vault_v5(
        &p1_path,
        &dec_shrunk,
        Auth::Password {
            password: b"ResizePw!3",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(dec_shrunk.join("tail_src.bin")).unwrap(), data);

    // 3) Long filename: stays under OS path/component limits while exceeding old
    //    `.rpm_tmp_<base>_<hex>.001.part` (+27..+31 chars) overhead on both Windows & Unix.
    let long_dir = dir.path().join("l");
    fs::create_dir(&long_dir).unwrap();
    let dir_len = long_dir.to_string_lossy().len();
    let stem_len = if cfg!(windows) {
        242usize.saturating_sub(dir_len).max(40)
    } else {
        235
    };
    let long_name = format!("{}.vault", "a".repeat(stem_len));
    let long_base = long_dir.join(long_name);
    let (_, _, long_parts) = encrypt_sources_v5_split(
        std::slice::from_ref(&src),
        &long_base,
        MIN_SPLIT_PART_SIZE,
        b"LongPw!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(long_parts.len() >= 2);
    assert!(!has_temp_artifacts(&long_dir));
    let (rep, part_count) = check_vault_integrity_with_parts(&long_parts[0]).unwrap();
    assert!(rep.ok);
    assert_eq!(part_count, Some(long_parts.len()));

    // 4) 4-digit `.999` -> `.1000` transition (discovery, O(N) cache, reader, join)
    let four_dir = dir.path().join("four_digit");
    fs::create_dir(&four_dir).unwrap();
    let four_base = four_dir.join("many.vault");
    let mut expected_four = Vec::with_capacity(1000 * 4);
    let mut part_paths = Vec::with_capacity(1000);
    for idx in 1..=1000usize {
        let p = split_part_path(&four_base, idx);
        let chunk = (idx as u32).to_be_bytes();
        fs::write(&p, chunk).unwrap();
        expected_four.extend_from_slice(&chunk);
        part_paths.push(p);
    }
    assert!(part_paths[998].to_string_lossy().ends_with(".999"));
    assert!(part_paths[999].to_string_lossy().ends_with(".1000"));
    assert_eq!(
        parse_split_part_path(&part_paths[999]),
        Some((four_base.clone(), 1000))
    );

    let mut cache = SplitDiscoveryCache::default();
    for p in &part_paths {
        let set = cache.discover(p).unwrap().unwrap();
        assert_eq!(set.part_count(), 1000);
        assert_eq!(set.first_part(), part_paths[0]);
    }
    let joined_four = dir.path().join("joined_four.vault");
    let (_, joined_len) = join_vault_parts(
        &part_paths[999],
        Some(&joined_four),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(joined_len as usize, expected_four.len());
    assert_eq!(fs::read(&joined_four).unwrap(), expected_four);

    // 5) `SplitVolumeReader::new` recomputes mismatched `total_len` consistently
    let mismatched_set = SplitVolumeSet {
        base: four_base.clone(),
        parts: vec![
            SplitVolumePart {
                path: part_paths[0].clone(),
                len: 4,
            },
            SplitVolumePart {
                path: part_paths[1].clone(),
                len: 4,
            },
        ],
        total_len: 999_999,
    };
    let mut reader = SplitVolumeReader::new(mismatched_set);
    assert_eq!(reader.total_len(), 8);
    assert_eq!(reader.seek(SeekFrom::End(0)).unwrap(), 8);

    // 6) Upfront `MIN_SPLIT_PART_SIZE` / `MAX_SPLIT_PARTS` validation & `EncryptProfile::sanitize`
    assert!(matches!(
        encrypt_sources_v5_split(
            std::slice::from_ref(&src),
            &dir.path().join("too_small.vault"),
            MIN_SPLIT_PART_SIZE - 1,
            b"Small!1",
            &opts,
            Arc::new(|_, _| {}),
            Arc::clone(&cancel),
            |_| {},
        ),
        Err(StorageError::InvalidPath(_))
    ));
    let huge_container_opts = EncryptOptions {
        container_size_bytes: Some(1024 * 1024 * 1024), // 1 GiB / 64 KiB = 16384 > 9999 parts
        ..opts
    };
    assert!(matches!(
        encrypt_sources_v5_split(
            std::slice::from_ref(&src),
            &dir.path().join("too_many.vault"),
            MIN_SPLIT_PART_SIZE,
            b"TooMany!1",
            &huge_container_opts,
            Arc::new(|_, _| {}),
            Arc::clone(&cancel),
            |_| {},
        ),
        Err(StorageError::LimitExceeded(_))
    ));
    let mut prof = EncryptProfile {
        name: "TooManyParts".into(),
        container_size_mib: Some(20_000),
        split_part_mib: Some(1),
        ..EncryptProfile::default()
    };
    assert!(prof.sanitize());
    assert_eq!(prof.split_part_mib, None);
}

#[test]
fn combinatorial_stealth_hidden_rs_keyfile_recovery_split_matrix() {
    let dir = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let decoy = dir.path().join("decoy.bin");
    let hidden = dir.path().join("hidden.bin");
    let decoy_bytes = deterministic_bytes(32 * 1024, 91);
    let hidden_bytes = deterministic_bytes(32 * 1024, 92);
    fs::write(&decoy, &decoy_bytes).unwrap();
    fs::write(&hidden, &hidden_bytes).unwrap();

    // 1) Stealth + Hidden + Split
    let sh_base = dir.path().join("stealth_hidden.bin");
    let sh_opts = HiddenEncryptOptions {
        stealth: true,
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        container_size_bytes: 256 * 1024,
        ..Default::default()
    };
    let (_, _, _, sh_parts) = encrypt_hidden_sources_v5_split(
        std::slice::from_ref(&decoy),
        std::slice::from_ref(&hidden),
        &sh_base,
        MIN_SPLIT_PART_SIZE,
        b"ShDecoy!1",
        b"ShHidden!2",
        &sh_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(sh_parts.len(), 4);
    let sh_dec_d = dir.path().join("sh_dec_d");
    decrypt_vault_v5_with_stealth_kdf(
        &sh_parts[0],
        &sh_dec_d,
        Auth::Password {
            password: b"ShDecoy!1",
            keyfile_hash: None,
        },
        None,
        &KdfParams::fast_test(),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(sh_dec_d.join("decoy.bin")).unwrap(), decoy_bytes);

    let sh_dec_h = dir.path().join("sh_dec_h");
    decrypt_vault_v5_with_stealth_kdf(
        &sh_parts[2],
        &sh_dec_h,
        Auth::Password {
            password: b"ShHidden!2",
            keyfile_hash: None,
        },
        None,
        &KdfParams::fast_test(),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(sh_dec_h.join("hidden.bin")).unwrap(), hidden_bytes);

    // 2) Reed-Solomon + Hidden + Split (corrupt .002, repair in place, decrypt BOTH compartments)
    let rsh_base = dir.path().join("rs_hidden.vault");
    let rsh_opts = HiddenEncryptOptions {
        reed_solomon: true,
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        container_size_bytes: 256 * 1024,
        ..Default::default()
    };
    let (_, _, _, rsh_parts) = encrypt_hidden_sources_v5_split(
        std::slice::from_ref(&decoy),
        std::slice::from_ref(&hidden),
        &rsh_base,
        MIN_SPLIT_PART_SIZE,
        b"RsHidDecoy!1",
        b"RsHidSecret!2",
        &rsh_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(rsh_parts.len() >= 4);
    let mut p2_bytes = fs::read(&rsh_parts[1]).unwrap();
    for b in &mut p2_bytes[1200..1248] {
        *b ^= 0xFF;
    }
    fs::write(&rsh_parts[1], &p2_bytes).unwrap();
    let rep = repair_vault_v5(&rsh_parts[1], None, Arc::clone(&cancel)).unwrap();
    assert_eq!(rep.repaired_bytes, 48);

    let rsh_dec_d = dir.path().join("rsh_dec_d");
    decrypt_vault_v5(
        &rsh_parts[0],
        &rsh_dec_d,
        Auth::Password {
            password: b"RsHidDecoy!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(rsh_dec_d.join("decoy.bin")).unwrap(), decoy_bytes);

    let rsh_dec_h = dir.path().join("rsh_dec_h");
    decrypt_vault_v5(
        &rsh_parts[0],
        &rsh_dec_h,
        Auth::Password {
            password: b"RsHidSecret!2",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(
        fs::read(rsh_dec_h.join("hidden.bin")).unwrap(),
        hidden_bytes
    );

    // 3) Stealth + Keyfile + Recovery + Split
    let kf_hash = hash_keyfile_reader(&mut Cursor::new(b"stealth-split-keyfile-material")).unwrap();
    let rec_entropy = generate_recovery_entropy();
    let mnemonic = entropy_to_mnemonic(&rec_entropy).unwrap();
    let recovered_key = mnemonic_to_entropy(&mnemonic).unwrap();

    let skr_src = dir.path().join("skr.bin");
    let skr_data = deterministic_bytes(110 * 1024, 93);
    fs::write(&skr_src, &skr_data).unwrap();
    let skr_base = dir.path().join("stealth_kf_rec.dat");
    let skr_opts = EncryptOptions {
        stealth: true,
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        keyfile_hash: Some(kf_hash.clone()),
        recovery_key: Some(rec_entropy),
        ..Default::default()
    };
    let (_, _, skr_parts) = encrypt_sources_v5_split(
        &[skr_src],
        &skr_base,
        MIN_SPLIT_PART_SIZE,
        b"StealthKfRec!1",
        &skr_opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(skr_parts.len() >= 2);

    // Password without keyfile must fail
    assert!(decrypt_vault_v5_with_stealth_kdf(
        &skr_parts[0],
        &dir.path().join("skr_fail"),
        Auth::Password {
            password: b"StealthKfRec!1",
            keyfile_hash: None,
        },
        None,
        &KdfParams::fast_test(),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .is_err());

    // Password + keyfile succeeds
    let skr_dec_pw = dir.path().join("skr_dec_pw");
    decrypt_vault_v5_with_stealth_kdf(
        &skr_parts[0],
        &skr_dec_pw,
        Auth::Password {
            password: b"StealthKfRec!1",
            keyfile_hash: Some(&kf_hash),
        },
        None,
        &KdfParams::fast_test(),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(skr_dec_pw.join("skr.bin")).unwrap(), skr_data);

    // 24-word recovery phrase succeeds without keyfile
    let skr_dec_rec = dir.path().join("skr_dec_rec");
    decrypt_vault_v5_with_stealth_kdf(
        &skr_parts[1],
        &skr_dec_rec,
        Auth::RecoveryKey(&recovered_key),
        None,
        &KdfParams::fast_test(),
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(skr_dec_rec.join("skr.bin")).unwrap(), skr_data);
}
