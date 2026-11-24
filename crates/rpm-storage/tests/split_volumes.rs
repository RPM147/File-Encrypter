use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rpm_core::constants::MIN_CHUNK_SIZE;
use rpm_core::{
    hash_keyfile_reader, inspect_header_seekable_with_kdf, Auth, EncryptOptions,
    HiddenEncryptOptions, KdfParams,
};
use rpm_storage::{
    check_vault_integrity, decrypt_vault_selected_v5, decrypt_vault_v5,
    decrypt_vault_v5_with_stealth_kdf, discover_split_parts, encrypt_hidden_sources_v5_split,
    encrypt_sources_v5, encrypt_sources_v5_split, extract_entry_to_memory_v5,
    is_vault_or_split_filename, join_vault_parts, open_vault_reader, parse_split_part_path,
    rekey_vault_v5, repair_vault_v5, split_part_path, split_vault_file, unique_split_base,
    vault_display_stem, SplitVolumePart, SplitVolumeReader, SplitVolumeSet, StorageError,
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
        name.starts_with(".rpm_tmp_") || name.ends_with(".part")
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
