#[path = "../../rpm-core/tests/support/fuzz.rs"]
mod fuzz;
use rpm_core::{
    constants::MIN_CHUNK_SIZE, encrypt_stream, inspect_header_seekable_with_kdf, Auth,
    EncryptOptions, KdfParams, VaultMetadata,
};
use rpm_storage::{
    decrypt_vault_selected_v5, decrypt_vault_v5, decrypt_vault_v5_with_stealth_kdf,
    extract_entry_to_memory_v5, extract_entry_to_memory_v5_with_stealth_kdf, repair_vault_v5,
    StorageError,
};
use std::{
    fs,
    io::Cursor,
    path::Path,
    sync::{atomic::AtomicBool, Arc},
};

fn cancel() -> Arc<AtomicBool> {
    Arc::new(false.into())
}

fn auth() -> Auth<'static> {
    Auth::Password {
        password: b"test",
        keyfile_hash: None,
    }
}

fn fixture_auth() -> Auth<'static> {
    Auth::Password {
        password: b"public fixture password",
        keyfile_hash: None,
    }
}

fn reject_payload_with(
    file: &Path,
    root: &Path,
    creds: Auth<'_>,
    member_name: &str,
    stealth_kdf: &KdfParams,
) -> (StorageError, StorageError, StorageError) {
    let e_full = decrypt_vault_v5_with_stealth_kdf(
        file,
        root,
        creds,
        None,
        stealth_kdf,
        Arc::new(|_, _| {}),
        cancel(),
    )
    .unwrap_err();
    let e_sel = decrypt_vault_v5_with_stealth_kdf(
        file,
        root,
        creds,
        Some(&[member_name.to_string()]),
        stealth_kdf,
        Arc::new(|_, _| {}),
        cancel(),
    )
    .unwrap_err();
    let e_mem = extract_entry_to_memory_v5_with_stealth_kdf(
        file,
        creds,
        member_name,
        64,
        stealth_kdf,
        Arc::new(|_, _| {}),
        cancel(),
    )
    .unwrap_err();
    assert!(!root.exists());
    (e_full, e_sel, e_mem)
}

#[test]
fn rejected_storage_inputs_leave_no_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("input");
    let output = dir.path().join("out");
    let repaired = dir.path().join("repaired");
    let fixture =
        include_bytes!("../../rpm-core/tests/fixtures/v4_4_0/standard_uncompressed.vault");
    let rs_fixture = include_bytes!("../../rpm-core/tests/fixtures/v4_4_0/rs_standard.vault");
    let fast = KdfParams::fast_test();
    let (_, _, fixture_meta_off) =
        rpm_core::header::read_header_and_meta(&mut Cursor::new(fixture)).unwrap();
    let meta_off = fixture_meta_off as usize;

    // Build multi-chunk Standard and Stealth vaults (4+ chunks at MIN_CHUNK_SIZE) once so
    // late-chunk mutations genuinely stream chunk-0 files into staging before failing AEAD auth.
    let mut multi_archive = member(b"first", b'0');
    multi_archive.extend(sized_member(
        b"filler.bin",
        &vec![0x3Cu8; 3 * MIN_CHUNK_SIZE as usize],
    ));
    multi_archive.extend_from_slice(&[0u8; 1024]);
    let multi_meta = VaultMetadata {
        filename: "multi".into(),
        source_type: "directory".into(),
        file_count: 2,
        original_size: 3 * MIN_CHUNK_SIZE as u64,
        created_at: String::new(),
        compressed: false,
        files: vec![],
    };
    let mut multi_std = Vec::new();
    encrypt_stream(
        &mut multi_archive.as_slice(),
        &mut multi_std,
        &multi_meta,
        b"test",
        &EncryptOptions {
            kdf: fast,
            chunk_size: MIN_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        |_| {},
        None,
    )
    .unwrap();
    let (_, _, multi_std_meta_off_u64) =
        rpm_core::header::read_header_and_meta(&mut Cursor::new(&multi_std)).unwrap();
    let multi_std_meta_off = multi_std_meta_off_u64 as usize;
    let multi_std_chunk1_off =
        multi_std_meta_off + 5 + MIN_CHUNK_SIZE as usize + rpm_core::constants::AES_TAG_SIZE;
    assert!(multi_std.len() > multi_std_chunk1_off + 64);

    let mut multi_stealth = Vec::new();
    encrypt_stream(
        &mut multi_archive.as_slice(),
        &mut multi_stealth,
        &multi_meta,
        b"test",
        &EncryptOptions {
            stealth: true,
            kdf: fast,
            chunk_size: MIN_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        |_| {},
        None,
    )
    .unwrap();
    assert!(multi_stealth.len() > 2 * MIN_CHUNK_SIZE as usize);

    // Sanity-check that credentials unlock every unmodified fixture/vault so mutations
    // genuinely exercise post-unlock streaming decryption, unpacking, and atomic rollback.
    assert!(
        inspect_header_seekable_with_kdf(&mut Cursor::new(fixture), fixture_auth(), &fast).is_ok()
    );
    assert!(
        inspect_header_seekable_with_kdf(&mut Cursor::new(rs_fixture), fixture_auth(), &fast)
            .is_ok()
    );
    assert!(inspect_header_seekable_with_kdf(&mut Cursor::new(&multi_std), auth(), &fast).is_ok());
    assert!(
        inspect_header_seekable_with_kdf(&mut Cursor::new(&multi_stealth), auth(), &fast).is_ok()
    );

    fuzz::corpus(|iter, rng| {
        let (data, creds, member_name, header_must_fail) = match iter % 6 {
            0 => {
                let mut buf = vec![0u8; rng.index(1025)];
                rng.fill(&mut buf);
                (buf, fixture_auth(), "note.txt", true)
            }
            1 => {
                let mut buf = fixture.to_vec();
                match rng.index(4) {
                    0 => {
                        // Damage magic / version / header length prefix.
                        let orig = buf[..9].to_vec();
                        let flips = 1 + rng.index(4);
                        for _ in 0..flips {
                            let pos = rng.index(9);
                            buf[pos] ^= (1 + rng.index(255)) as u8;
                        }
                        if buf[..9] == orig[..] {
                            buf[0] ^= 1;
                        }
                    }
                    1 => {
                        // Damage authenticated metadata or payload chunk frames.
                        let start = if rng.index(3) == 0 {
                            meta_off.saturating_sub(32)
                        } else {
                            meta_off
                        };
                        let orig = buf[start..].to_vec();
                        let flips = 1 + rng.index(8);
                        for _ in 0..flips {
                            let pos = start + rng.index(buf.len() - start);
                            buf[pos] ^= (1 + rng.index(255)) as u8;
                        }
                        if buf[start..] == orig[..] {
                            buf[start] ^= 1;
                        }
                    }
                    2 => {
                        // Truncate header, metadata, or payload.
                        let new_len = rng.index(buf.len());
                        buf.truncate(new_len);
                    }
                    _ => {
                        // Append unauthenticated trailing bytes after final chunk.
                        let extra = 1 + rng.index(64);
                        let old = buf.len();
                        buf.resize(old + extra, 0);
                        rng.fill(&mut buf[old..]);
                    }
                }
                // Exact prefix comparison avoids false expectations if two flips cancel in metadata.
                let header_damaged = buf.len() < meta_off || buf[..meta_off] != fixture[..meta_off];
                (buf, fixture_auth(), "note.txt", header_damaged)
            }
            2 => {
                let len = 9 + rng.index(1016);
                let mut buf = vec![0u8; len];
                rng.fill(&mut buf);
                buf[..4].copy_from_slice(b"RPMV");
                buf[4] = 5;
                if rng.index(2) == 0 {
                    buf[5..9].fill(255);
                }
                (buf, fixture_auth(), "note.txt", true)
            }
            3 => {
                let mut buf = rs_fixture.to_vec();
                let start = 48 + rng.index(buf.len() - 48 - 1024);
                for b in &mut buf[start..start + 1024] {
                    *b ^= (1 + rng.index(255)) as u8;
                }
                (buf, fixture_auth(), "note.txt", true)
            }
            4 => {
                // Multi-chunk Standard vault: mutate/truncate/append strictly after chunk 0 so
                // chunk 0 streams real tar members into staging before AEAD failure triggers rollback.
                let mut buf = multi_std.clone();
                match rng.index(3) {
                    0 => {
                        let orig = buf[multi_std_chunk1_off..].to_vec();
                        let flips = 1 + rng.index(8);
                        for _ in 0..flips {
                            let pos =
                                multi_std_chunk1_off + rng.index(buf.len() - multi_std_chunk1_off);
                            buf[pos] ^= (1 + rng.index(255)) as u8;
                        }
                        if buf[multi_std_chunk1_off..] == orig[..] {
                            buf[multi_std_chunk1_off] ^= 1;
                        }
                    }
                    1 => {
                        let new_len =
                            multi_std_chunk1_off + rng.index(buf.len() - multi_std_chunk1_off);
                        buf.truncate(new_len);
                    }
                    _ => {
                        let extra = 1 + rng.index(64);
                        let old = buf.len();
                        buf.resize(old + extra, 0);
                        rng.fill(&mut buf[old..]);
                    }
                }
                (buf, auth(), "first", false)
            }
            _ => {
                // Multi-chunk Stealth vault: mutate salt/pw-slot, truncate header, or corrupt/append tail chunks.
                let mut buf = multi_stealth.clone();
                let header_damaged = match rng.index(4) {
                    0 => {
                        let pos = rng.index(140);
                        buf[pos] ^= (1 + rng.index(255)) as u8;
                        true
                    }
                    1 => {
                        buf.truncate(rng.index(248));
                        true
                    }
                    2 => {
                        // Damage final chunk ciphertext/tag (after chunk 0 has already streamed).
                        let tail_start = buf.len() - MIN_CHUNK_SIZE as usize;
                        let pos = tail_start + rng.index(MIN_CHUNK_SIZE as usize);
                        buf[pos] ^= (1 + rng.index(255)) as u8;
                        false
                    }
                    _ => {
                        let extra = 1 + rng.index(64);
                        let old = buf.len();
                        buf.resize(old + extra, 0);
                        rng.fill(&mut buf[old..]);
                        false
                    }
                };
                (buf, auth(), "first", header_damaged)
            }
        };
        fs::write(&file, &data).unwrap();
        let inspect =
            inspect_header_seekable_with_kdf(&mut fs::File::open(&file).unwrap(), creds, &fast);
        if header_must_fail {
            assert!(inspect.is_err());
        } else {
            assert!(inspect.is_ok());
        }
        let (e_full, e_sel, e_mem) = reject_payload_with(&file, &output, creds, member_name, &fast);
        if !header_must_fail {
            assert!(
                matches!(e_full, StorageError::Crypto(_)),
                "post-unlock full decrypt returned {e_full:?}"
            );
            assert!(
                matches!(e_sel, StorageError::Crypto(_)),
                "post-unlock selected decrypt returned {e_sel:?}"
            );
            assert!(
                matches!(e_mem, StorageError::Crypto(_)),
                "post-unlock memory preview returned {e_mem:?}"
            );
        }
        assert!(repair_vault_v5(&file, Some(&repaired), cancel()).is_err());
        assert!(!repaired.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(fs::read(&file).unwrap(), data);
    });
}

fn member(name: &[u8], kind: u8) -> Vec<u8> {
    let mut out = Vec::new();
    if name.len() > 100 {
        // Emit a valid GNU LongName ('L') entry so long TEMP paths never corrupt tar header fields.
        let mut long_hdr = tar::Header::new_gnu();
        long_hdr.set_mode(0o600);
        long_hdr.set_size((name.len() + 1) as u64);
        long_hdr.set_entry_type(tar::EntryType::GNULongName);
        let marker = b"././@LongLink";
        long_hdr.as_mut_bytes()[..marker.len()].copy_from_slice(marker);
        long_hdr.set_cksum();
        out.extend_from_slice(long_hdr.as_bytes());
        out.extend_from_slice(name);
        out.push(0);
        let pad = (512 - ((name.len() + 1) % 512)) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
    }

    let mut h = tar::Header::new_gnu();
    h.set_mode(0o600);
    h.set_size(0);
    h.set_entry_type(tar::EntryType::new(kind));
    if matches!(kind, b'1' | b'2') {
        h.set_link_name("../outside").unwrap();
    }
    let short_len = name.len().min(100);
    h.as_mut_bytes()[..short_len].copy_from_slice(&name[..short_len]);
    h.set_cksum();
    out.extend_from_slice(h.as_bytes());
    out
}

fn sized_member(name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut h = tar::Header::new_gnu();
    h.set_mode(0o600);
    h.set_size(payload.len() as u64);
    h.set_entry_type(tar::EntryType::Regular);
    let short_len = name.len().min(100);
    h.as_mut_bytes()[..short_len].copy_from_slice(&name[..short_len]);
    h.set_cksum();
    let mut out = h.as_bytes().to_vec();
    out.extend_from_slice(payload);
    let pad = (512 - (payload.len() % 512)) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

#[test]
fn authenticated_malformed_archives_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = dir.path().join("sandbox");
    fs::create_dir(&sandbox).unwrap();
    let outside = dir.path().join("sentinel");
    fs::write(&outside, b"untouched").unwrap();
    let absolute = outside.to_string_lossy().replace('\\', "/");
    let long_traversal = format!("{}../escape.txt", "nested_dir/".repeat(12));
    assert!(long_traversal.len() > 100);

    let mut cases: Vec<(Vec<u8>, bool, bool)> = [
        ("../escape.txt", b'0'),
        ("sub/../../escape.txt", b'0'),
        (r"sub\..\..\escape.txt", b'0'),
        (r"\escape.txt", b'0'),
        ("/tmp/escape.txt", b'0'),
        (r"C:\escape.txt", b'0'),
        (&absolute, b'0'),
        (&long_traversal, b'0'),
        ("link", b'2'),
        ("link", b'1'),
    ]
    .iter()
    .map(|(p, t)| (member(p.as_bytes(), *t), false, true))
    .collect();
    // Multi-chunk (> 8 pipe slots) authenticated archive with an early Tar-Slip member:
    // ensures early unpack rejection surfaces InvalidPath rather than BrokenPipe.
    let mut multi_chunk_slip = member(b"../escape_multichunk.txt", b'0');
    multi_chunk_slip.extend(sized_member(
        b"filler.bin",
        &vec![0x55u8; 12 * MIN_CHUNK_SIZE as usize],
    ));
    multi_chunk_slip.extend_from_slice(&[0u8; 1024]);
    cases.push((multi_chunk_slip, false, true));

    cases.push((member(b"incomplete", b'0')[..100].to_vec(), false, false));
    cases.push((b"invalid gzip".to_vec(), true, false));
    // Multi-chunk (> 8 pipe slots) invalid gzip header: ensures early GzDecoder failure
    // surfaces StorageError::Io rather than BrokenPipe from the decryptor thread.
    let mut multi_chunk_bad_gzip = b"invalid gzip".to_vec();
    multi_chunk_bad_gzip.resize(12 * MIN_CHUNK_SIZE as usize, 0xAA);
    cases.push((multi_chunk_bad_gzip, true, false));

    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    use std::io::Write;
    gzip.write_all(&member(b"first", b'0')).unwrap();
    gzip.write_all(&[0; 1024]).unwrap();
    let mut encoded = gzip.finish().unwrap();
    let crc = encoded.len() - 8;
    encoded[crc] ^= 1;
    cases.push((encoded, true, false));

    for (tail, compressed, expect_invalid_path) in cases {
        let mut archive = if compressed {
            Vec::new()
        } else {
            member(b"first", b'0')
        };
        archive.extend(tail);
        let options = EncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            compressed,
            ..Default::default()
        };
        let meta = VaultMetadata {
            filename: "test".into(),
            source_type: "file".into(),
            file_count: 2,
            original_size: 0,
            created_at: String::new(),
            compressed,
            files: vec![],
        };
        let file = sandbox.join("input");
        encrypt_stream(
            &mut archive.as_slice(),
            &mut fs::File::create(&file).unwrap(),
            &meta,
            b"test",
            &options,
            |_| {},
            None,
        )
        .unwrap();
        // Header inspection intentionally reads no tar bytes.
        assert_eq!(
            inspect_header_seekable_with_kdf(
                &mut fs::File::open(&file).unwrap(),
                auth(),
                &KdfParams::fast_test(),
            )
            .unwrap()
            .metadata,
            meta
        );
        let out_root = sandbox.join("out");
        let e_full =
            decrypt_vault_v5(&file, &out_root, auth(), Arc::new(|_, _| {}), cancel()).unwrap_err();
        let e_sel = decrypt_vault_selected_v5(
            &file,
            &out_root,
            auth(),
            &["first".to_string()],
            Arc::new(|_, _| {}),
            cancel(),
        )
        .unwrap_err();
        let e_mem =
            extract_entry_to_memory_v5(&file, auth(), "first", 64, Arc::new(|_, _| {}), cancel())
                .unwrap_err();
        assert!(!out_root.exists());
        if expect_invalid_path {
            assert!(
                matches!(e_full, StorageError::InvalidPath(_)),
                "full decrypt returned {e_full:?}"
            );
            assert!(
                matches!(e_sel, StorageError::InvalidPath(_)),
                "selected decrypt returned {e_sel:?}"
            );
            assert!(
                matches!(e_mem, StorageError::InvalidPath(_)),
                "memory preview returned {e_mem:?}"
            );
        } else {
            assert!(
                matches!(e_full, StorageError::Io(_)),
                "full decrypt returned {e_full:?}"
            );
            assert!(
                matches!(e_sel, StorageError::Io(_)),
                "selected decrypt returned {e_sel:?}"
            );
            assert!(
                matches!(e_mem, StorageError::Io(_)),
                "memory preview returned {e_mem:?}"
            );
        }
        assert_eq!(fs::read_dir(&sandbox).unwrap().count(), 1);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    }
}
