use rand::{rngs::StdRng, seq::SliceRandom, Rng, RngCore, SeedableRng};
use rpm_core::{
    rs::{correct_codeword, encode_codeword, RS_BLOCK_DATA_CAP, RS_BLOCK_WIRE_SIZE},
    *,
};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

#[test]
fn unknown_error_locations_include_shortened_words_and_parity() {
    let mut rng = StdRng::seed_from_u64(0xa501);
    for size in [17, 31, 129, 255] {
        let mut clean = vec![0; size];
        rng.fill_bytes(&mut clean);
        encode_codeword(&mut clean).unwrap();
        assert_eq!(correct_codeword(&mut clean).unwrap(), 0);
        for count in 1..=8 {
            for _ in 0..5 {
                let mut positions: Vec<_> = (0..size).collect();
                positions.shuffle(&mut rng);
                let mut copy = clean.clone();
                for i in &positions[..count] {
                    copy[*i] ^= rng.gen_range(1..=255);
                }
                assert_eq!(correct_codeword(&mut copy).unwrap(), count);
                assert_eq!(copy, clean);
            }
        }
        let mut damaged = clean.clone();
        for (i, b) in damaged.iter_mut().take(9).enumerate() {
            *b ^= i as u8 + 1;
        }
        assert!(correct_codeword(&mut damaged).is_err());
    }
    assert!(correct_codeword(&mut [0; 15]).is_err());
}
fn metadata() -> VaultMetadata {
    VaultMetadata {
        filename: "feature.bin".into(),
        source_type: "file".into(),
        original_size: 50000,
        file_count: 1,
        created_at: String::new(),
        compressed: false,
        files: vec![],
    }
}
fn auth(password: &[u8]) -> Auth<'_> {
    Auth::Password {
        password,
        keyfile_hash: None,
    }
}
fn damage(bytes: &mut [u8], start: usize, n: usize) {
    for (i, b) in bytes[start..start + n].iter_mut().enumerate() {
        *b ^= (i % 255 + 1) as u8;
    }
}
fn physical(offset: usize) -> usize {
    let within = offset % RS_BLOCK_DATA_CAP + 4;
    48 + (offset / RS_BLOCK_DATA_CAP) * RS_BLOCK_WIRE_SIZE + (within % 239) * 64 + within / 239
}
#[test]
fn damaged_sectors_recover_identical_envelopes_and_both_compartments() {
    let plain = vec![71; 50000];
    let secret = b"private";
    let meta = metadata();
    let container = 160 * 1024;
    for (padded, hidden) in [(false, false), (true, false), (true, true)] {
        let mut clean = vec![];
        if hidden {
            let opts = HiddenEncryptOptions {
                reed_solomon: true,
                kdf: KdfParams::fast_test(),
                container_size_bytes: container,
                ..Default::default()
            };
            encrypt_hidden_stream(
                &mut plain.as_slice(),
                &mut secret.as_slice(),
                &mut clean,
                &meta,
                &meta,
                b"outer",
                b"inner",
                &opts,
                |_| {},
                |_| {},
                None,
            )
            .unwrap();
        } else {
            let opts = EncryptOptions {
                reed_solomon: true,
                kdf: KdfParams::fast_test(),
                container_size_bytes: padded.then_some(container),
                chunk_size: 16 * 1024,
                ..Default::default()
            };
            encrypt_stream(
                &mut plain.as_slice(),
                &mut clean,
                &meta,
                b"outer",
                &opts,
                |_| {},
                None,
            )
            .unwrap();
        }
        let tmp = tempfile::NamedTempFile::new().unwrap();
        for first_sector in [0, physical(48)] {
            let mut bytes = clean.clone();
            damage(&mut bytes, first_sector, 512);
            // An independent sector in the JSON header, another inside the payload.
            damage(&mut bytes, 48 + 2 * RS_BLOCK_WIRE_SIZE - 231, 512);
            let mut changed = 1024;
            if hidden {
                damage(&mut bytes, physical(container as usize - 108), 512);
                changed += 512;
            }

            std::fs::write(tmp.path(), &bytes).unwrap();
            let report = check_integrity(tmp.path()).unwrap();
            assert!(
                report.ok && report.has_reed_solomon && !report.sha256_only,
                "{}",
                report.message
            );
            assert_eq!(report.rs_repaired_bytes, changed);
            assert_eq!(report.sha256_hex, format!("{:x}", Sha256::digest(&bytes)));
            for (pw, expected) in [
                (b"outer".as_slice(), plain.as_slice()),
                (b"inner", secret.as_slice()),
            ] {
                if pw == b"inner" && !hidden {
                    continue;
                }
                let mut reader = Cursor::new(&bytes);
                assert!(
                    inspect_header_seekable(&mut reader, auth(pw))
                        .unwrap()
                        .has_reed_solomon
                );
                let mut out = vec![];
                decrypt_stream_seekable(&mut reader, &mut out, auth(pw), |_| {}, None).unwrap();
                assert_eq!(out, expected);
                if hidden {
                    // Damaging only the trailing block must count its repairs once, never double-count.
                    let mut tail_damaged = clean.clone();
                    let start = tail_damaged.len() - 512;
                    damage(&mut tail_damaged, start, 512);
                    let rep_info =
                        inspect_header_seekable(&mut Cursor::new(&tail_damaged), auth(pw)).unwrap();
                    assert_eq!(rep_info.rs_repaired_bytes, 512);
                }
            }
            let mut fixed = vec![];
            let report = repair_vault_stream(&mut Cursor::new(&bytes), &mut fixed, None).unwrap();
            assert_eq!(report.repaired_bytes, changed);
            assert_eq!(report.header_repaired, first_sector == 0);
            assert_eq!(fixed, clean);
        }
        // A whole missing block has no syndromes in the surviving words.
        let truncated = &clean[..clean.len() - RS_BLOCK_WIRE_SIZE];
        assert!(repair_vault_stream(&mut Cursor::new(truncated), &mut Vec::new(), None).is_err());
        let mut cancelled = vec![];
        assert!(matches!(
            repair_vault_stream(
                &mut Cursor::new(&clean),
                &mut cancelled,
                Some(&std::sync::atomic::AtomicBool::new(true))
            ),
            Err(CryptoError::Cancelled)
        ));
        assert!(cancelled.is_empty());
        let mut bad = clean.clone();
        damage(&mut bad, 48 + RS_BLOCK_WIRE_SIZE * 2, 1024);
        std::fs::write(tmp.path(), &bad).unwrap();
        assert!(!check_integrity(tmp.path()).unwrap().ok);
        assert!(repair_vault_stream(&mut Cursor::new(&bad), &mut Vec::new(), None).is_err());
        let mut out = vec![];
        assert!(decrypt_stream_seekable(
            &mut Cursor::new(&bad),
            &mut out,
            auth(b"outer"),
            |_| {},
            None
        )
        .is_err());
        assert!(out.len() <= 16 * 1024 && out == plain[..out.len()] && out.len() < plain.len());
        let mut block1_bad = clean.clone();
        damage(&mut block1_bad, 48 + RS_BLOCK_WIRE_SIZE, 1024);
        let mut out_early = vec![];
        assert!(decrypt_stream_seekable(
            &mut Cursor::new(&block1_bad),
            &mut out_early,
            auth(b"outer"),
            |_| {},
            None
        )
        .is_err());
        assert!(out_early.is_empty());
        if hidden {
            // Damage isolated to the outer decoy/padding still allows recovering the intact hidden compartment.
            let mut hidden_ok = vec![];
            decrypt_stream_seekable(
                &mut Cursor::new(&bad),
                &mut hidden_ok,
                auth(b"inner"),
                |_| {},
                None,
            )
            .unwrap();
            assert_eq!(hidden_ok, secret);

            // Uncorrectable 1024-byte damage hitting the trailing hidden mini-header fails hidden decrypt.
            let mut tail_bad = clean.clone();
            let tail_start = tail_bad.len() - 1024;
            damage(&mut tail_bad, tail_start, 1024);
            let mut hidden_out = vec![];
            assert!(decrypt_stream_seekable(
                &mut Cursor::new(&tail_bad),
                &mut hidden_out,
                auth(b"inner"),
                |_| {},
                None
            )
            .is_err());
            assert!(hidden_out.is_empty());
        }
        let rekey = RekeyOptions {
            old_password: b"outer",
            new_password: b"next",
            old_keyfile_hash: None,
            new_keyfile_hash: None,
            new_kdf: None,
        };
        out.clear();
        assert!(matches!(
            rekey_stream(&mut clean.as_slice(), &mut out, &rekey, None),
            Err(CryptoError::UnsupportedOperation(_))
        ));
    }
}
#[test]
fn valid_parity_does_not_authenticate_modified_ciphertext() {
    let data = vec![1; 36000];
    let opts = EncryptOptions {
        reed_solomon: true,
        chunk_size: 16384,
        kdf: KdfParams::fast_test(),
        ..Default::default()
    };
    let mut encoded = vec![];
    encrypt_stream(
        &mut data.as_slice(),
        &mut encoded,
        &metadata(),
        b"pw",
        &opts,
        |_| {},
        None,
    )
    .unwrap();
    let mut inner = vec![];
    RsSeekableReader::new(Cursor::new(encoded))
        .unwrap()
        .read_to_end(&mut inner)
        .unwrap();
    let (_, _, hdr_len) = rpm_core::header::read_header_and_meta(&mut Cursor::new(&inner)).unwrap();

    // Tamper first ciphertext chunk and recompute valid RS parity: nothing may be released.
    let mut first_tampered = inner.clone();
    first_tampered[hdr_len as usize + 5] ^= 1;
    let mut writer = RsEncoderWriter::new(Vec::new()).unwrap();
    writer.write_all(&first_tampered).unwrap();
    let mut out_first = vec![];
    assert!(matches!(
        decrypt_stream_seekable(
            &mut Cursor::new(writer.finish().unwrap()),
            &mut out_first,
            auth(b"pw"),
            |_| {},
            None
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    assert!(out_first.is_empty());

    // Tamper final chunk and recompute valid RS parity: tampered final chunk must never be released.
    *inner.last_mut().unwrap() ^= 1;
    let mut writer = RsEncoderWriter::new(Vec::new()).unwrap();
    writer.write_all(&inner).unwrap();
    let mut out_last = vec![];
    assert!(matches!(
        decrypt_stream_seekable(
            &mut Cursor::new(writer.finish().unwrap()),
            &mut out_last,
            auth(b"pw"),
            |_| {},
            None
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    assert!(out_last.len() <= 2 * 16384);
}
#[test]
fn envelope_seek_boundaries_header_vote_and_mode_conflicts() {
    for n in [0, 1, RS_BLOCK_DATA_CAP, RS_BLOCK_DATA_CAP + 1] {
        let data = vec![55; n];
        let mut w = RsEncoderWriter::new(Vec::new()).unwrap();
        w.write_all(&data).unwrap();
        let mut wire = w.finish().unwrap();
        for offset in [0, 17, 34] {
            wire[offset] ^= 77;
        }
        let mut r = RsSeekableReader::new(Cursor::new(wire)).unwrap();
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), n as u64);
        r.rewind().unwrap();
        let mut out = vec![];
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }
    let mut out = vec![];
    assert!(matches!(
        encrypt_stream(
            &mut &b""[..],
            &mut out,
            &metadata(),
            b"a",
            &EncryptOptions {
                stealth: true,
                reed_solomon: true,
                ..Default::default()
            },
            |_| {},
            None
        ),
        Err(CryptoError::InvalidFormat(_))
    ));
    assert!(matches!(
        encrypt_hidden_stream(
            &mut &b""[..],
            &mut &b""[..],
            &mut out,
            &metadata(),
            &metadata(),
            b"a",
            b"b",
            &HiddenEncryptOptions {
                stealth: true,
                reed_solomon: true,
                ..Default::default()
            },
            |_| {},
            |_| {},
            None
        ),
        Err(CryptoError::InvalidFormat(_))
    ));
    assert!(out.is_empty());
    assert!(matches!(
        repair_vault_stream(&mut Cursor::new(b"any other file"), &mut out, None),
        Err(CryptoError::UnsupportedOperation(_))
    ));

    // Future unsupported RPMR profile with corrupted copy 0 but intact copy 1/2 must be flagged.
    let mut w = RsEncoderWriter::new(Vec::new()).unwrap();
    w.write_all(b"payload").unwrap();
    let mut future_wire = w.finish().unwrap();
    let mut future_copy = *b"RPMR\x02\x10\x40\0\0\0\0\0\0\0\0\0";
    let mut crc = !0u32;
    for &b in &future_copy[..12] {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    future_copy[12..16].copy_from_slice(&(!crc).to_be_bytes());
    future_wire[0..16].fill(0xaa);
    future_wire[16..32].copy_from_slice(&future_copy);
    future_wire[32..48].copy_from_slice(&future_copy);
    let err = RsSeekableReader::new(Cursor::new(&future_wire))
        .err()
        .expect("future profile rejected");
    assert!(err.to_string().contains("unsupported Reed-Solomon"));
    let repair_err = repair_vault_stream(&mut Cursor::new(&future_wire), &mut out, None)
        .expect_err("future profile repair rejected");
    assert!(repair_err.to_string().contains("unsupported Reed-Solomon"));
}
