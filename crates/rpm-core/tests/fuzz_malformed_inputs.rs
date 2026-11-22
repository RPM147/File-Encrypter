#[path = "support/fuzz.rs"]
mod fuzz;
use rpm_core::{rs::*, *};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::{self, Cursor, Read};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v4_4_0");

fn rs_property(rng: &mut fuzz::SplitMix64) {
    let mut clean = [0; 255];
    rng.fill(&mut clean[..239]);
    encode_codeword(&mut clean).unwrap();
    let mut positions: [usize; 255] = std::array::from_fn(|i| i);
    for i in 0..32 {
        let j = i + rng.index(255 - i);
        positions.swap(i, j);
    }
    for count in [1 + rng.index(8), 9 + rng.index(24)] {
        let mut word = clean;
        for &i in &positions[..count] {
            word[i] ^= (1 + rng.index(255)) as u8;
        }
        let result = correct_codeword(&mut word);
        if count <= 8 {
            assert_eq!(result.unwrap(), count);
            assert_eq!(word, clean);
        }
    }
}

fn exercise_parsers(bytes: &[u8], auth: Auth<'_>) -> Result<(), CryptoError> {
    let _ = header::read_header_and_meta(&mut Cursor::new(bytes));
    let mut cursor = Cursor::new(bytes);
    let _ = probe_rs_header(&mut cursor)?;
    let _ = repair_vault_stream(&mut cursor, &mut io::sink(), None);
    if let Ok(mut reader) = RsSeekableReader::new(&mut cursor) {
        let mut buf = [0; 512];
        let _ = reader.read(&mut buf);
    }
    let _ = vault::check_integrity_reader(&mut cursor)?;
    let unlocked = unlock_seekable(&mut cursor, auth)?;
    decrypt_unlocked_stream(&mut cursor, &mut io::sink(), &unlocked, |_| {}, None)?;
    Ok(())
}

fn mutate_span(bytes: &mut [u8], start: usize, end: usize, rng: &mut fuzz::SplitMix64) {
    let hi = end.min(bytes.len());
    if start >= hi {
        return;
    }
    let orig = bytes[start..hi].to_vec();
    let flips = 1 + rng.index(8);
    for _ in 0..flips {
        let idx = start + rng.index(hi - start);
        bytes[idx] ^= (1 + rng.index(255)) as u8;
    }
    if bytes[start..hi] == orig[..] {
        bytes[start] ^= 1;
    }
}

fn random_mutate(bytes: &mut Vec<u8>, min_off: usize, rng: &mut fuzz::SplitMix64) {
    if bytes.len() <= min_off + 2 {
        bytes.truncate(rng.index(bytes.len().max(1)));
        return;
    }
    match rng.index(4) {
        0 => {
            let len = bytes.len();
            mutate_span(bytes, min_off, len, rng);
        }
        1 => {
            let new_len = min_off + rng.index(bytes.len() - min_off);
            bytes.truncate(new_len);
        }
        2 => {
            let extra = 1 + rng.index(64);
            let old = bytes.len();
            bytes.resize(old + extra, 0);
            rng.fill(&mut bytes[old..]);
        }
        _ => {
            let span = (bytes.len() - min_off).min(1 + rng.index(256));
            let start = min_off + rng.index((bytes.len() - min_off - span) + 1);
            for b in &mut bytes[start..start + span] {
                *b ^= (1 + rng.index(255)) as u8;
            }
        }
    }
}

#[test]
fn deterministic_structural_edge_cases() {
    let load = |n: &str| std::fs::read(format!("{DIR}/{n}.vault")).unwrap();
    let std = load("standard_uncompressed");
    let padded = load("padded_64k");
    let hidden = load("hidden_64k");
    let stealth = load("stealth_standard");
    let rs = load("rs_hidden_64k");
    let entropy = SecretKey::new([42; 32]);
    let hidden_auth = Auth::Password {
        password: b"hidden fixture password",
        keyfile_hash: None,
    };

    // Header length boundaries, invalid UTF-8, and non-JSON.
    for len in [0u32, constants::MAX_HEADER_SIZE as u32 + 1, u32::MAX] {
        let mut b = std.clone();
        b[5..9].copy_from_slice(&len.to_be_bytes());
        assert!(exercise_parsers(&b, Auth::RecoveryKey(&entropy)).is_err());
        assert!(!check_integrity_reader(&mut Cursor::new(&b)).unwrap().ok);
    }
    for byte in [0xff, b'!'] {
        let mut b = std.clone();
        b[9] = byte;
        assert!(exercise_parsers(&b, Auth::RecoveryKey(&entropy)).is_err());
        assert!(!check_integrity_reader(&mut Cursor::new(&b)).unwrap().ok);
    }

    // Out-of-bounds or invalid JSON header values.
    for case in 0..4 {
        let mut b = std.clone();
        let end = 9 + u32::from_be_bytes(b[5..9].try_into().unwrap()) as usize;
        let mut header: Value = serde_json::from_slice(&b[9..end]).unwrap();
        match case {
            0 => header["chunk_size"] = 0.into(),
            1 => header["kdf"]["memory_kib"] = u32::MAX.into(),
            2 => header["flags"] = 255.into(),
            _ => header["kdf"]["iterations"] = 0.into(),
        }
        let json = serde_json::to_vec(&header).unwrap();
        b[5..9].copy_from_slice(&(json.len() as u32).to_be_bytes());
        b.splice(9..end, json);
        assert!(exercise_parsers(&b, Auth::RecoveryKey(&entropy)).is_err());
        assert!(!check_integrity_reader(&mut Cursor::new(&b)).unwrap().ok);
    }

    // Corrupt chunk frame length and final_flag.
    for corrupt_len in [true, false] {
        let mut b = std.clone();
        let (_, _, offset) = header::read_header_and_meta(&mut Cursor::new(&b)).unwrap();
        let frame = &mut b[offset as usize..];
        if corrupt_len {
            frame[..4].fill(255);
        } else {
            frame[4] = 3;
        }
        assert!(exercise_parsers(&b, Auth::RecoveryKey(&entropy)).is_err());
        assert!(!check_integrity_reader(&mut Cursor::new(&b)).unwrap().ok);
    }

    // Trailing byte on padded container.
    let mut extra_padded = padded;
    extra_padded.push(1);
    assert!(exercise_parsers(&extra_padded, Auth::RecoveryKey(&entropy)).is_err());

    // Hidden mini-header corruption.
    let mut bad_hidden = hidden;
    let tail = bad_hidden.len() - 1;
    bad_hidden[tail] ^= 1;
    assert!(exercise_parsers(&bad_hidden, hidden_auth).is_err());

    // Stealth recovery slot, password slot, and truncation edge cases.
    let mut bad_rec_stealth = stealth.clone();
    bad_rec_stealth[140] ^= 1;
    assert!(matches!(
        exercise_parsers(&bad_rec_stealth, Auth::RecoveryKey(&entropy)),
        Err(CryptoError::AuthenticationFailed)
    ));
    let mut bad_pw_stealth = stealth.clone();
    bad_pw_stealth[32] ^= 1;
    assert!(matches!(
        unlock_seekable(
            &mut Cursor::new(bad_pw_stealth),
            Auth::Password {
                password: b"public fixture password",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    let short_stealth = stealth[..247].to_vec();
    assert!(matches!(
        exercise_parsers(&short_stealth, Auth::RecoveryKey(&entropy)),
        Err(CryptoError::AuthenticationFailed)
    ));

    // RS triplicated header repair, block-0 uncorrectable corruption, and truncation.
    let mut rs_hdr = rs.clone();
    for off in [0, 16, 32] {
        rs_hdr[off + 1] ^= 1;
    }
    let mut repaired = Vec::new();
    let report = repair_vault_stream(&mut Cursor::new(&rs_hdr), &mut repaired, None).unwrap();
    assert_eq!(report.repaired_bytes, 3);
    assert_eq!(repaired, rs);

    let mut rs_uncorr = rs.clone();
    for b in &mut rs_uncorr[48..1072] {
        *b ^= 0xcb;
    }
    assert!(
        !check_integrity_reader(&mut Cursor::new(&rs_uncorr))
            .unwrap()
            .ok
    );
    assert!(exercise_parsers(&rs_uncorr, hidden_auth).is_err());

    let mut rs_trunc = rs;
    rs_trunc.pop();
    assert!(probe_rs_header(&mut Cursor::new(&rs_trunc)).unwrap());
    assert!(
        !check_integrity_reader(&mut Cursor::new(&rs_trunc))
            .unwrap()
            .ok
    );
    assert!(exercise_parsers(&rs_trunc, hidden_auth).is_err());
}

#[test]
fn deterministic_malformed_inputs() {
    let load = |n: &str| std::fs::read(format!("{DIR}/{n}.vault")).unwrap();
    let std = load("standard_uncompressed");
    let padded = load("padded_64k");
    let hidden = load("hidden_64k");
    let stealth = load("stealth_standard");
    let rs = load("rs_hidden_64k");
    let entropy = SecretKey::new([42; 32]);
    let hidden_auth = Auth::Password {
        password: b"hidden fixture password",
        keyfile_hash: None,
    };
    let (_, _, std_meta_off) = header::read_header_and_meta(&mut Cursor::new(&std)).unwrap();
    let (_, _, padded_meta_off) = header::read_header_and_meta(&mut Cursor::new(&padded)).unwrap();

    fuzz::corpus(|i, rng| {
        rs_property(rng);
        match i % 6 {
            0 => {
                let mut bytes = std.clone();
                if rng.index(4) == 0 {
                    mutate_span(&mut bytes, 0, 9, rng);
                } else {
                    random_mutate(&mut bytes, std_meta_off as usize, rng);
                }
                assert!(exercise_parsers(&bytes, Auth::RecoveryKey(&entropy)).is_err());
            }
            1 => {
                let mut bytes = padded.clone();
                match rng.index(4) {
                    0 => mutate_span(&mut bytes, 0, 9, rng),
                    1 => mutate_span(
                        &mut bytes,
                        padded_meta_off as usize - 32,
                        padded_meta_off as usize + 21,
                        rng,
                    ),
                    2 => bytes.truncate(rng.index(bytes.len())),
                    _ => {
                        let extra = 1 + rng.index(64);
                        let old = bytes.len();
                        bytes.resize(old + extra, 0);
                        rng.fill(&mut bytes[old..]);
                    }
                }
                assert!(exercise_parsers(&bytes, Auth::RecoveryKey(&entropy)).is_err());
            }
            2 => {
                let mut bytes = hidden.clone();
                match rng.index(3) {
                    0 => {
                        let len = bytes.len();
                        mutate_span(&mut bytes, len - 108, len, rng);
                    }
                    1 => bytes.truncate(rng.index(bytes.len())),
                    _ => {
                        let extra = 1 + rng.index(64);
                        let old = bytes.len();
                        bytes.resize(old + extra, 0);
                        rng.fill(&mut bytes[old..]);
                    }
                }
                assert!(exercise_parsers(&bytes, hidden_auth).is_err());
            }
            3 => {
                let mut bytes = stealth.clone();
                // Mutate salt, recovery slot, encrypted metadata, or masked chunk frames (>= 140),
                // or truncate below 248 bytes so RecoveryKey unlock cannot bypass password-slot damage.
                if rng.index(4) == 0 {
                    bytes.truncate(rng.index(248));
                } else {
                    random_mutate(&mut bytes, 140, rng);
                }
                let err = exercise_parsers(&bytes, Auth::RecoveryKey(&entropy)).unwrap_err();
                assert!(matches!(
                    err,
                    CryptoError::AuthenticationFailed
                        | CryptoError::InvalidFormat(_)
                        | CryptoError::Io(_)
                ));
            }
            4 => {
                let mut bytes = rs.clone();
                if rng.index(2) == 0 {
                    match rng.index(3) {
                        0 => bytes.truncate(rng.index(bytes.len())),
                        1 => bytes.push((1 + rng.index(255)) as u8),
                        _ => {
                            let start = if rng.index(2) == 0 {
                                48
                            } else {
                                bytes.len() - 1024
                            };
                            for b in &mut bytes[start..start + 1024] {
                                *b ^= (1 + rng.index(255)) as u8;
                            }
                        }
                    }
                    assert!(exercise_parsers(&bytes, hidden_auth).is_err());
                } else {
                    random_mutate(&mut bytes, 0, rng);
                    let _ = exercise_parsers(&bytes, hidden_auth);
                }
            }
            _ => {
                let len = match rng.index(5) {
                    0 => 0,
                    1 => rng.index(248),
                    2 => 248 + rng.index(1800),
                    3 => 48 + 256,
                    _ => 48 + RS_BLOCK_WIRE_SIZE,
                };
                let mut bytes = vec![0u8; len];
                rng.fill(&mut bytes);
                match rng.index(3) {
                    0 if len >= 5 => {
                        bytes[..4].copy_from_slice(&VAULT_MAGIC);
                        bytes[4] = VAULT_VERSION;
                    }
                    1 if len >= 16 => bytes[..4].copy_from_slice(b"RPMR"),
                    _ => {}
                }
                assert!(exercise_parsers(&bytes, Auth::RecoveryKey(&entropy)).is_err());
            }
        }
    });
}

#[test]
fn diff_metadata_fuzz_and_boundaries() {
    fn make_meta(entries: Vec<FileManifestEntry>) -> VaultMetadata {
        VaultMetadata {
            filename: "vault".into(),
            source_type: "directory".into(),
            original_size: entries
                .iter()
                .fold(0u64, |acc, e| acc.saturating_add(e.size)),
            file_count: entries.len() as u64,
            created_at: String::new(),
            compressed: true,
            files: entries,
        }
    }

    // Empty, identical, Unicode, and u64::MAX boundary manifests.
    let empty = make_meta(vec![]);
    let same = diff_metadata(&empty, &empty).unwrap();
    assert!(
        same.added.is_empty()
            && same.removed.is_empty()
            && same.changed.is_empty()
            && same.unchanged.is_empty()
    );

    let boundary = make_meta(vec![
        FileManifestEntry {
            path: "Iğdır/ölçü-🔒.txt".into(),
            size: u64::MAX,
            modified_unix: u64::MAX,
        },
        FileManifestEntry {
            path: "zero.bin".into(),
            size: 0,
            modified_unix: 0,
        },
    ]);
    let ab = diff_metadata(&empty, &boundary).unwrap();
    let ba = diff_metadata(&boundary, &empty).unwrap();
    assert_eq!(ab.added, ba.removed);
    assert_eq!(ab.removed, ba.added);

    // Duplicate paths must fail cleanly.
    let dup = make_meta(vec![
        FileManifestEntry {
            path: "dup.txt".into(),
            size: 1,
            modified_unix: 1,
        },
        FileManifestEntry {
            path: "dup.txt".into(),
            size: 2,
            modified_unix: 2,
        },
    ]);
    assert!(matches!(
        diff_metadata(&dup, &empty),
        Err(CryptoError::InvalidFormat(_))
    ));

    let pool = [
        "alpha.txt",
        "dir/beta.bin",
        "dir/nested/Iğdır.txt",
        "empty",
        "img/photo.png",
        "z/last.dat",
    ];
    let mut rng = fuzz::SplitMix64(0x9e37_79b9_u64);
    for _ in 0..200 {
        let mut build = || {
            let mut seen = BTreeSet::new();
            let mut out = Vec::new();
            let count = rng.index(pool.len() + 1);
            for _ in 0..count {
                let p = pool[rng.index(pool.len())];
                if seen.insert(p) {
                    out.push(FileManifestEntry {
                        path: p.into(),
                        size: if rng.index(4) == 0 { 0 } else { rng.next() },
                        modified_unix: if rng.index(4) == 0 { 0 } else { rng.next() },
                    });
                }
            }
            make_meta(out)
        };
        let left = build();
        let right = build();
        let fwd = diff_metadata(&left, &right).unwrap();
        let rev = diff_metadata(&right, &left).unwrap();
        assert_eq!(fwd.added, rev.removed);
        assert_eq!(fwd.removed, rev.added);
        assert_eq!(fwd.changed.len(), rev.changed.len());
        assert_eq!(fwd.unchanged, rev.unchanged);
        assert!(fwd.added.windows(2).all(|w| w[0].path < w[1].path));
        assert!(fwd.removed.windows(2).all(|w| w[0].path < w[1].path));
        assert!(fwd
            .changed
            .windows(2)
            .all(|w| w[0].before.path < w[1].before.path));
    }
}
