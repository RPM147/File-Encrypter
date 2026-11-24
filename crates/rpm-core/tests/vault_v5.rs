use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};

use rpm_core::constants::{
    FLAG_COMPRESSED, FLAG_HAS_RECOVERY, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, VAULT_MAGIC,
};
use rpm_core::{
    check_integrity, decrypt_stream, encrypt_stream, entropy_to_mnemonic,
    generate_recovery_entropy, hash_keyfile_reader, inspect_header, mnemonic_to_entropy,
    rekey_stream, Auth, CryptoError, EncryptOptions, KdfParams, RekeyOptions, SecretKey,
    VaultHeader, VaultMetadata, VAULT_VERSION,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

fn sample_metadata() -> VaultMetadata {
    VaultMetadata {
        filename: "payload.tar.gz".into(),
        source_type: "file".into(),
        original_size: 12345,
        file_count: 1,
        created_at: "2026-11-20T12:00:00Z".into(),
        compressed: true,
        files: vec![],
    }
}

fn fast_opts() -> EncryptOptions {
    EncryptOptions {
        reed_solomon: false,
        stealth: false,
        kdf: KdfParams::fast_test(),
        chunk_size: 16 * 1024, // 16 KiB minimum to exercise multi-chunk logic with small data
        recovery_key: None,
        keyfile_hash: None,
        compressed: true,
        container_size_bytes: None,
    }
}

#[test]
fn empty_and_multichunk_round_trip() {
    for size in [
        0usize,
        1,
        16 * 1024 - 1,
        16 * 1024,
        16 * 1024 + 1,
        16 * 1024 * 3 + 777,
    ] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let mut vault = Vec::new();
        let summary = encrypt_stream(
            &mut Cursor::new(&data),
            &mut vault,
            &sample_metadata(),
            b"StrongPassword!1",
            &fast_opts(),
            |_| {},
            None,
        )
        .unwrap();
        assert_eq!(summary.bytes_encrypted, size as u64);

        let mut out = Vec::new();
        let meta = decrypt_stream(
            &mut Cursor::new(&vault),
            &mut out,
            Auth::Password {
                password: b"StrongPassword!1",
                keyfile_hash: None,
            },
            |_| {},
            None,
        )
        .unwrap();
        assert_eq!(out, data);
        assert_eq!(meta.filename, "payload.tar.gz");
    }
}

#[test]
fn chunk_tampering_reordering_truncation_and_trailing_rejected_before_output() {
    let data = vec![0x42u8; 16 * 1024 * 3 + 123]; // 4 chunks
    let mut vault = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&data),
        &mut vault,
        &sample_metadata(),
        b"pw",
        &fast_opts(),
        |_| {},
        None,
    )
    .unwrap();

    // Locate where chunk 0 begins (after header + enc_meta)
    let hdr_len = u32::from_be_bytes(vault[5..9].try_into().unwrap()) as usize;
    let hdr: rpm_core::VaultHeader = serde_json::from_slice(&vault[9..9 + hdr_len]).unwrap();
    let payload_offset = 9 + hdr_len + hdr.encrypted_meta_len as usize;

    // 1. Corrupt byte in chunk 0 -> fails BEFORE writing any byte to output
    let mut tampered = vault.clone();
    tampered[payload_offset + 10] ^= 0xFF;
    let mut out = Vec::new();
    let res = decrypt_stream(
        &mut Cursor::new(&tampered),
        &mut out,
        Auth::Password {
            password: b"pw",
            keyfile_hash: None,
        },
        |_| {},
        None,
    );
    assert!(matches!(res, Err(CryptoError::AuthenticationFailed)));
    assert!(out.is_empty(), "unverified plaintext must never be written");

    // 2. Truncation: drop the last 5 bytes
    let mut truncated = vault.clone();
    truncated.truncate(truncated.len() - 5);
    assert!(matches!(
        decrypt_stream(
            &mut Cursor::new(&truncated),
            &mut Vec::new(),
            Auth::Password {
                password: b"pw",
                keyfile_hash: None,
            },
            |_| {},
            None,
        ),
        Err(CryptoError::AuthenticationFailed)
    ));

    // 3. Trailing byte append after final chunk
    let mut appended = vault.clone();
    appended.push(0x00);
    assert!(matches!(
        decrypt_stream(
            &mut Cursor::new(&appended),
            &mut Vec::new(),
            Auth::Password {
                password: b"pw",
                keyfile_hash: None,
            },
            |_| {},
            None,
        ),
        Err(CryptoError::AuthenticationFailed)
    ));

    // 4. Chunk reordering: swap chunk 0 and chunk 1 bytes
    let c0_len = 5 + 16 * 1024 + 16;
    let c1_len = 5 + 16 * 1024 + 16;
    let mut reordered = vault.clone();
    let c0 = reordered[payload_offset..payload_offset + c0_len].to_vec();
    let c1 = reordered[payload_offset + c0_len..payload_offset + c0_len + c1_len].to_vec();
    reordered[payload_offset..payload_offset + c1_len].copy_from_slice(&c1);
    reordered[payload_offset + c1_len..payload_offset + c1_len + c0_len].copy_from_slice(&c0);
    let mut out2 = Vec::new();
    assert!(matches!(
        decrypt_stream(
            &mut Cursor::new(&reordered),
            &mut out2,
            Auth::Password {
                password: b"pw",
                keyfile_hash: None,
            },
            |_| {},
            None,
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    assert!(out2.is_empty());
}

#[test]
fn keyfile_recovery_rekey_inspect_and_integrity_work() {
    let kf1 = hash_keyfile_reader(&mut Cursor::new(b"secret-keyfile-material")).unwrap();
    let kf2 = hash_keyfile_reader(&mut Cursor::new(b"wrong-keyfile-material")).unwrap();
    let rec_entropy = generate_recovery_entropy();
    let phrase = entropy_to_mnemonic(&rec_entropy).unwrap();
    assert_eq!(phrase.split_whitespace().count(), 24);
    let parsed_entropy = mnemonic_to_entropy(&phrase).unwrap();

    let mut opts = fast_opts();
    opts.recovery_key = Some(rec_entropy.clone());
    opts.keyfile_hash = Some(kf1.clone());

    let data = b"chunked AEAD with keyfile and recovery!".repeat(1200);
    let mut vault = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&data),
        &mut vault,
        &sample_metadata(),
        b"InitialPw!1",
        &opts,
        |_| {},
        None,
    )
    .unwrap();

    // Missing keyfile rejected
    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&vault),
            Auth::Password {
                password: b"InitialPw!1",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::KeyfileRequired)
    ));

    // Wrong keyfile rejected
    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&vault),
            Auth::Password {
                password: b"InitialPw!1",
                keyfile_hash: Some(&kf2),
            }
        ),
        Err(CryptoError::AuthenticationFailed)
    ));

    // Correct keyfile inspects cleanly
    let info = inspect_header(
        &mut Cursor::new(&vault),
        Auth::Password {
            password: b"InitialPw!1",
            keyfile_hash: Some(&kf1),
        },
    )
    .unwrap();
    assert_eq!(info.version, VAULT_VERSION);
    assert!(info.has_keyfile && info.has_recovery);

    // Re-key rotates password without decrypting payload, preserving recovery slot
    let mut rekeyed = Vec::new();
    rekey_stream(
        &mut Cursor::new(&vault),
        &mut rekeyed,
        &RekeyOptions {
            old_password: b"InitialPw!1",
            new_password: b"RotatedPw!2",
            old_keyfile_hash: Some(&kf1),
            new_keyfile_hash: Some(&kf1),
            new_kdf: None,
        },
        None,
    )
    .unwrap();

    // Old password rejected, new password succeeds, recovery phrase still succeeds
    assert!(matches!(
        decrypt_stream(
            &mut Cursor::new(&rekeyed),
            &mut Vec::new(),
            Auth::Password {
                password: b"InitialPw!1",
                keyfile_hash: Some(&kf1),
            },
            |_| {},
            None,
        ),
        Err(CryptoError::AuthenticationFailed)
    ));

    let mut out_pw = Vec::new();
    decrypt_stream(
        &mut Cursor::new(&rekeyed),
        &mut out_pw,
        Auth::Password {
            password: b"RotatedPw!2",
            keyfile_hash: Some(&kf1),
        },
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(out_pw, data);

    let mut out_rec = Vec::new();
    decrypt_stream(
        &mut Cursor::new(&rekeyed),
        &mut out_rec,
        Auth::RecoveryKey(&parsed_entropy),
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(out_rec, data);

    // Passwordless integrity check on disk file
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), &rekeyed).unwrap();
    let report = check_integrity(tmp.path()).unwrap();
    assert!(report.ok);
    assert_eq!(report.version, 5);
    assert!(report.chunk_count >= 1);
    assert_eq!(report.sha256_hex.len(), 64);

    // Cancel flag aborts immediately
    let cancel = AtomicBool::new(true);
    assert!(matches!(
        decrypt_stream(
            &mut Cursor::new(&rekeyed),
            &mut Vec::new(),
            Auth::RecoveryKey(&parsed_entropy),
            |_| {},
            Some(&cancel),
        ),
        Err(CryptoError::Cancelled)
    ));
}

#[inline(never)]
fn move_secret_key(k: SecretKey) -> SecretKey {
    k
}

fn rewrite_vault_header(vault: &[u8], mut edit: impl FnMut(&mut VaultHeader)) -> Vec<u8> {
    let hdr_len = u32::from_be_bytes(vault[5..9].try_into().unwrap()) as usize;
    let mut hdr: VaultHeader = serde_json::from_slice(&vault[9..9 + hdr_len]).unwrap();
    edit(&mut hdr);
    let new_json = serde_json::to_vec(&hdr).unwrap();

    let mut out = Vec::with_capacity(vault.len() + new_json.len());
    out.extend_from_slice(&vault[..5]);
    out.extend_from_slice(&(new_json.len() as u32).to_be_bytes());
    out.extend_from_slice(&new_json);
    out.extend_from_slice(&vault[9 + hdr_len..]);
    out
}

#[test]
fn secret_key_heap_stability_clone_zeroize_and_redaction() {
    let k1 = SecretKey::new([0xAAu8; 32]);
    let addr1 = k1.as_bytes().as_ptr() as usize;
    let k2 = move_secret_key(k1);
    assert_eq!(
        k2.as_bytes().as_ptr() as usize,
        addr1,
        "heap backing address must stay pinned across moves"
    );

    let mut k3 = k2.clone();
    assert_ne!(k3.as_bytes().as_ptr() as usize, addr1);
    assert_eq!(k3.as_bytes(), &[0xAAu8; 32]);

    k3.zeroize();
    assert_eq!(k3.as_bytes(), &[0u8; 32]);
    assert_eq!(format!("{k2:?}"), "SecretKey([REDACTED])");
    assert!(SecretKey::from_slice(&[1u8; 31]).is_none());
    assert!(SecretKey::from_slice(&[1u8; 32]).is_some());

    drop(k3);
    drop(k2);
}

#[test]
fn header_flag_tampering_and_malformed_headers_rejected() {
    let data = vec![0x11u8; 1024];
    let mut vault = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&data),
        &mut vault,
        &sample_metadata(),
        b"HeaderPw!1",
        &fast_opts(),
        |_| {},
        None,
    )
    .unwrap();

    // 1. Flip FLAG_COMPRESSED in JSON header -> payload_context mismatch rejects before unpacking
    let compressed_flipped = rewrite_vault_header(&vault, |hdr| hdr.flags ^= FLAG_COMPRESSED);
    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&compressed_flipped),
            Auth::Password {
                password: b"HeaderPw!1",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    let mut out = Vec::new();
    assert!(matches!(
        decrypt_stream(
            &mut Cursor::new(&compressed_flipped),
            &mut out,
            Auth::Password {
                password: b"HeaderPw!1",
                keyfile_hash: None,
            },
            |_| {},
            None,
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    assert!(out.is_empty());

    // 2. Unknown flag bits rejected
    let unknown_flags = rewrite_vault_header(&vault, |hdr| hdr.flags |= 0x80);
    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&unknown_flags),
            Auth::Password {
                password: b"HeaderPw!1",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    // 3. Recovery flag without recovery_slot rejected
    let rec_mismatch = rewrite_vault_header(&vault, |hdr| hdr.flags |= FLAG_HAS_RECOVERY);
    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&rec_mismatch),
            Auth::Password {
                password: b"HeaderPw!1",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    // 4. Too-small / too-large chunk size & malformed vault_id rejected
    let bad_chunk = rewrite_vault_header(&vault, |hdr| hdr.chunk_size = MIN_CHUNK_SIZE - 1);
    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&bad_chunk),
            Auth::Password {
                password: b"HeaderPw!1",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    let bad_vid = rewrite_vault_header(&vault, |hdr| hdr.vault_id = "bad id!".into());
    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&bad_vid),
            Auth::Password {
                password: b"HeaderPw!1",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    // 5. Magic, version 4, truncated headers, corrupt JSON
    let mut bad_magic = vault.clone();
    bad_magic[3] = b'X';
    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&bad_magic),
            Auth::Password {
                password: b"HeaderPw!1",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    let mut v4 = vault.clone();
    v4[4] = 4;
    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&v4),
            Auth::Password {
                password: b"HeaderPw!1",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::UnsupportedVersion(4))
    ));

    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&VAULT_MAGIC),
            Auth::Password {
                password: b"HeaderPw!1",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::InvalidFormat(_))
    ));
}

#[test]
fn kdf_and_recovery_validation_bounds() {
    let invalid_kdfs = [
        KdfParams {
            memory_kib: 4096,
            iterations: 1,
            parallelism: 1,
        },
        KdfParams {
            memory_kib: 5 * 1024 * 1024,
            iterations: 1,
            parallelism: 1,
        },
        KdfParams {
            memory_kib: 8192,
            iterations: 0,
            parallelism: 1,
        },
        KdfParams {
            memory_kib: 8192,
            iterations: 65,
            parallelism: 1,
        },
        KdfParams {
            memory_kib: 8192,
            iterations: 1,
            parallelism: 0,
        },
        KdfParams {
            memory_kib: 8192,
            iterations: 1,
            parallelism: 65,
        },
    ];
    for kdf in invalid_kdfs {
        assert!(kdf.validate().is_err());
        let opts = EncryptOptions {
            reed_solomon: false,
            stealth: false,
            kdf,
            chunk_size: MIN_CHUNK_SIZE,
            recovery_key: None,
            keyfile_hash: None,
            compressed: false,
            container_size_bytes: None,
        };
        assert!(matches!(
            encrypt_stream(
                &mut Cursor::new(b"abc"),
                &mut Vec::new(),
                &sample_metadata(),
                b"pw",
                &opts,
                |_| {},
                None,
            ),
            Err(CryptoError::InvalidFormat(_))
        ));
    }

    // Invalid chunk_size > MAX_CHUNK_SIZE
    let mut bad_opts = fast_opts();
    bad_opts.chunk_size = MAX_CHUNK_SIZE + 1;
    assert!(matches!(
        encrypt_stream(
            &mut Cursor::new(b"abc"),
            &mut Vec::new(),
            &sample_metadata(),
            b"pw",
            &bad_opts,
            |_| {},
            None,
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    // Empty password & empty keyfile rejected
    assert!(matches!(
        encrypt_stream(
            &mut Cursor::new(b"abc"),
            &mut Vec::new(),
            &sample_metadata(),
            b"",
            &fast_opts(),
            |_| {},
            None,
        ),
        Err(CryptoError::InvalidFormat(_))
    ));
    assert!(matches!(
        hash_keyfile_reader(&mut Cursor::new(b"")),
        Err(CryptoError::InvalidFormat(_))
    ));

    // BIP-39 edge cases
    let ent = generate_recovery_entropy();
    let phrase = entropy_to_mnemonic(&ent).unwrap();
    let noisy = format!(
        "  {}  ",
        phrase
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("   ")
            .to_uppercase()
    );
    let parsed = mnemonic_to_entropy(&noisy).unwrap();
    assert_eq!(parsed.as_bytes(), ent.as_bytes());

    let twelve = phrase
        .split_whitespace()
        .take(12)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(matches!(
        mnemonic_to_entropy(&twelve),
        Err(CryptoError::InvalidFormat(_))
    ));
    let mut bad_words: Vec<&str> = phrase.split_whitespace().collect();
    // Word 23 carries the last 3 entropy bits (bits 10..8) + 8 checksum bits (bits 7..0).
    // Flipping only bit 0 preserves the exact 256-bit entropy while guaranteeing a checksum
    // mismatch (100% deterministic, avoiding the ~1/256 collision when swapping to "abandon").
    let last_idx = bip39::Language::English
        .find_word(bad_words[23])
        .expect("valid BIP-39 word");
    bad_words[23] = bip39::Language::English.word_list()[usize::from(last_idx ^ 1)];
    assert!(matches!(
        mnemonic_to_entropy(&bad_words.join(" ")),
        Err(CryptoError::InvalidFormat(_))
    ));
}

#[test]
fn rekey_keyfile_transitions_and_errors() {
    let kf1 = hash_keyfile_reader(&mut Cursor::new(b"kf-one")).unwrap();
    let kf2 = hash_keyfile_reader(&mut Cursor::new(b"kf-two")).unwrap();
    let rec = generate_recovery_entropy();

    let mut opts = fast_opts();
    opts.recovery_key = Some(rec.clone());
    let data = b"transition-payload-check".repeat(800);

    let mut v0 = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&data),
        &mut v0,
        &sample_metadata(),
        b"Pw0!",
        &opts,
        |_| {},
        None,
    )
    .unwrap();

    // 1. None -> Some(kf1)
    let mut v1 = Vec::new();
    rekey_stream(
        &mut Cursor::new(&v0),
        &mut v1,
        &RekeyOptions {
            old_password: b"Pw0!",
            new_password: b"Pw1!",
            old_keyfile_hash: None,
            new_keyfile_hash: Some(&kf1),
            new_kdf: None,
        },
        None,
    )
    .unwrap();
    assert!(matches!(
        inspect_header(
            &mut Cursor::new(&v1),
            Auth::Password {
                password: b"Pw1!",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::KeyfileRequired)
    ));

    // 2. Some(kf1) -> Some(kf2)
    let mut v2 = Vec::new();
    rekey_stream(
        &mut Cursor::new(&v1),
        &mut v2,
        &RekeyOptions {
            old_password: b"Pw1!",
            new_password: b"Pw2!",
            old_keyfile_hash: Some(&kf1),
            new_keyfile_hash: Some(&kf2),
            new_kdf: None,
        },
        None,
    )
    .unwrap();
    assert!(matches!(
        decrypt_stream(
            &mut Cursor::new(&v2),
            &mut Vec::new(),
            Auth::Password {
                password: b"Pw2!",
                keyfile_hash: Some(&kf1),
            },
            |_| {},
            None,
        ),
        Err(CryptoError::AuthenticationFailed)
    ));

    // 3. Some(kf2) -> None
    let mut v3 = Vec::new();
    rekey_stream(
        &mut Cursor::new(&v2),
        &mut v3,
        &RekeyOptions {
            old_password: b"Pw2!",
            new_password: b"Pw3!",
            old_keyfile_hash: Some(&kf2),
            new_keyfile_hash: None,
            new_kdf: None,
        },
        None,
    )
    .unwrap();
    let info = inspect_header(
        &mut Cursor::new(&v3),
        Auth::Password {
            password: b"Pw3!",
            keyfile_hash: None,
        },
    )
    .unwrap();
    assert!(!info.has_keyfile);
    assert!(info.has_recovery);

    let mut dec_rec = Vec::new();
    decrypt_stream(
        &mut Cursor::new(&v3),
        &mut dec_rec,
        Auth::RecoveryKey(&rec),
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(dec_rec, data);

    // Reject empty new password and wrong old password
    assert!(matches!(
        rekey_stream(
            &mut Cursor::new(&v3),
            &mut Vec::new(),
            &RekeyOptions {
                old_password: b"Pw3!",
                new_password: b"",
                old_keyfile_hash: None,
                new_keyfile_hash: None,
                new_kdf: None,
            },
            None,
        ),
        Err(CryptoError::InvalidFormat(_))
    ));
    assert!(matches!(
        rekey_stream(
            &mut Cursor::new(&v3),
            &mut Vec::new(),
            &RekeyOptions {
                old_password: b"Wrong!",
                new_password: b"Pw4!",
                old_keyfile_hash: None,
                new_keyfile_hash: None,
                new_kdf: None,
            },
            None,
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
}

#[test]
fn check_integrity_single_pass_detects_every_corruption_and_hashes_accurately() {
    let data = vec![0x5Au8; 16 * 1024 * 2 + 55]; // 3 chunks
    let mut vault = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&data),
        &mut vault,
        &sample_metadata(),
        b"IntegPw!1",
        &fast_opts(),
        |_| {},
        None,
    )
    .unwrap();

    let hdr_len = u32::from_be_bytes(vault[5..9].try_into().unwrap()) as usize;
    let hdr: VaultHeader = serde_json::from_slice(&vault[9..9 + hdr_len]).unwrap();
    let payload_offset = 9 + hdr_len + hdr.encrypted_meta_len as usize;

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let expected_hex = |bytes: &[u8]| -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };

    // Valid 3-chunk vault
    std::fs::write(tmp.path(), &vault).unwrap();
    let rep_ok = check_integrity(tmp.path()).unwrap();
    assert!(rep_ok.ok);
    assert_eq!(rep_ok.version, 5);
    assert_eq!(rep_ok.chunk_count, 3);
    assert_eq!(rep_ok.sha256_hex, expected_hex(&vault));

    // Truncated payload
    let trunc = &vault[..vault.len() - 10];
    std::fs::write(tmp.path(), trunc).unwrap();
    let rep_trunc = check_integrity(tmp.path()).unwrap();
    assert!(!rep_trunc.ok);
    assert_eq!(rep_trunc.sha256_hex, expected_hex(trunc));

    // Trailing byte
    let mut trailing = vault.clone();
    trailing.push(0x99);
    std::fs::write(tmp.path(), &trailing).unwrap();
    let rep_trail = check_integrity(tmp.path()).unwrap();
    assert!(!rep_trail.ok);
    assert_eq!(rep_trail.sha256_hex, expected_hex(&trailing));

    // Oversized chunk frame
    let mut big_len = vault.clone();
    big_len[payload_offset..payload_offset + 4]
        .copy_from_slice(&(hdr.chunk_size + 1).to_be_bytes());
    std::fs::write(tmp.path(), &big_len).unwrap();
    let rep_big = check_integrity(tmp.path()).unwrap();
    assert!(!rep_big.ok);
    assert_eq!(rep_big.sha256_hex, expected_hex(&big_len));

    // Invalid final_flag (= 2)
    let mut bad_flag = vault.clone();
    bad_flag[payload_offset + 4] = 2;
    std::fs::write(tmp.path(), &bad_flag).unwrap();
    assert!(!check_integrity(tmp.path()).unwrap().ok);

    // Unsupported v4 still hashes entire file
    let mut v4 = vault.clone();
    v4[4] = 4;
    std::fs::write(tmp.path(), &v4).unwrap();
    let rep_v4 = check_integrity(tmp.path()).unwrap();
    assert!(!rep_v4.ok);
    assert_eq!(rep_v4.version, 4);
    assert_eq!(rep_v4.sha256_hex, expected_hex(&v4));
}

#[test]
fn encrypt_and_decrypt_cancel_mid_stream() {
    let data = vec![0x7Cu8; 16 * 1024 * 3];
    let cancel_enc = AtomicBool::new(false);
    let mut partial = Vec::new();
    let res_enc = encrypt_stream(
        &mut Cursor::new(&data),
        &mut partial,
        &sample_metadata(),
        b"CancelPw!1",
        &fast_opts(),
        |written| {
            if written > 0 {
                cancel_enc.store(true, Ordering::Relaxed);
            }
        },
        Some(&cancel_enc),
    );
    assert!(matches!(res_enc, Err(CryptoError::Cancelled)));

    // Build full vault then cancel during decrypt after chunk 0
    let mut full_vault = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&data),
        &mut full_vault,
        &sample_metadata(),
        b"CancelPw!1",
        &fast_opts(),
        |_| {},
        None,
    )
    .unwrap();

    let cancel_dec = AtomicBool::new(false);
    let res_dec = decrypt_stream(
        &mut Cursor::new(&full_vault),
        &mut Vec::new(),
        Auth::Password {
            password: b"CancelPw!1",
            keyfile_hash: None,
        },
        |done| {
            if done > 0 {
                cancel_dec.store(true, Ordering::Relaxed);
            }
        },
        Some(&cancel_dec),
    );
    assert!(matches!(res_dec, Err(CryptoError::Cancelled)));
}

#[test]
fn rekey_stream_validates_chunk_frames_final_flag_and_exact_eof() {
    let data = vec![0x3Eu8; 16 * 1024 * 2 + 123]; // 3 chunks
    let mut vault = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&data),
        &mut vault,
        &sample_metadata(),
        b"FramePw!1",
        &fast_opts(),
        |_| {},
        None,
    )
    .unwrap();

    let opts = RekeyOptions {
        old_password: b"FramePw!1",
        new_password: b"FramePw!2",
        old_keyfile_hash: None,
        new_keyfile_hash: None,
        new_kdf: Some(KdfParams::fast_test()),
    };

    // 1) Truncating the final chunk / tail bytes (simulating missing tail `.00N` split part)
    // must be rejected as InvalidFormat rather than blindly copying truncated bytes.
    let truncated_mid_chunk = &vault[..vault.len() - 10];
    assert!(matches!(
        rekey_stream(
            &mut Cursor::new(truncated_mid_chunk),
            &mut Vec::new(),
            &opts,
            None
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    // 2) Cutting exactly at a chunk boundary (so final_flag == 1 chunk is completely missing)
    let hdr_len = u32::from_be_bytes(vault[5..9].try_into().unwrap()) as usize;
    let hdr: VaultHeader = serde_json::from_slice(&vault[9..9 + hdr_len]).unwrap();
    let payload_offset = 9 + hdr_len + hdr.encrypted_meta_len as usize;
    let first_chunk_end = payload_offset + 5 + 16 * 1024 + 16;
    assert!(matches!(
        rekey_stream(
            &mut Cursor::new(&vault[..first_chunk_end]),
            &mut Vec::new(),
            &opts,
            None
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    // 3) Trailing unauthenticated bytes after final_flag == 1 must be rejected.
    let mut with_trailing = vault.clone();
    with_trailing.push(0xFF);
    assert!(matches!(
        rekey_stream(
            &mut Cursor::new(&with_trailing),
            &mut Vec::new(),
            &opts,
            None
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    // 4) Invalid final flag (> 1) must be rejected.
    let mut bad_flag = vault.clone();
    bad_flag[payload_offset + 4] = 2;
    assert!(matches!(
        rekey_stream(&mut Cursor::new(&bad_flag), &mut Vec::new(), &opts, None),
        Err(CryptoError::InvalidFormat(_))
    ));

    // 5) Oversized chunk length (> header.chunk_size) must be rejected.
    let mut oversized = vault.clone();
    oversized[payload_offset..payload_offset + 4]
        .copy_from_slice(&(hdr.chunk_size + 1).to_be_bytes());
    assert!(matches!(
        rekey_stream(&mut Cursor::new(&oversized), &mut Vec::new(), &opts, None),
        Err(CryptoError::InvalidFormat(_))
    ));
}
