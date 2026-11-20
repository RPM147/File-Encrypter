use std::io::Cursor;
use std::sync::atomic::AtomicBool;

use rpm_core::{
    check_integrity, decrypt_stream, encrypt_stream, entropy_to_mnemonic,
    generate_recovery_entropy, hash_keyfile_reader, inspect_header, mnemonic_to_entropy,
    rekey_stream, Auth, CryptoError, EncryptOptions, KdfParams, RekeyOptions, VaultMetadata,
    VAULT_VERSION,
};

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
        kdf: KdfParams::fast_test(),
        chunk_size: 16 * 1024, // 16 KiB minimum to exercise multi-chunk logic with small data
        recovery_key: None,
        keyfile_hash: None,
        compressed: true,
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
