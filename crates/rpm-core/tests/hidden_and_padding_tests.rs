use std::collections::BTreeSet;
use std::io::Cursor;

use rpm_core::constants::{HIDDEN_MINI_HEADER_WIRE_SIZE, MIN_CHUNK_SIZE};
use rpm_core::header::{read_header_and_meta, VaultMetadata};
use rpm_core::{
    check_integrity, decrypt_stream, decrypt_stream_seekable, encrypt_hidden_stream,
    encrypt_stream, generate_recovery_entropy, hash_keyfile_reader, inspect_header,
    inspect_header_seekable, rekey_stream, Auth, CryptoError, EncryptOptions, HiddenEncryptOptions,
    KdfParams, RekeyOptions, SecretKey,
};

fn meta(name: &str, size: u64) -> VaultMetadata {
    VaultMetadata {
        filename: name.into(),
        source_type: "file".into(),
        original_size: size,
        file_count: 1,
        created_at: "2026-11-21T00:00:00Z".into(),
        compressed: false,
        files: vec![],
    }
}

#[test]
fn padded_container_enforces_exact_size_integrity_and_rejects_rekey() {
    let payload: Vec<u8> = (0..(2 * MIN_CHUNK_SIZE as usize + 513))
        .map(|i| (i % 247) as u8)
        .collect();
    let container_size = 128 * 1024;
    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        recovery_key: None,
        keyfile_hash: None,
        compressed: false,
        container_size_bytes: Some(container_size),
    };

    let mut vault = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&payload),
        &mut vault,
        &meta("padded.bin", payload.len() as u64),
        b"PadPw!1",
        &opts,
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(vault.len() as u64, container_size);

    let auth = Auth::Password {
        password: b"PadPw!1",
        keyfile_hash: None,
    };
    let info = inspect_header(&mut Cursor::new(&vault), auth).unwrap();
    assert_eq!(info.container_size, Some(container_size));
    assert!(!info.is_hidden_compartment);

    let mut out_seq = Vec::new();
    decrypt_stream(&mut Cursor::new(&vault), &mut out_seq, auth, |_| {}, None).unwrap();
    assert_eq!(out_seq, payload);

    let mut out_seek = Vec::new();
    decrypt_stream_seekable(&mut Cursor::new(&vault), &mut out_seek, auth, |_| {}, None).unwrap();
    assert_eq!(out_seek, payload);

    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), &vault).unwrap();
    let ok_rep = check_integrity(tmp.path()).unwrap();
    assert!(ok_rep.ok, "expected integrity ok, got: {}", ok_rep.message);

    // 1-byte truncation fails decrypt_stream, decrypt_stream_seekable, and check_integrity.
    let truncated = &vault[..vault.len() - 1];
    assert!(matches!(
        decrypt_stream(
            &mut Cursor::new(truncated),
            &mut Vec::new(),
            auth,
            |_| {},
            None
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    assert!(matches!(
        decrypt_stream_seekable(
            &mut Cursor::new(truncated),
            &mut Vec::new(),
            auth,
            |_| {},
            None
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    std::fs::write(tmp.path(), truncated).unwrap();
    assert!(!check_integrity(tmp.path()).unwrap().ok);

    // 1-byte trailing append past container_size fails everything cleanly.
    let mut appended = vault.clone();
    appended.push(0xAA);
    assert!(matches!(
        decrypt_stream(
            &mut Cursor::new(&appended),
            &mut Vec::new(),
            auth,
            |_| {},
            None
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    assert!(matches!(
        decrypt_stream_seekable(
            &mut Cursor::new(&appended),
            &mut Vec::new(),
            auth,
            |_| {},
            None
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    std::fs::write(tmp.path(), &appended).unwrap();
    assert!(!check_integrity(tmp.path()).unwrap().ok);

    // Re-key is disallowed on padded containers.
    let rekey_res = rekey_stream(
        &mut Cursor::new(&vault),
        &mut Vec::new(),
        &RekeyOptions {
            old_password: b"PadPw!1",
            new_password: b"NewPadPw!2",
            old_keyfile_hash: None,
            new_keyfile_hash: None,
            new_kdf: None,
        },
        None,
    );
    assert!(matches!(rekey_res, Err(CryptoError::InvalidFormat(_))));
}

#[test]
fn normal_padded_and_hidden_vault_share_indistinguishable_public_header() {
    let decoy: Vec<u8> = vec![0x33u8; 4096];
    let hidden: Vec<u8> = vec![0x77u8; 4096];
    let container_size = 192 * 1024;

    let mut normal_padded = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&decoy),
        &mut normal_padded,
        &meta("normal.bin", decoy.len() as u64),
        b"OuterPw!1",
        &EncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            recovery_key: None,
            keyfile_hash: None,
            compressed: false,
            container_size_bytes: Some(container_size),
        },
        |_| {},
        None,
    )
    .unwrap();

    let mut hidden_vault = Vec::new();
    encrypt_hidden_stream(
        &mut Cursor::new(&decoy),
        &mut Cursor::new(&hidden),
        &mut hidden_vault,
        &meta("normal.bin", decoy.len() as u64),
        &meta("secret.bin", hidden.len() as u64),
        b"OuterPw!1",
        b"HiddenPw!2",
        &HiddenEncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            container_size_bytes: container_size,
            decoy_recovery_key: None,
            decoy_keyfile_hash: None,
            decoy_compressed: false,
            hidden_keyfile_hash: None,
            hidden_compressed: false,
        },
        |_| {},
        |_| {},
        None,
    )
    .unwrap();

    assert_eq!(normal_padded.len(), hidden_vault.len());
    assert_eq!(hidden_vault.len() as u64, container_size);

    let len_a = u32::from_be_bytes(normal_padded[5..9].try_into().unwrap()) as usize;
    let len_b = u32::from_be_bytes(hidden_vault[5..9].try_into().unwrap()) as usize;
    let json_a: serde_json::Value = serde_json::from_slice(&normal_padded[9..9 + len_a]).unwrap();
    let json_b: serde_json::Value = serde_json::from_slice(&hidden_vault[9..9 + len_b]).unwrap();

    let keys_a: BTreeSet<String> = json_a.as_object().unwrap().keys().cloned().collect();
    let keys_b: BTreeSet<String> = json_b.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys_a, keys_b);
    assert_eq!(json_a["flags"], json_b["flags"]);
    assert_eq!(json_a["container_size"], json_b["container_size"]);

    let raw_hdr_str = std::str::from_utf8(&hidden_vault[9..9 + len_b]).unwrap();
    assert!(!raw_hdr_str.contains("hidden"));
    assert!(!raw_hdr_str.contains("RPMH"));
}

#[test]
fn hidden_vault_round_trip_keyfiles_recovery_and_security_negatives() {
    let decoy: Vec<u8> = (0..(2 * MIN_CHUNK_SIZE as usize + 123))
        .map(|i| (i % 199) as u8)
        .collect();
    let hidden: Vec<u8> = (0..(2 * MIN_CHUNK_SIZE as usize + 321))
        .map(|i| ((i * 3) % 211) as u8)
        .collect();
    let container_size = 256 * 1024;

    let decoy_kf = hash_keyfile_reader(&mut Cursor::new(b"decoy-keyfile-bits")).unwrap();
    let hidden_kf = hash_keyfile_reader(&mut Cursor::new(b"hidden-keyfile-bits")).unwrap();
    let decoy_rec = generate_recovery_entropy();

    let mut container = Vec::new();
    let summary = encrypt_hidden_stream(
        &mut Cursor::new(&decoy),
        &mut Cursor::new(&hidden),
        &mut container,
        &meta("decoy.dat", decoy.len() as u64),
        &meta("hidden.dat", hidden.len() as u64),
        b"DecoyPass!1",
        b"HiddenPass!2",
        &HiddenEncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            container_size_bytes: container_size,
            decoy_recovery_key: Some(decoy_rec.clone()),
            decoy_keyfile_hash: Some(decoy_kf.clone()),
            decoy_compressed: false,
            hidden_keyfile_hash: Some(hidden_kf.clone()),
            hidden_compressed: false,
        },
        |_| {},
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(summary.container_size, container_size);
    assert_eq!(container.len() as u64, container_size);
    assert!(summary.hidden_chunks_written >= 3);

    // Wrong password without keyfile yields the outer KeyfileRequired error (zero hidden oracle).
    assert!(matches!(
        inspect_header_seekable(
            &mut Cursor::new(&container),
            Auth::Password {
                password: b"HiddenPass!2",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::KeyfileRequired)
    ));

    // Decoy password + decoy keyfile opens outer decoy vault cleanly.
    let decoy_info = inspect_header_seekable(
        &mut Cursor::new(&container),
        Auth::Password {
            password: b"DecoyPass!1",
            keyfile_hash: Some(&decoy_kf),
        },
    )
    .unwrap();
    assert!(!decoy_info.is_hidden_compartment);
    assert_eq!(decoy_info.metadata.filename, "decoy.dat");

    let mut out_decoy = Vec::new();
    decrypt_stream_seekable(
        &mut Cursor::new(&container),
        &mut out_decoy,
        Auth::RecoveryKey(&decoy_rec),
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(out_decoy, decoy);

    // Hidden password + hidden keyfile transparently unlocks hidden compartment.
    let hidden_auth = Auth::Password {
        password: b"HiddenPass!2",
        keyfile_hash: Some(&hidden_kf),
    };
    let hidden_info = inspect_header_seekable(&mut Cursor::new(&container), hidden_auth).unwrap();
    assert!(hidden_info.is_hidden_compartment);
    assert_eq!(hidden_info.metadata.filename, "hidden.dat");

    let mut out_hidden = Vec::new();
    let decoded_meta = decrypt_stream_seekable(
        &mut Cursor::new(&container),
        &mut out_hidden,
        hidden_auth,
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(decoded_meta.filename, "hidden.dat");
    assert_eq!(out_hidden, hidden);

    // Asymmetric keyfile setup: outer has no keyfile, hidden requires keyfile -> wrong password returns AuthenticationFailed.
    let mut asym = Vec::new();
    encrypt_hidden_stream(
        &mut Cursor::new(b"outer-no-kf"),
        &mut Cursor::new(b"hidden-with-kf"),
        &mut asym,
        &meta("outer.txt", 11),
        &meta("secret.txt", 14),
        b"OutPass!",
        b"HidPass!",
        &HiddenEncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            container_size_bytes: 128 * 1024,
            decoy_recovery_key: None,
            decoy_keyfile_hash: None,
            decoy_compressed: false,
            hidden_keyfile_hash: Some(hidden_kf.clone()),
            hidden_compressed: false,
        },
        |_| {},
        |_| {},
        None,
    )
    .unwrap();
    assert!(matches!(
        inspect_header_seekable(
            &mut Cursor::new(&asym),
            Auth::Password {
                password: b"HidPass!",
                keyfile_hash: None,
            }
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    let mut asym_out = Vec::new();
    decrypt_stream_seekable(
        &mut Cursor::new(&asym),
        &mut asym_out,
        Auth::Password {
            password: b"HidPass!",
            keyfile_hash: Some(&hidden_kf),
        },
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(asym_out, b"hidden-with-kf");

    // Equal passwords rejected.
    assert!(matches!(
        encrypt_hidden_stream(
            &mut Cursor::new(b"a"),
            &mut Cursor::new(b"b"),
            &mut Vec::new(),
            &meta("a", 1),
            &meta("b", 1),
            b"SamePassword",
            b"SamePassword",
            &HiddenEncryptOptions {
                kdf: KdfParams::fast_test(),
                chunk_size: MIN_CHUNK_SIZE,
                container_size_bytes: 128 * 1024,
                ..Default::default()
            },
            |_| {},
            |_| {},
            None,
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    // Undersized container capacity rejected cleanly.
    assert!(matches!(
        encrypt_hidden_stream(
            &mut Cursor::new(&decoy),
            &mut Cursor::new(&hidden),
            &mut Vec::new(),
            &meta("d", decoy.len() as u64),
            &meta("h", hidden.len() as u64),
            b"PassA!",
            b"PassB!",
            &HiddenEncryptOptions {
                kdf: KdfParams::fast_test(),
                chunk_size: MIN_CHUNK_SIZE,
                container_size_bytes: 64 * 1024,
                ..Default::default()
            },
            |_| {},
            |_| {},
            None,
        ),
        Err(CryptoError::InvalidFormat(_))
    ));

    // Tamper mini-header (last 108 bytes) -> hidden fails with zero output.
    let mut mini_tamper = container.clone();
    let tail_pos = mini_tamper.len() - HIDDEN_MINI_HEADER_WIRE_SIZE + 20;
    mini_tamper[tail_pos] ^= 0x01;
    let mut bad_out = Vec::new();
    assert!(decrypt_stream_seekable(
        &mut Cursor::new(&mini_tamper),
        &mut bad_out,
        hidden_auth,
        |_| {},
        None,
    )
    .is_err());
    assert!(bad_out.is_empty());

    // Tamper container length -> both outer and hidden fail cleanly.
    let mut short_cont = container.clone();
    short_cont.pop();
    assert!(matches!(
        decrypt_stream_seekable(
            &mut Cursor::new(&short_cont),
            &mut Vec::new(),
            Auth::Password {
                password: b"DecoyPass!1",
                keyfile_hash: Some(&decoy_kf),
            },
            |_| {},
            None,
        ),
        Err(CryptoError::AuthenticationFailed)
    ));
    assert!(matches!(
        decrypt_stream_seekable(
            &mut Cursor::new(&short_cont),
            &mut Vec::new(),
            hidden_auth,
            |_| {},
            None,
        ),
        Err(CryptoError::AuthenticationFailed)
    ));

    // Verify outer header offset stays valid after container creation.
    let (_, _, hdr_len) = read_header_and_meta(&mut Cursor::new(&container)).unwrap();
    assert!(hdr_len < container_size - HIDDEN_MINI_HEADER_WIRE_SIZE as u64);
    let _ = SecretKey::new([0u8; 32]);
}
