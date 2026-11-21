use rpm_core::{
    check_integrity, constants::MIN_CHUNK_SIZE, decrypt_stream_seekable_with_kdf,
    encrypt_hidden_stream, encrypt_stream, entropy_to_mnemonic, generate_recovery_entropy,
    inspect_header_seekable_with_kdf, mnemonic_to_entropy, rekey_stream, Auth, CryptoError,
    EncryptOptions, HiddenEncryptOptions, KdfParams, RekeyOptions, SecretKey, VaultMetadata,
};
use sha2::{Digest, Sha256};
use std::io::Cursor;

const CONTAINER: u64 = 256 * 1024;
fn password<'a>(pw: &'a [u8], kf: Option<&'a SecretKey>) -> Auth<'a> {
    Auth::Password {
        password: pw,
        keyfile_hash: kf,
    }
}
fn meta(name: &str, len: usize) -> VaultMetadata {
    VaultMetadata {
        filename: name.into(),
        source_type: "file".into(),
        original_size: len as u64,
        file_count: 1,
        created_at: String::new(),
        compressed: false,
        files: vec![],
    }
}
fn decrypt(bytes: &[u8], auth: Auth<'_>) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![];
    decrypt_stream_seekable_with_kdf(
        &mut Cursor::new(bytes),
        &mut out,
        auth,
        &KdfParams::fast_test(),
        |_| {},
        None,
    )?;
    Ok(out)
}
fn encrypt(plain: &[u8], opts: &EncryptOptions) -> Vec<u8> {
    let mut out = vec![];
    encrypt_stream(
        &mut Cursor::new(plain),
        &mut out,
        &meta("private filename", plain.len()),
        b"outer",
        opts,
        |_| {},
        None,
    )
    .unwrap();
    out
}

#[test]
fn encrypted_slots_and_frames_round_trip_without_public_structure() {
    let kf = SecretKey::new([9; 32]);
    let entropy = generate_recovery_entropy();
    let recovery = mnemonic_to_entropy(&entropy_to_mnemonic(&entropy).unwrap()).unwrap();
    let payload = vec![0x31; MIN_CHUNK_SIZE as usize * 2 + 17];
    for size in [None, Some(CONTAINER)] {
        let opts = EncryptOptions {
            stealth: true,
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            compressed: false,
            keyfile_hash: Some(kf.clone()),
            recovery_key: Some(entropy.clone()),
            container_size_bytes: size,
        };
        let bytes = encrypt(&payload, &opts);
        let auth = password(b"outer", Some(&kf));
        assert_ne!(&bytes[..4], b"RPMV");
        // A chance occurrence in random bytes is legal. A plaintext field would recur at the same offset.
        for marker in [
            b"RPMV".as_slice(),
            b"RPMH",
            b"RPMS",
            br#""filename""#,
            b"private filename",
        ] {
            if let Some(offset) = bytes.windows(marker.len()).position(|w| w == marker) {
                let independent = encrypt(&payload, &opts);
                assert_ne!(&independent[offset..offset + marker.len()], marker);
            }
        }
        if let Some(size) = size {
            assert_eq!(bytes.len() as u64, size);
            let mut counts = [0u32; 256];
            for &b in &bytes {
                counts[b as usize] += 1;
            }
            let entropy: f64 = counts
                .into_iter()
                .filter(|&n| n > 0)
                .map(|n| {
                    let p = n as f64 / bytes.len() as f64;
                    -p * p.log2()
                })
                .sum();
            assert!(entropy > 7.9, "{entropy}");
        }
        let info =
            inspect_header_seekable_with_kdf(&mut Cursor::new(&bytes), auth, &opts.kdf).unwrap();
        assert!(
            info.is_stealth && !info.is_hidden_compartment && info.has_keyfile && info.has_recovery
        );
        assert_eq!(info.container_size, size);
        assert_eq!(decrypt(&bytes, auth).unwrap(), payload);
        assert_eq!(
            decrypt(&bytes, Auth::RecoveryKey(&recovery)).unwrap(),
            payload
        );
        for bad in [
            password(b"outer", None),
            password(b"outer", Some(&recovery)),
            password(b"incorrect", Some(&kf)),
            Auth::RecoveryKey(&kf),
        ] {
            assert!(matches!(
                decrypt(&bytes, bad),
                Err(CryptoError::AuthenticationFailed)
            ));
        }
        assert!(decrypt(&bytes[..bytes.len() - 1], auth).is_err());
        let mut appended = bytes.clone();
        appended.push(1);
        assert!(decrypt(&appended, auth).is_err());
        for off in [0, 32, 139, 248, 280] {
            let mut damaged = bytes.clone();
            damaged[off] ^= 0x80;
            assert!(decrypt(&damaged, auth).is_err());
        }
        if size.is_none() {
            let mut damaged = bytes.clone();
            *damaged.last_mut().unwrap() ^= 1;
            assert!(decrypt(&damaged, auth).is_err());
        }
        let mut dst = vec![];
        let rekey = RekeyOptions {
            old_password: b"outer",
            new_password: b"changed",
            old_keyfile_hash: Some(&kf),
            new_keyfile_hash: None,
            new_kdf: None,
        };
        assert!(matches!(
            rekey_stream(&mut bytes.as_slice(), &mut dst, &rekey, None),
            Err(CryptoError::UnsupportedOperation(_))
        ));
        assert!(dst.is_empty());
        assert_digest_only(&bytes);
    }
}
fn assert_digest_only(bytes: &[u8]) {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    let report = check_integrity(file.path()).unwrap();
    assert!(report.ok && report.sha256_only);
    assert_eq!(report.file_size, bytes.len() as u64);
    assert_eq!(report.sha256_hex, format!("{:x}", Sha256::digest(bytes)));
    assert_eq!(
        (
            report.version,
            report.chunk_count,
            report.has_keyfile,
            report.has_recovery
        ),
        (0, 0, false, false)
    );
}

#[test]
fn ordinary_files_get_the_same_digest_only_report() {
    for bytes in [b"".as_slice(), b"R", b"RPM", b"an ordinary file"] {
        assert_digest_only(bytes);
    }
}

#[test]
fn hidden_uses_independent_credentials_and_recovery_unlocks_outer() {
    let key = SecretKey::new([3; 32]);
    let entropy = generate_recovery_entropy();
    let opts = HiddenEncryptOptions {
        stealth: true,
        kdf: KdfParams::fast_test(),
        container_size_bytes: CONTAINER,
        decoy_recovery_key: Some(entropy.clone()),
        hidden_keyfile_hash: Some(key.clone()),
        ..Default::default()
    };
    let mut out = vec![];
    encrypt_hidden_stream(
        &mut b"visible".as_slice(),
        &mut b"secret".as_slice(),
        &mut out,
        &meta("first", 7),
        &meta("second", 6),
        b"outer",
        b"hidden",
        &opts,
        |_| {},
        |_| {},
        None,
    )
    .unwrap();
    let hidden = password(b"hidden", Some(&key));
    assert_eq!(out.len(), CONTAINER as usize);
    assert_eq!(decrypt(&out, password(b"outer", None)).unwrap(), b"visible");
    assert_eq!(
        decrypt(&out, Auth::RecoveryKey(&entropy)).unwrap(),
        b"visible"
    );
    assert_eq!(decrypt(&out, hidden).unwrap(), b"secret");
    let info = inspect_header_seekable_with_kdf(&mut Cursor::new(&out), hidden, &opts.kdf).unwrap();
    assert!(info.is_stealth && info.is_hidden_compartment && !info.has_recovery);
    for bad in [
        password(b"hidden", None),
        password(b"hidden", Some(&entropy)),
        password(b"other", Some(&key)),
    ] {
        assert!(matches!(
            decrypt(&out, bad),
            Err(CryptoError::AuthenticationFailed)
        ));
    }
    out.pop();
    assert!(decrypt(&out, hidden).is_err());
    out.extend_from_slice(&[0, 0]);
    assert!(decrypt(&out, hidden).is_err());
}

// Independent wire fixture generated with Python cryptography (Argon2id, HKDF and AESGCM).
// Fixed salt 0..31, DEK 32..63, ID 0..15, nonces 01/02/03 repeated for PW/recovery/metadata.
#[test]
fn opens_independently_encoded_stealth_v5() {
    use base64::Engine;
    let wire = base64::engine::general_purpose::STANDARD
        .decode(concat!(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8BAQEBAQEBAQEBAQG0nf1Vtu/jpZn+VFa6Dmmt",
            "QsvztiKaTPcQdT09fYWFTgIi3dmW6x+BdDHDb4miAMsDeQcGZlEstP+V902V8VSBQuOt7MuNym7gmUGA",
            "naGKicGZPgEWle4lScQxozlZsw0CAgICAgICAgICAgJSjxJZ3vD24Dm3XvePYOKmxInUqWd9kZip6ViJ",
            "Xem8BBXw0MwtFNyd/825r1dv+I2f6iBAb5Cz9S6tbJa4M8ksxJev2+Dslq0d1WSo2Jj5i3uoEkbCKXZT",
            "fgZq9oD+v3YDAwMDAwMDAwMDAwNO8CE/haVZvfvHzV6fTYq6sD3P7AGxEYj50DTZhbbMMg57mXFluHQ1",
            "tLk0sOPYtT70XDd/UH7Ve7Mj2lHhxPfKPrLrQxN+XyB/Esfak52vc6XfClqN0fRiVkU7Hp3tpNbHKIER",
            "hn1w90+RrKL6rnltNrYZMQ4TFzApw40eDae2dYxjLYFbYpAvT/epZX6PVTL0qC6ePMWRl2LaHmvBckRE",
            "2p1p",
        ))
        .unwrap();
    let entropy = SecretKey::new([11; 32]);
    for auth in [password(b"example", None), Auth::RecoveryKey(&entropy)] {
        assert_eq!(decrypt(&wire, auth).unwrap(), b"hello");
    }
}
