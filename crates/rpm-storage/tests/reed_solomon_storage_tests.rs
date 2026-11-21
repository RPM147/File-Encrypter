use rpm_core::{
    check_integrity, Auth, CryptoError, EncryptOptions, HiddenEncryptOptions, KdfParams,
    RsEncoderWriter, RsSeekableReader,
};
use rpm_storage::{
    decrypt_vault_selected_v5, decrypt_vault_v5, encrypt_hidden_sources_v5, encrypt_sources_v5,
    extract_entry_to_memory_v5, repair_vault_v5, StorageError,
};
use std::{
    fs,
    io::{Cursor, Read, Write},
    sync::{atomic::AtomicBool, Arc},
};

#[test]
fn damaged_ciphertext_can_be_previewed_extracted_and_atomically_repaired() {
    for hidden in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let outer = dir.join("public");
        let secret = dir.join("note");
        let vault = dir.join("protected.vault");
        fs::write(&outer, b"public").unwrap();
        fs::write(&secret, b"private").unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let progress: Arc<dyn Fn(u64, u64) + Send + Sync> = Arc::new(|_, _| {});
        if hidden {
            encrypt_hidden_sources_v5(
                &[outer],
                &[secret],
                &vault,
                b"outer",
                b"hidden",
                &HiddenEncryptOptions {
                    reed_solomon: true,
                    kdf: KdfParams::fast_test(),
                    container_size_bytes: 128 * 1024,
                    ..Default::default()
                },
                progress.clone(),
                cancel.clone(),
                |_| {},
            )
            .unwrap();
        } else {
            encrypt_sources_v5(
                &[outer],
                &vault,
                b"outer",
                &EncryptOptions {
                    reed_solomon: true,
                    kdf: KdfParams::fast_test(),
                    ..Default::default()
                },
                progress.clone(),
                cancel.clone(),
                |_| {},
            )
            .unwrap();
        }
        let clean = fs::read(&vault).unwrap();
        let mut damaged = clean.clone();
        for b in &mut damaged[0..512] {
            *b ^= 0xff;
        }
        fs::write(&vault, &damaged).unwrap();
        let (pw, name, expected) = if hidden {
            ("hidden", "note", "private")
        } else {
            ("outer", "public", "public")
        };
        let auth = Auth::Password {
            password: pw.as_bytes(),
            keyfile_hash: None,
        };
        let count = fs::read_dir(dir).unwrap().count();
        let preview =
            extract_entry_to_memory_v5(&vault, auth, name, 128, progress.clone(), cancel.clone())
                .unwrap();
        assert_eq!(preview.as_slice(), expected.as_bytes());
        assert_eq!(fs::read_dir(dir).unwrap().count(), count);
        let full = dir.join("full");
        decrypt_vault_v5(&vault, &full, auth, progress.clone(), cancel.clone()).unwrap();
        let sel = dir.join("selected");
        decrypt_vault_selected_v5(&vault, &sel, auth, &[name.into()], progress, cancel.clone())
            .unwrap();
        for root in [full, sel] {
            assert_eq!(fs::read(root.join(name)).unwrap(), expected.as_bytes());
        }
        let copy = dir.join("repaired");
        let report = repair_vault_v5(&vault, Some(&copy), cancel.clone()).unwrap();
        assert_eq!(report.repaired_bytes, 512);
        assert_eq!(fs::read(&vault).unwrap(), damaged);
        assert_eq!(fs::read(&copy).unwrap(), clean);
        repair_vault_v5(&vault, None, cancel.clone()).unwrap();
        assert_eq!(fs::read(&vault).unwrap(), clean);
        assert_eq!(check_integrity(&vault).unwrap().rs_repaired_bytes, 0);
        for b in &mut damaged[48..48 + 1024] {
            *b = b.wrapping_add(1);
        }
        fs::write(&vault, &damaged).unwrap();
        assert!(repair_vault_v5(&vault, Some(&copy), cancel.clone()).is_err());
        assert_eq!(fs::read(&copy).unwrap(), clean);
        assert!(repair_vault_v5(&vault, None, cancel).is_err());
        assert_eq!(fs::read(&vault).unwrap(), damaged);
    }
}

#[test]
fn multi_chunk_tampered_final_chunk_with_valid_parity_releases_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let large = dir.join("large");
    let vault = dir.join("large.vault");
    fs::write(&large, vec![0x5Au8; 36_000]).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let progress: Arc<dyn Fn(u64, u64) + Send + Sync> = Arc::new(|_, _| {});
    encrypt_sources_v5(
        &[large],
        &vault,
        b"pw",
        &EncryptOptions {
            reed_solomon: true,
            compressed: false,
            chunk_size: 16 * 1024,
            kdf: KdfParams::fast_test(),
            ..Default::default()
        },
        progress.clone(),
        cancel.clone(),
        |_| {},
    )
    .unwrap();

    let raw = fs::read(&vault).unwrap();
    let mut inner = Vec::new();
    RsSeekableReader::new(Cursor::new(raw))
        .unwrap()
        .read_to_end(&mut inner)
        .unwrap();
    *inner.last_mut().unwrap() ^= 1;
    let mut re_encoded = RsEncoderWriter::new(Vec::new()).unwrap();
    re_encoded.write_all(&inner).unwrap();
    fs::write(&vault, re_encoded.finish().unwrap()).unwrap();

    let auth = Auth::Password {
        password: b"pw",
        keyfile_hash: None,
    };
    let dest = dir.join("out");
    let err = decrypt_vault_v5(&vault, &dest, auth, progress.clone(), cancel.clone())
        .expect_err("tampered final chunk must fail stage-and-swap");
    assert!(matches!(
        err,
        StorageError::Crypto(CryptoError::AuthenticationFailed)
    ));
    assert!(!dest.exists() || fs::read_dir(&dest).unwrap().count() == 0);

    let mem_err = extract_entry_to_memory_v5(&vault, auth, "large", 64 * 1024, progress, cancel)
        .expect_err("tampered final chunk must fail RAM preview");
    assert!(matches!(
        mem_err,
        StorageError::Crypto(CryptoError::AuthenticationFailed)
    ));
}
