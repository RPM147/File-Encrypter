use std::fs;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use rpm_core::constants::{HIDDEN_MINI_HEADER_WIRE_SIZE, MIN_CHUNK_SIZE};
use rpm_core::{Auth, HiddenEncryptOptions, KdfParams};
use rpm_storage::{decrypt_vault_selected_v5, decrypt_vault_v5, encrypt_hidden_sources_v5};

#[test]
fn hidden_storage_end_to_end_full_and_selective_extract_with_tamper_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let decoy_dir = dir.path().join("decoy");
    let hidden_dir = dir.path().join("secret");
    fs::create_dir_all(&decoy_dir).unwrap();
    fs::create_dir_all(hidden_dir.join("sub")).unwrap();

    fs::write(decoy_dir.join("note.txt"), b"public decoy memo").unwrap();
    fs::write(decoy_dir.join("blob.bin"), vec![0x41u8; 24 * 1024]).unwrap();

    fs::write(hidden_dir.join("alpha.txt"), b"secret alpha contents").unwrap();
    fs::write(hidden_dir.join("sub/beta.bin"), vec![0x5Au8; 40 * 1024]).unwrap();
    fs::write(hidden_dir.join("gamma.txt"), b"unselected hidden file").unwrap();

    let container_size = 512 * 1024;
    let vault = dir.path().join("archive.vault");
    let cancel = Arc::new(AtomicBool::new(false));
    let opts = HiddenEncryptOptions {
        stealth: false,
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        container_size_bytes: container_size,
        decoy_recovery_key: None,
        decoy_keyfile_hash: None,
        decoy_compressed: true,
        hidden_keyfile_hash: None,
        hidden_compressed: true,
    };

    let (summary, decoy_meta, hidden_meta) = encrypt_hidden_sources_v5(
        std::slice::from_ref(&decoy_dir),
        std::slice::from_ref(&hidden_dir),
        &vault,
        b"DecoyPw!1",
        b"SecretPw!2",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert_eq!(summary.container_size, container_size);
    assert_eq!(fs::metadata(&vault).unwrap().len(), container_size);
    assert_eq!(decoy_meta.file_count, 2);
    assert_eq!(hidden_meta.file_count, 3);

    let entries_before = fs::read_dir(dir.path()).unwrap().count();
    let preview = |password: &[u8], path| {
        rpm_storage::extract_entry_to_memory_v5(
            &vault,
            Auth::Password {
                password,
                keyfile_hash: None,
            },
            path,
            rpm_storage::DEFAULT_PREVIEW_MAX_BYTES,
            Arc::new(|_, _| {}),
            cancel.clone(),
        )
        .unwrap()
    };
    assert_eq!(
        &preview(b"DecoyPw!1", "./decoy/note.txt")[..],
        b"public decoy memo"
    );
    assert_eq!(
        *preview(b"SecretPw!2", "secret/sub/beta.bin"),
        vec![0x5a; 40 * 1024]
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), entries_before);

    // 1. Decrypting with decoy password extracts ONLY decoy folder.
    let decoy_out = dir.path().join("decoy_out");
    let dec_d = decrypt_vault_v5(
        &vault,
        &decoy_out,
        Auth::Password {
            password: b"DecoyPw!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(dec_d.files_extracted, 2);
    assert_eq!(
        fs::read(decoy_out.join("decoy/note.txt")).unwrap(),
        b"public decoy memo"
    );
    assert!(!decoy_out.join("secret").exists());

    // 2. Decrypting with hidden password transparently extracts ONLY hidden folder.
    let hidden_out = dir.path().join("hidden_out");
    let dec_h = decrypt_vault_v5(
        &vault,
        &hidden_out,
        Auth::Password {
            password: b"SecretPw!2",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(dec_h.files_extracted, 3);
    assert_eq!(
        fs::read(hidden_out.join("secret/alpha.txt")).unwrap(),
        b"secret alpha contents"
    );
    assert_eq!(
        fs::read(hidden_out.join("secret/sub/beta.bin")).unwrap(),
        vec![0x5Au8; 40 * 1024]
    );
    assert!(!hidden_out.join("decoy").exists());

    // 3. Selective extraction on the hidden compartment extracts only matching member.
    let sel_out = dir.path().join("sel_out");
    let sel = decrypt_vault_selected_v5(
        &vault,
        &sel_out,
        Auth::Password {
            password: b"SecretPw!2",
            keyfile_hash: None,
        },
        &["secret/sub/beta.bin".into()],
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(sel.files_extracted, 1);
    assert_eq!(
        fs::read(sel_out.join("secret/sub/beta.bin")).unwrap(),
        vec![0x5Au8; 40 * 1024]
    );
    assert!(!sel_out.join("secret/alpha.txt").exists());
    assert!(!sel_out.join("secret/gamma.txt").exists());

    // 4. Mini-header tamper causes clean rollback without leaking partial files or leaving staging dirs.
    let mut tampered = fs::read(&vault).unwrap();
    let idx = tampered.len() - HIDDEN_MINI_HEADER_WIRE_SIZE + 5;
    tampered[idx] ^= 0xFF;
    fs::write(&vault, tampered).unwrap();

    let tamper_out = dir.path().join("tamper_out");
    assert!(decrypt_vault_v5(
        &vault,
        &tamper_out,
        Auth::Password {
            password: b"SecretPw!2",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .is_err());
    assert!(!tamper_out.exists());
}
