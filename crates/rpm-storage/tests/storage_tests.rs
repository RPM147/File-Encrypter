use std::fs;
use std::io::Cursor;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use rpm_core::{hash_keyfile_reader, Auth, EncryptOptions, KdfParams};
use rpm_storage::packager::{collect_manifest, unpack_vault_stream};
use rpm_storage::shell_integration::{
    get_status_with_backend, install_with_backend, uninstall_with_backend, MemoryRegistryBackend,
    DIR_MENU_KEY, FILE_MENU_KEY, PROG_ID_KEY, VAULT_EXT_KEY,
};
use rpm_storage::{
    decrypt_vault_v5, encrypt_sources_v5, parse_gui_launch_args, rekey_vault_v5, unique_path,
    GuiLaunchIntent, LaunchTab, SecureWiper, StorageError,
};
use tar::{Builder, Header};

#[test]
fn streaming_pack_encrypt_decrypt_unpack_round_trip_with_zero_temp_files() {
    let dir = tempfile::tempdir().unwrap();
    let src_folder = dir.path().join("docs");
    fs::create_dir_all(src_folder.join("nested")).unwrap();
    fs::write(src_folder.join("a.txt"), b"hello pure rust v5!").unwrap();
    fs::write(src_folder.join("nested/big.bin"), vec![0xABu8; 95_000]).unwrap();

    let keyfile_hash = hash_keyfile_reader(&mut Cursor::new(b"kf-bytes")).unwrap();
    let vault_path = dir.path().join("docs.vault");
    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: 16 * 1024,
        recovery_key: None,
        keyfile_hash: Some(keyfile_hash.clone()),
        compressed: true,
    };

    let cancel = Arc::new(AtomicBool::new(false));
    let (summary, meta) = encrypt_sources_v5(
        std::slice::from_ref(&src_folder),
        &vault_path,
        b"VaultPw!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(summary.chunks_written >= 1);
    assert_eq!(meta.file_count, 2);

    // No temp .part left behind
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".rpm_tmp_"))
        .collect();
    assert!(leftovers.is_empty());

    // Decrypt back into fresh folder
    let out_dir = dir.path().join("restored");
    let dec = decrypt_vault_v5(
        &vault_path,
        &out_dir,
        Auth::Password {
            password: b"VaultPw!1",
            keyfile_hash: Some(&keyfile_hash),
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(dec.files_extracted, 2);
    assert_eq!(
        fs::read(out_dir.join("docs/a.txt")).unwrap(),
        b"hello pure rust v5!"
    );
    assert_eq!(
        fs::read(out_dir.join("docs/nested/big.bin")).unwrap(),
        vec![0xABu8; 95_000]
    );

    // Re-key in place on disk (verifies Windows handle closed before atomic rename!)
    rekey_vault_v5(
        &vault_path,
        b"VaultPw!1",
        b"NewVaultPw!2",
        Some(&keyfile_hash),
        Some(&keyfile_hash),
        None,
        None,
    )
    .unwrap();

    let out_dir2 = dir.path().join("restored2");
    assert!(decrypt_vault_v5(
        &vault_path,
        &out_dir2,
        Auth::Password {
            password: b"VaultPw!1",
            keyfile_hash: Some(&keyfile_hash),
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .is_err());
    assert!(!out_dir2.exists(), "partial output cleaned on auth error");

    decrypt_vault_v5(
        &vault_path,
        &out_dir2,
        Auth::Password {
            password: b"NewVaultPw!2",
            keyfile_hash: Some(&keyfile_hash),
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(
        fs::read(out_dir2.join("docs/a.txt")).unwrap(),
        b"hello pure rust v5!"
    );
}

#[test]
fn unpack_rejects_tar_slip_and_symlinks() {
    let mut tar_slip_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut tar_slip_bytes);
        let mut header = Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        let slip = b"safe/../escape.txt";
        let raw = header.as_mut_bytes();
        raw[..slip.len()].copy_from_slice(slip);
        raw[slip.len()] = 0;
        header.set_cksum();
        builder.append(&header, &b"evil"[..]).unwrap();
        builder.finish().unwrap();
    }

    let dir = tempfile::tempdir().unwrap();
    let res = unpack_vault_stream(Cursor::new(tar_slip_bytes), dir.path(), false, None);
    assert!(matches!(res, Err(StorageError::InvalidPath(_))));
    assert!(!dir.path().join("escape.txt").exists());

    let mut symlink_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut symlink_bytes);
        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("outside.txt").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "link.txt", std::io::empty())
            .unwrap();
        builder.finish().unwrap();
    }

    let res_sym = unpack_vault_stream(Cursor::new(symlink_bytes), dir.path(), false, None);
    assert!(matches!(res_sym, Err(StorageError::InvalidPath(_))));
    assert!(!dir.path().join("link.txt").exists());
}

#[test]
fn basename_collisions_and_wiper_and_unique_path_work() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    let f1 = a.join("dup.txt");
    let f2 = b.join("dup.txt");
    fs::write(&f1, b"1").unwrap();
    fs::write(&f2, b"22").unwrap();

    let meta = collect_manifest(&[f1.clone(), f2.clone()], false, None).unwrap();
    let names: Vec<_> = meta.files.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(names, vec!["dup.txt", "dup_2.txt"]);

    assert_ne!(unique_path(&f1), f1);

    SecureWiper::new(2).wipe_folder(&a).unwrap();
    assert!(!a.exists());
}

#[test]
fn memory_shell_integration_and_launch_args() {
    let mut reg = MemoryRegistryBackend::default();
    let s0 = get_status_with_backend(&reg);
    assert!(!s0.installed);

    let s1 = install_with_backend(&mut reg, "\"C:\\RPM\\rpm-encrypter.exe\"", None).unwrap();
    assert!(s1.installed);
    assert_eq!(reg.keys[FILE_MENU_KEY][""], "Encrypt with RPM Encrypter");
    assert_eq!(
        reg.keys[&format!("{PROG_ID_KEY}\\shell\\open\\command")][""],
        "\"C:\\RPM\\rpm-encrypter.exe\" --gui-decrypt \"%1\""
    );

    // Foreign .vault ProgID is preserved on uninstall.
    reg.keys
        .get_mut(VAULT_EXT_KEY)
        .unwrap()
        .insert(String::new(), "ForeignApp.Vault".into());
    let s2 = uninstall_with_backend(&mut reg).unwrap();
    assert!(!s2.installed);
    assert_eq!(reg.keys[VAULT_EXT_KEY][""], "ForeignApp.Vault");
    assert!(!reg.keys.contains_key(DIR_MENU_KEY));

    assert_eq!(
        parse_gui_launch_args(&["secret.vault".into()]),
        GuiLaunchIntent {
            tab: Some(LaunchTab::Decrypt),
            paths: vec!["secret.vault".into()],
        }
    );
    assert_eq!(
        parse_gui_launch_args(&["folder".into()]),
        GuiLaunchIntent {
            tab: Some(LaunchTab::Encrypt),
            paths: vec!["folder".into()],
        }
    );
}
