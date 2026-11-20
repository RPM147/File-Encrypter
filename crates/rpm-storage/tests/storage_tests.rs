use std::fs;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rpm_core::{hash_keyfile_reader, Auth, CryptoError, EncryptOptions, KdfParams};
use rpm_storage::config::{load_config_from, save_config_to, AppConfig, ThemeMode};
use rpm_storage::packager::{
    collect_manifest, pack_sources, unpack_vault_stream, unpack_vault_stream_with_limits,
};
use rpm_storage::shell_integration::{
    get_status_with_backend, install_with_backend, uninstall_with_backend, MemoryRegistryBackend,
    DIR_MENU_KEY, FILE_MENU_KEY, PROG_ID_KEY, VAULT_EXT_KEY,
};
use rpm_storage::{
    decrypt_vault_v5, encrypt_sources_v5, parse_gui_launch_args, rekey_vault_v5, unique_path,
    GuiLaunchIntent, LaunchTab, SecureWiper, StorageError, UnpackLimits,
};
use tar::{Builder, EntryType, Header};

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
        header.set_entry_type(EntryType::Symlink);
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

    // Absolute entry path rejected
    let mut abs_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut abs_bytes);
        let mut header = Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        let raw_abs = b"/etc/passwd";
        let raw = header.as_mut_bytes();
        raw[..raw_abs.len()].copy_from_slice(raw_abs);
        raw[raw_abs.len()] = 0;
        header.set_cksum();
        builder.append(&header, &b"evil"[..]).unwrap();
        builder.finish().unwrap();
    }
    let res_abs = unpack_vault_stream(Cursor::new(abs_bytes), dir.path(), false, None);
    assert!(matches!(res_abs, Err(StorageError::InvalidPath(_))));

    // Hardlink entry rejected
    let mut hardlink_bytes = Vec::new();
    {
        let mut builder = Builder::new(&mut hardlink_bytes);
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Link);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_link_name("target.txt").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink.txt", std::io::empty())
            .unwrap();
        builder.finish().unwrap();
    }
    let res_hl = unpack_vault_stream(Cursor::new(hardlink_bytes), dir.path(), false, None);
    assert!(matches!(res_hl, Err(StorageError::InvalidPath(_))));
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

#[test]
fn single_file_unicode_empty_items_and_batch_extract_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // 1. Single Unicode file -> direct extraction without double nesting + collision suffix
    let uni = src_dir.join("Türkçe_Şifre_Ğüİöç.txt");
    fs::write(&uni, "Gizli Türkçe metin 🚀".as_bytes()).unwrap();
    let vault_uni = dir.path().join("uni.vault");
    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: 16 * 1024,
        recovery_key: None,
        keyfile_hash: None,
        compressed: true,
    };
    let cancel = Arc::new(AtomicBool::new(false));
    encrypt_sources_v5(
        std::slice::from_ref(&uni),
        &vault_uni,
        b"UniPw!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();

    let out_uni = dir.path().join("out_uni");
    let dec1 = decrypt_vault_v5(
        &vault_uni,
        &out_uni,
        Auth::Password {
            password: b"UniPw!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(dec1.output_path, out_uni.join("Türkçe_Şifre_Ğüİöç.txt"));
    assert_eq!(
        fs::read(&dec1.output_path).unwrap(),
        "Gizli Türkçe metin 🚀".as_bytes()
    );

    let dec2 = decrypt_vault_v5(
        &vault_uni,
        &out_uni,
        Auth::Password {
            password: b"UniPw!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(dec2.output_path, out_uni.join("Türkçe_Şifre_Ğüİöç_1.txt"));

    // 2. Folder containing 0-byte file + empty subdirectory
    let mix = src_dir.join("mix");
    fs::create_dir_all(mix.join("empty_sub")).unwrap();
    fs::write(mix.join("zero.bin"), b"").unwrap();
    let vault_mix = dir.path().join("mix.vault");
    encrypt_sources_v5(
        std::slice::from_ref(&mix),
        &vault_mix,
        b"MixPw!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    let out_mix = dir.path().join("out_mix");
    let dec_mix = decrypt_vault_v5(
        &vault_mix,
        &out_mix,
        Auth::Password {
            password: b"MixPw!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(dec_mix.output_path, out_mix.join("mix"));
    assert_eq!(fs::read(out_mix.join("mix/zero.bin")).unwrap().len(), 0);
    assert!(out_mix.join("mix/empty_sub").is_dir());

    // 3. Multi-item batch extracts grouped under vault stem
    let f1 = src_dir.join("first.txt");
    let f2 = src_dir.join("second.txt");
    fs::write(&f1, b"one").unwrap();
    fs::write(&f2, b"two").unwrap();
    let vault_batch = dir.path().join("batch_pack.vault");
    encrypt_sources_v5(
        &[f1, f2],
        &vault_batch,
        b"BatchPw!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    let out_batch = dir.path().join("out_batch");
    let dec_batch = decrypt_vault_v5(
        &vault_batch,
        &out_batch,
        Auth::Password {
            password: b"BatchPw!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(dec_batch.output_path, out_batch.join("batch_pack"));
    assert_eq!(
        fs::read(out_batch.join("batch_pack/first.txt")).unwrap(),
        b"one"
    );
    assert_eq!(
        fs::read(out_batch.join("batch_pack/second.txt")).unwrap(),
        b"two"
    );
}

#[test]
fn atomic_stage_and_swap_rolls_back_on_final_chunk_tamper() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("secret_docs");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("chunk0.bin"), vec![0x41u8; 64 * 1024]).unwrap();
    fs::write(folder.join("chunk_end.bin"), vec![0x42u8; 40 * 1024]).unwrap();

    let vault = dir.path().join("secret_docs.vault");
    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: 16 * 1024,
        recovery_key: None,
        keyfile_hash: None,
        compressed: false,
    };
    let cancel = Arc::new(AtomicBool::new(false));
    encrypt_sources_v5(
        std::slice::from_ref(&folder),
        &vault,
        b"AtomicPw!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();

    // Flip 1 byte in the final chunk tag after initial chunks already streamed to unpacker
    let mut raw = fs::read(&vault).unwrap();
    let idx = raw.len() - 5;
    raw[idx] ^= 0xAA;
    fs::write(&vault, raw).unwrap();

    let existing_root = dir.path().join("existing_root");
    fs::create_dir_all(&existing_root).unwrap();
    let res = decrypt_vault_v5(
        &vault,
        &existing_root,
        Auth::Password {
            password: b"AtomicPw!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        cancel,
    );
    assert!(matches!(
        res,
        Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
    ));
    let remaining: Vec<_> = fs::read_dir(&existing_root).unwrap().collect();
    assert!(
        remaining.is_empty(),
        "staging and partial extracted files must be completely removed"
    );
}

#[test]
fn tar_bomb_limits_enforce_size_count_and_depth() {
    let dir = tempfile::tempdir().unwrap();

    // 1. Compressed payload size bomb
    let big_zeroes = dir.path().join("zeros.bin");
    fs::write(&big_zeroes, vec![0u8; 200 * 1024]).unwrap();
    let mut gz_tar = Vec::new();
    pack_sources(
        std::slice::from_ref(&big_zeroes),
        &mut gz_tar,
        true,
        None,
        |_| {},
    )
    .unwrap();
    let out1 = dir.path().join("u1");
    let res_size = unpack_vault_stream_with_limits(
        Cursor::new(&gz_tar),
        &out1,
        true,
        UnpackLimits {
            max_total_bytes: 50_000,
            max_file_count: 100,
            max_path_depth: 32,
        },
        None,
    );
    assert!(matches!(res_size, Err(StorageError::LimitExceeded(_))));

    // 2. Entry count limit
    let files_dir = dir.path().join("many");
    fs::create_dir_all(&files_dir).unwrap();
    for i in 0..5 {
        fs::write(files_dir.join(format!("f{i}.txt")), b"x").unwrap();
    }
    let mut tar_many = Vec::new();
    pack_sources(
        std::slice::from_ref(&files_dir),
        &mut tar_many,
        false,
        None,
        |_| {},
    )
    .unwrap();
    let out2 = dir.path().join("u2");
    let res_count = unpack_vault_stream_with_limits(
        Cursor::new(&tar_many),
        &out2,
        false,
        UnpackLimits {
            max_total_bytes: 1024 * 1024,
            max_file_count: 3,
            max_path_depth: 32,
        },
        None,
    );
    assert!(matches!(res_count, Err(StorageError::LimitExceeded(_))));

    // 3. Path depth limit
    let deep = dir.path().join("a/b/c/d/e");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("leaf.txt"), b"ok").unwrap();
    let mut tar_deep = Vec::new();
    pack_sources(
        std::slice::from_ref(&dir.path().join("a")),
        &mut tar_deep,
        false,
        None,
        |_| {},
    )
    .unwrap();
    let out3 = dir.path().join("u3");
    let res_depth = unpack_vault_stream_with_limits(
        Cursor::new(&tar_deep),
        &out3,
        false,
        UnpackLimits {
            max_total_bytes: 1024 * 1024,
            max_file_count: 100,
            max_path_depth: 4,
        },
        None,
    );
    assert!(matches!(res_depth, Err(StorageError::LimitExceeded(_))));
}

#[test]
fn streaming_16mib_multichunk_and_cancellation_and_config_wiper() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("large_16m.bin");
    // Uncompressible pseudo-random pattern across 16 x 1 MiB default chunks
    let mut payload = vec![0u8; 16 * 1024 * 1024];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i.wrapping_mul(31).wrapping_add(i >> 9) & 0xFF) as u8;
    }
    fs::write(&big, &payload).unwrap();

    let vault = dir.path().join("large_16m.vault");
    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: rpm_core::constants::DEFAULT_CHUNK_SIZE,
        recovery_key: None,
        keyfile_hash: None,
        compressed: false,
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let (sum, _) = encrypt_sources_v5(
        std::slice::from_ref(&big),
        &vault,
        b"BigStreamPw!1",
        &opts,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    assert!(sum.chunks_written >= 16);

    let restore_root = dir.path().join("restored_big");
    let dec = decrypt_vault_v5(
        &vault,
        &restore_root,
        Auth::Password {
            password: b"BigStreamPw!1",
            keyfile_hash: None,
        },
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    assert_eq!(fs::read(&dec.output_path).unwrap(), payload);

    // Mid-encrypt cancellation removes temp files and creates no vault
    let cancel_enc = Arc::new(AtomicBool::new(false));
    let c_enc_cb = Arc::clone(&cancel_enc);
    let cancel_vault = dir.path().join("cancelled.vault");
    let res_enc_cancel = encrypt_sources_v5(
        std::slice::from_ref(&big),
        &cancel_vault,
        b"CancelPw!1",
        &opts,
        Arc::new(move |done, _| {
            if done > 0 {
                c_enc_cb.store(true, Ordering::Relaxed);
            }
        }),
        cancel_enc,
        |_| {},
    );
    assert!(matches!(
        res_enc_cancel,
        Err(StorageError::Crypto(CryptoError::Cancelled)) | Err(StorageError::Cancelled)
    ));
    assert!(!cancel_vault.exists());

    // Mid-decrypt cancellation leaves destination root untouched
    let cancel_dec = Arc::new(AtomicBool::new(false));
    let c_dec_cb = Arc::clone(&cancel_dec);
    let cancel_out = dir.path().join("cancel_out");
    let res_dec_cancel = decrypt_vault_v5(
        &vault,
        &cancel_out,
        Auth::Password {
            password: b"BigStreamPw!1",
            keyfile_hash: None,
        },
        Arc::new(move |done, _| {
            if done > 0 {
                c_dec_cb.store(true, Ordering::Relaxed);
            }
        }),
        cancel_dec,
    );
    assert!(matches!(
        res_dec_cancel,
        Err(StorageError::Crypto(CryptoError::Cancelled)) | Err(StorageError::Cancelled)
    ));
    assert!(!cancel_out.exists());

    // Config save/load round-trip & corrupt JSON fallback
    let cfg_path = dir.path().join("cfg/config.json");
    let cfg = AppConfig {
        theme: ThemeMode::Light,
        wipe_passes: 3,
        argon_memory_kib: 131_072,
        argon_iterations: 4,
        argon_parallelism: 4,
        compress_by_default: false,
    };
    save_config_to(&cfg_path, &cfg).unwrap();
    assert_eq!(load_config_from(&cfg_path), cfg);
    fs::write(&cfg_path, b"{not json!").unwrap();
    assert_eq!(load_config_from(&cfg_path), AppConfig::default());

    // SecureWiper on 0-byte file
    let zero_file = dir.path().join("empty_wipe.txt");
    fs::write(&zero_file, b"").unwrap();
    SecureWiper::default().wipe_file(&zero_file).unwrap();
    assert!(!zero_file.exists());
}
