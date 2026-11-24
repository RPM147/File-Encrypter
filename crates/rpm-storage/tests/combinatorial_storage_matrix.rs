use rpm_core::constants::MIN_CHUNK_SIZE;
use rpm_core::rs::RS_BLOCK_WIRE_SIZE;
use rpm_core::{
    check_integrity, entropy_to_mnemonic, generate_recovery_entropy, hash_keyfile_reader,
    inspect_header_seekable_with_kdf, mnemonic_to_entropy, Auth, EncryptOptions,
    HiddenEncryptOptions, KdfParams, SecretKey,
};
use rpm_storage::config::{
    load_config_from, save_config_to, AppConfig, AppLanguage, EncryptProfile, ThemeMode,
};
use rpm_storage::shell_integration::{
    get_status_with_backend, install_with_backend, uninstall_with_backend, MemoryRegistryBackend,
};
use rpm_storage::{
    decrypt_vault_v5_with_stealth_kdf, encrypt_hidden_sources_v5, encrypt_sources_v5,
    extract_entry_to_memory_v5_with_stealth_kdf, parse_gui_launch_args, rekey_vault_v5,
    repair_vault_v5, unique_path, GuiLaunchIntent, LaunchTab, SecureWiper,
};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

const MINI_PNG: &[u8] = include_bytes!("../../rpm-gui/assets/icon.png");
const PADDED_BYTES: u64 = 128 * 1024;
const HIDDEN_BYTES: u64 = 160 * 1024;
const TEST_CHUNK_SIZE: u32 = MIN_CHUNK_SIZE;

#[derive(Clone, Copy, PartialEq, Eq)]
enum EnvelopeMode {
    Standard,
    Stealth,
    ReedSolomon,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ContainerLayout {
    Unpadded,
    Padded,
    Hidden,
}

fn hash_key(bytes: &[u8]) -> SecretKey {
    hash_keyfile_reader(&mut Cursor::new(bytes)).unwrap()
}

fn flip_sector(bytes: &mut [u8], offset: usize, len: usize) {
    for (i, b) in bytes[offset..offset + len].iter_mut().enumerate() {
        *b ^= ((i % 251) + 1) as u8;
    }
}

fn wipe_targets(wiper: &SecureWiper, paths: &[PathBuf]) {
    for p in paths {
        if let Ok(meta) = fs::symlink_metadata(p) {
            if meta.is_dir() {
                wiper.wipe_folder(p).unwrap();
            } else {
                wiper.wipe_file(p).unwrap();
            }
        }
    }
}

fn run_storage_24_configs(mode: EnvelopeMode) {
    let fixture = tempfile::tempdir().unwrap();
    let outer_dir = fixture.path().join("outer");
    fs::create_dir_all(outer_dir.join("nested/sub")).unwrap();
    fs::create_dir_all(outer_dir.join("empty_dir")).unwrap();
    let outer_text = "Iğdır ölçüm raporu — Şifreli kasa testi 🚀\nSatır 2".as_bytes();
    let outer_bin: Vec<u8> = (0..2048).map(|i| ((i * 37) % 251) as u8).collect();
    let outer_deep = b"deep nested content for selective folder extraction";
    fs::write(outer_dir.join("Iğdır-ölçü.txt"), outer_text).unwrap();
    fs::write(outer_dir.join("icon.png"), MINI_PNG).unwrap();
    fs::write(outer_dir.join("data.bin"), &outer_bin).unwrap();
    fs::write(outer_dir.join("empty.txt"), b"").unwrap();
    fs::write(outer_dir.join("nested/sub/deep.txt"), outer_deep).unwrap();

    let hidden_dir = fixture.path().join("hidden");
    fs::create_dir_all(hidden_dir.join("vault_sub")).unwrap();
    let hidden_text = "Gizli bölme metni — yalnız gizli parolayla görünür".as_bytes();
    let hidden_bin: Vec<u8> = (0..2048).map(|i| (255 - ((i * 19) % 241)) as u8).collect();
    let hidden_nested = b"hidden nested sub item";
    fs::write(hidden_dir.join("gizli-not.txt"), hidden_text).unwrap();
    fs::write(hidden_dir.join("secret.png"), MINI_PNG).unwrap();
    fs::write(hidden_dir.join("secret.bin"), &hidden_bin).unwrap();
    fs::write(hidden_dir.join("h_empty.txt"), b"").unwrap();
    fs::write(hidden_dir.join("vault_sub/item.txt"), hidden_nested).unwrap();

    let kf1 = hash_key(b"storage-outer-keyfile-1");
    let kf2 = hash_key(b"storage-outer-keyfile-2");
    let kf_hidden = hash_key(b"storage-hidden-keyfile");
    let fast = KdfParams::fast_test();
    let cancel = Arc::new(AtomicBool::new(false));
    let progress: Arc<dyn Fn(u64, u64) + Send + Sync> = Arc::new(|_, _| {});
    let mut configs_run = 0usize;

    for layout in [
        ContainerLayout::Unpadded,
        ContainerLayout::Padded,
        ContainerLayout::Hidden,
    ] {
        let hidden_variants: &[(bool, bool)] = match layout {
            ContainerLayout::Hidden => {
                &[(false, false), (false, true), (true, false), (true, true)]
            }
            ContainerLayout::Unpadded | ContainerLayout::Padded => &[(false, false)],
        };
        for &outer_compress in &[false, true] {
            for &outer_kf_on in &[false, true] {
                for &(hidden_compress, hidden_kf_on) in hidden_variants {
                    configs_run += 1;
                    let case_dir = tempfile::tempdir().unwrap();
                    let out_dir = case_dir.path().join("vaults");
                    fs::create_dir_all(&out_dir).unwrap();
                    let mut vault_path = out_dir.join(format!("case_{configs_run}.vault"));

                    let entropy = generate_recovery_entropy();
                    let phrase = entropy_to_mnemonic(&entropy).unwrap();
                    let parsed_entropy = mnemonic_to_entropy(&phrase).unwrap();
                    let outer_kf = outer_kf_on.then(|| kf1.clone());
                    let hidden_kf = (layout == ContainerLayout::Hidden && hidden_kf_on)
                        .then(|| kf_hidden.clone());

                    if layout == ContainerLayout::Hidden {
                        let opts = HiddenEncryptOptions {
                            reed_solomon: mode == EnvelopeMode::ReedSolomon,
                            stealth: mode == EnvelopeMode::Stealth,
                            kdf: fast,
                            chunk_size: TEST_CHUNK_SIZE,
                            decoy_compressed: outer_compress,
                            hidden_compressed: hidden_compress,
                            decoy_recovery_key: Some(entropy.clone()),
                            decoy_keyfile_hash: outer_kf.clone(),
                            hidden_keyfile_hash: hidden_kf.clone(),
                            container_size_bytes: HIDDEN_BYTES,
                        };
                        encrypt_hidden_sources_v5(
                            std::slice::from_ref(&outer_dir),
                            std::slice::from_ref(&hidden_dir),
                            &vault_path,
                            b"OuterPw!1",
                            b"HiddenPw!2",
                            &opts,
                            Arc::clone(&progress),
                            Arc::clone(&cancel),
                            |_| {},
                        )
                        .unwrap();
                    } else {
                        let opts = EncryptOptions {
                            reed_solomon: mode == EnvelopeMode::ReedSolomon,
                            stealth: mode == EnvelopeMode::Stealth,
                            kdf: fast,
                            chunk_size: TEST_CHUNK_SIZE,
                            compressed: outer_compress,
                            recovery_key: Some(entropy.clone()),
                            keyfile_hash: outer_kf.clone(),
                            container_size_bytes: (layout == ContainerLayout::Padded)
                                .then_some(PADDED_BYTES),
                        };
                        encrypt_sources_v5(
                            std::slice::from_ref(&outer_dir),
                            &vault_path,
                            b"OuterPw!1",
                            &opts,
                            Arc::clone(&progress),
                            Arc::clone(&cancel),
                            |_| {},
                        )
                        .unwrap();
                    }

                    // No leftover .rpm_tmp_* staging files
                    let siblings: Vec<String> = fs::read_dir(&out_dir)
                        .unwrap()
                        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                        .collect();
                    assert_eq!(siblings.len(), 1);
                    assert!(!siblings[0].starts_with(".rpm_tmp_"));

                    // Stealth files work identically with arbitrary or missing extensions
                    if mode == EnvelopeMode::Stealth {
                        let renamed = out_dir.join(if configs_run.is_multiple_of(2) {
                            "archive_blob.bin"
                        } else {
                            "opaque_data"
                        });
                        fs::rename(&vault_path, &renamed).unwrap();
                        vault_path = renamed;
                    }

                    let outer_auth = Auth::Password {
                        password: b"OuterPw!1",
                        keyfile_hash: outer_kf.as_ref(),
                    };
                    let rec_auth = Auth::RecoveryKey(&parsed_entropy);

                    // Reed-Solomon: corrupt 512 B, test transparent preview & selective decrypt, alternate copy vs in-place repair
                    if mode == EnvelopeMode::ReedSolomon {
                        let clean = fs::read(&vault_path).unwrap();
                        let dmg_off = match configs_run % 3 {
                            0 => 0,
                            1 if clean.len() > 48 + RS_BLOCK_WIRE_SIZE + 64 + 512 => {
                                48 + RS_BLOCK_WIRE_SIZE + 64
                            }
                            1 => 48 + 64,
                            _ => clean.len() - 512,
                        };
                        let mut damaged = clean.clone();
                        flip_sector(&mut damaged, dmg_off, 512);
                        fs::write(&vault_path, &damaged).unwrap();

                        let dmg_rep = check_integrity(&vault_path).unwrap();
                        assert!(dmg_rep.ok && dmg_rep.has_reed_solomon);
                        assert_eq!(dmg_rep.rs_repaired_bytes, 512);

                        let preview_text = extract_entry_to_memory_v5_with_stealth_kdf(
                            &vault_path,
                            outer_auth,
                            "outer/Iğdır-ölçü.txt",
                            64 * 1024,
                            &fast,
                            Arc::clone(&progress),
                            Arc::clone(&cancel),
                        )
                        .unwrap();
                        assert_eq!(&preview_text[..], outer_text);

                        let sel_dmg_dir = case_dir.path().join("sel_dmg");
                        fs::create_dir_all(&sel_dmg_dir).unwrap();
                        decrypt_vault_v5_with_stealth_kdf(
                            &vault_path,
                            &sel_dmg_dir,
                            outer_auth,
                            Some(&["outer/icon.png".into()]),
                            &fast,
                            Arc::clone(&progress),
                            Arc::clone(&cancel),
                        )
                        .unwrap();
                        assert_eq!(
                            fs::read(sel_dmg_dir.join("outer/icon.png")).unwrap(),
                            MINI_PNG
                        );

                        if configs_run.is_multiple_of(2) {
                            let copy_path = out_dir.join("repaired_copy.vault");
                            let copy_rep =
                                repair_vault_v5(&vault_path, Some(&copy_path), Arc::clone(&cancel))
                                    .unwrap();
                            assert_eq!(copy_rep.repaired_bytes, 512);
                            assert_eq!(fs::read(&copy_path).unwrap(), clean);
                            assert_eq!(fs::read(&vault_path).unwrap(), damaged);
                            fs::rename(&copy_path, &vault_path).unwrap();
                        } else {
                            let in_place =
                                repair_vault_v5(&vault_path, None, Arc::clone(&cancel)).unwrap();
                            assert_eq!(in_place.repaired_bytes, 512);
                            assert_eq!(fs::read(&vault_path).unwrap(), clean);
                        }
                    }

                    let rep = check_integrity(&vault_path).unwrap();
                    assert!(rep.ok);
                    assert_eq!(rep.sha256_only, mode == EnvelopeMode::Stealth);
                    assert_eq!(rep.has_reed_solomon, mode == EnvelopeMode::ReedSolomon);
                    assert_eq!(rep.rs_repaired_bytes, 0);

                    // Outer RAM-Only Preview (rotating Text / PNG / Binary across Password and Recovery)
                    let vault_dir_before = fs::read_dir(&out_dir).unwrap().count();
                    let (pw_entry, pw_exp): (&str, &[u8]) = if configs_run.is_multiple_of(2) {
                        ("outer/Iğdır-ölçü.txt", outer_text)
                    } else {
                        ("outer/icon.png", MINI_PNG)
                    };
                    let (rec_entry, rec_exp): (&str, &[u8]) = if configs_run.is_multiple_of(2) {
                        ("outer/icon.png", MINI_PNG)
                    } else {
                        ("outer/data.bin", &outer_bin[..])
                    };

                    let prev_pw = extract_entry_to_memory_v5_with_stealth_kdf(
                        &vault_path,
                        outer_auth,
                        pw_entry,
                        64 * 1024,
                        &fast,
                        Arc::clone(&progress),
                        Arc::clone(&cancel),
                    )
                    .unwrap();
                    assert_eq!(&prev_pw[..], pw_exp);

                    let prev_rec = extract_entry_to_memory_v5_with_stealth_kdf(
                        &vault_path,
                        rec_auth,
                        rec_entry,
                        64 * 1024,
                        &fast,
                        Arc::clone(&progress),
                        Arc::clone(&cancel),
                    )
                    .unwrap();
                    assert_eq!(&prev_rec[..], rec_exp);
                    assert_eq!(fs::read_dir(&out_dir).unwrap().count(), vault_dir_before);

                    // Selective extract (single file + nested folder prefix) via Recovery
                    let sel_dir = case_dir.path().join("sel_outer");
                    fs::create_dir_all(&sel_dir).unwrap();
                    decrypt_vault_v5_with_stealth_kdf(
                        &vault_path,
                        &sel_dir,
                        rec_auth,
                        Some(&["outer/Iğdır-ölçü.txt".into(), "outer/nested".into()]),
                        &fast,
                        Arc::clone(&progress),
                        Arc::clone(&cancel),
                    )
                    .unwrap();
                    assert_eq!(
                        fs::read(sel_dir.join("outer/Iğdır-ölçü.txt")).unwrap(),
                        outer_text
                    );
                    assert_eq!(
                        fs::read(sel_dir.join("outer/nested/sub/deep.txt")).unwrap(),
                        outer_deep
                    );
                    assert!(!sel_dir.join("outer/data.bin").exists());

                    // Full decrypt via Password
                    let full_dir = case_dir.path().join("full_outer");
                    decrypt_vault_v5_with_stealth_kdf(
                        &vault_path,
                        &full_dir,
                        outer_auth,
                        None,
                        &fast,
                        Arc::clone(&progress),
                        Arc::clone(&cancel),
                    )
                    .unwrap();
                    let root = full_dir.join("outer");
                    assert_eq!(fs::read(root.join("Iğdır-ölçü.txt")).unwrap(), outer_text);
                    assert_eq!(fs::read(root.join("icon.png")).unwrap(), MINI_PNG);
                    assert_eq!(fs::read(root.join("data.bin")).unwrap(), outer_bin);
                    assert_eq!(fs::read(root.join("empty.txt")).unwrap(), b"");
                    assert_eq!(
                        fs::read(root.join("nested/sub/deep.txt")).unwrap(),
                        outer_deep
                    );
                    assert!(root.join("empty_dir").is_dir());

                    // Hidden compartment: RAM Preview + Selective + Full Decrypt
                    if layout == ContainerLayout::Hidden {
                        let hidden_auth = Auth::Password {
                            password: b"HiddenPw!2",
                            keyfile_hash: hidden_kf.as_ref(),
                        };
                        let (h_entry, h_exp): (&str, &[u8]) = if configs_run.is_multiple_of(2) {
                            ("hidden/gizli-not.txt", hidden_text)
                        } else {
                            ("hidden/secret.png", MINI_PNG)
                        };
                        let h_prev = extract_entry_to_memory_v5_with_stealth_kdf(
                            &vault_path,
                            hidden_auth,
                            h_entry,
                            64 * 1024,
                            &fast,
                            Arc::clone(&progress),
                            Arc::clone(&cancel),
                        )
                        .unwrap();
                        assert_eq!(&h_prev[..], h_exp);

                        let sel_hidden = case_dir.path().join("sel_hidden");
                        decrypt_vault_v5_with_stealth_kdf(
                            &vault_path,
                            &sel_hidden,
                            hidden_auth,
                            Some(&["hidden/vault_sub".into()]),
                            &fast,
                            Arc::clone(&progress),
                            Arc::clone(&cancel),
                        )
                        .unwrap();
                        assert_eq!(
                            fs::read(sel_hidden.join("hidden/vault_sub/item.txt")).unwrap(),
                            hidden_nested
                        );
                        assert!(!sel_hidden.join("hidden/secret.bin").exists());

                        let full_hidden = case_dir.path().join("full_hidden");
                        decrypt_vault_v5_with_stealth_kdf(
                            &vault_path,
                            &full_hidden,
                            hidden_auth,
                            None,
                            &fast,
                            Arc::clone(&progress),
                            Arc::clone(&cancel),
                        )
                        .unwrap();
                        let hroot = full_hidden.join("hidden");
                        assert_eq!(fs::read(hroot.join("gizli-not.txt")).unwrap(), hidden_text);
                        assert_eq!(fs::read(hroot.join("secret.png")).unwrap(), MINI_PNG);
                        assert_eq!(fs::read(hroot.join("secret.bin")).unwrap(), hidden_bin);
                        assert_eq!(fs::read(hroot.join("h_empty.txt")).unwrap(), b"");
                        assert_eq!(
                            fs::read(hroot.join("vault_sub/item.txt")).unwrap(),
                            hidden_nested
                        );
                    }

                    // Standard + Unpadded Re-Key transitions across compress × keyfile
                    if mode == EnvelopeMode::Standard && layout == ContainerLayout::Unpadded {
                        let mut current_pw = "OuterPw!1".to_string();
                        let mut current_kf = outer_kf.clone();
                        let transitions: Vec<Option<SecretKey>> = if outer_kf_on {
                            vec![Some(kf1.clone()), Some(kf2.clone()), None]
                        } else {
                            vec![None, Some(kf1.clone())]
                        };
                        for (step, next_kf) in transitions.into_iter().enumerate() {
                            let next_pw = format!("RotatedStorage!{configs_run}_{step}");
                            rekey_vault_v5(
                                &vault_path,
                                current_pw.as_bytes(),
                                next_pw.as_bytes(),
                                current_kf.as_ref(),
                                next_kf.as_ref(),
                                Some(fast),
                                Some(&cancel),
                            )
                            .unwrap();
                            current_pw = next_pw;
                            current_kf = next_kf;

                            let out_rekey = case_dir.path().join(format!("rekey_{step}"));
                            decrypt_vault_v5_with_stealth_kdf(
                                &vault_path,
                                &out_rekey,
                                Auth::Password {
                                    password: current_pw.as_bytes(),
                                    keyfile_hash: current_kf.as_ref(),
                                },
                                None,
                                &fast,
                                Arc::clone(&progress),
                                Arc::clone(&cancel),
                            )
                            .unwrap();
                            assert_eq!(
                                fs::read(out_rekey.join("outer/Iğdır-ölçü.txt")).unwrap(),
                                outer_text
                            );
                        }
                        let out_rec_after = case_dir.path().join("rekey_rec_final");
                        decrypt_vault_v5_with_stealth_kdf(
                            &vault_path,
                            &out_rec_after,
                            rec_auth,
                            None,
                            &fast,
                            Arc::clone(&progress),
                            Arc::clone(&cancel),
                        )
                        .unwrap();
                        assert_eq!(
                            fs::read(out_rec_after.join("outer/data.bin")).unwrap(),
                            outer_bin
                        );
                    }
                }
            }
        }
    }

    assert_eq!(configs_run, 24);
}

#[test]
fn storage_vault_matrix_standard_24() {
    run_storage_24_configs(EnvelopeMode::Standard);
}

#[test]
fn storage_vault_matrix_stealth_24() {
    run_storage_24_configs(EnvelopeMode::Stealth);
}

#[test]
fn storage_vault_matrix_reed_solomon_24() {
    run_storage_24_configs(EnvelopeMode::ReedSolomon);
}

#[test]
fn storage_payload_edge_cases_and_stealth_self_exclusion_matrix() {
    let fast = KdfParams::fast_test();
    let cancel = Arc::new(AtomicBool::new(false));
    let progress: Arc<dyn Fn(u64, u64) + Send + Sync> = Arc::new(|_, _| {});

    for mode in [
        EnvelopeMode::Standard,
        EnvelopeMode::Stealth,
        EnvelopeMode::ReedSolomon,
    ] {
        for compress in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let dir = dir.path();

            // Colliding basenames + mixed file & folder + 0 B file + empty dir + Unicode/emoji
            let folder_a = dir.join("dir_a");
            let folder_b = dir.join("dir_b");
            let single = dir.join("Iğdır-ölçü-🚀.txt");
            let empty_file = dir.join("zero.bin");
            let empty_folder = dir.join("void_dir");
            fs::create_dir_all(&folder_a).unwrap();
            fs::create_dir_all(&folder_b).unwrap();
            fs::create_dir_all(&empty_folder).unwrap();
            fs::write(folder_a.join("dup.txt"), b"from dir A").unwrap();
            fs::write(folder_b.join("dup.txt"), b"from dir B").unwrap();
            fs::write(&single, "Tek dosya UTF-8 içeriği — şğıöçÜ".as_bytes()).unwrap();
            fs::write(&empty_file, b"").unwrap();

            // Colliding output names via unique_path
            let base_vault = dir.join("archive.vault");
            let v1 = unique_path(&base_vault);
            let opts = EncryptOptions {
                reed_solomon: mode == EnvelopeMode::ReedSolomon,
                stealth: mode == EnvelopeMode::Stealth,
                kdf: fast,
                chunk_size: TEST_CHUNK_SIZE,
                compressed: compress,
                ..Default::default()
            };
            encrypt_sources_v5(
                &[
                    folder_a.join("dup.txt"),
                    folder_b.join("dup.txt"),
                    single.clone(),
                    empty_file.clone(),
                    empty_folder.clone(),
                ],
                &v1,
                b"EdgePw!1",
                &opts,
                Arc::clone(&progress),
                Arc::clone(&cancel),
                |_| {},
            )
            .unwrap();

            let v2 = unique_path(&base_vault);
            assert_ne!(v1, v2);
            encrypt_sources_v5(
                std::slice::from_ref(&single),
                &v2,
                b"EdgePw!1",
                &opts,
                Arc::clone(&progress),
                Arc::clone(&cancel),
                |_| {},
            )
            .unwrap();
            assert!(v2.exists());

            let dec1 = dir.join("dec_multi");
            let summary1 = decrypt_vault_v5_with_stealth_kdf(
                &v1,
                &dec1,
                Auth::Password {
                    password: b"EdgePw!1",
                    keyfile_hash: None,
                },
                None,
                &fast,
                Arc::clone(&progress),
                Arc::clone(&cancel),
            )
            .unwrap();
            assert_eq!(
                fs::read(summary1.output_path.join("dup.txt")).unwrap(),
                b"from dir A"
            );
            assert_eq!(
                fs::read(summary1.output_path.join("dup_2.txt")).unwrap(),
                b"from dir B"
            );
            assert_eq!(
                fs::read(summary1.output_path.join("Iğdır-ölçü-🚀.txt")).unwrap(),
                "Tek dosya UTF-8 içeriği — şğıöçÜ".as_bytes()
            );
            assert_eq!(
                fs::read(summary1.output_path.join("zero.bin")).unwrap(),
                b""
            );
            assert!(summary1.output_path.join("void_dir").is_dir());

            let dec2 = dir.join("dec_single");
            let summary2 = decrypt_vault_v5_with_stealth_kdf(
                &v2,
                &dec2,
                Auth::Password {
                    password: b"EdgePw!1",
                    keyfile_hash: None,
                },
                None,
                &fast,
                Arc::clone(&progress),
                Arc::clone(&cancel),
            )
            .unwrap();
            assert_eq!(
                fs::read(&summary2.output_path).unwrap(),
                "Tek dosya UTF-8 içeriği — şğıöçÜ".as_bytes()
            );
        }
    }

    // Stealth output placed directly inside the selected folder excludes itself cleanly
    let sdir = tempfile::tempdir().unwrap();
    let payload_dir = sdir.path().join("src_folder");
    fs::create_dir_all(&payload_dir).unwrap();
    fs::write(
        payload_dir.join("note.txt"),
        b"hello stealth self exclusion",
    )
    .unwrap();
    let stealth_inside = payload_dir.join("inside.bin");
    encrypt_sources_v5(
        std::slice::from_ref(&payload_dir),
        &stealth_inside,
        b"SelfExcl!1",
        &EncryptOptions {
            stealth: true,
            kdf: fast,
            chunk_size: TEST_CHUNK_SIZE,
            ..Default::default()
        },
        Arc::clone(&progress),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();
    let info = inspect_header_seekable_with_kdf(
        &mut fs::File::open(&stealth_inside).unwrap(),
        Auth::Password {
            password: b"SelfExcl!1",
            keyfile_hash: None,
        },
        &fast,
    )
    .unwrap();
    assert_eq!(info.metadata.files.len(), 1);
    assert_eq!(info.metadata.files[0].path, "src_folder/note.txt");

    // Best-effort symlink skip test when OS permits symlink creation
    let link_target = sdir.path().join("real_target.txt");
    let link_path = payload_dir.join("link.txt");
    fs::write(&link_target, b"outside target").unwrap();
    #[cfg(windows)]
    let link_res = std::os::windows::fs::symlink_file(&link_target, &link_path);
    #[cfg(unix)]
    let link_res = std::os::unix::fs::symlink(&link_target, &link_path);
    if link_res.is_ok() {
        let skipped = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let skipped_cb = Arc::clone(&skipped);
        let sym_vault = sdir.path().join("sym.vault");
        encrypt_sources_v5(
            std::slice::from_ref(&payload_dir),
            &sym_vault,
            b"SymPw!1",
            &EncryptOptions {
                kdf: fast,
                chunk_size: TEST_CHUNK_SIZE,
                ..Default::default()
            },
            progress,
            cancel,
            move |msg| skipped_cb.lock().unwrap().push(msg.to_string()),
        )
        .unwrap();
        assert!(skipped
            .lock()
            .unwrap()
            .iter()
            .any(|m| m.contains("symlink skipped")));
    }
}

#[test]
fn storage_wipe_passes_and_output_modes_matrix() {
    let fast = KdfParams::fast_test();
    let cancel = Arc::new(AtomicBool::new(false));
    let progress: Arc<dyn Fn(u64, u64) + Send + Sync> = Arc::new(|_, _| {});
    let mut ran = 0usize;

    for passes in 1u8..=5 {
        for mode in [
            EnvelopeMode::Standard,
            EnvelopeMode::Stealth,
            EnvelopeMode::ReedSolomon,
        ] {
            for is_dir in [false, true] {
                for next_to_source in [false, true] {
                    ran += 1;
                    let dir = tempfile::tempdir().unwrap();
                    let src_root = dir.path().join("src");
                    let custom_out = dir.path().join("out");
                    fs::create_dir_all(&src_root).unwrap();
                    fs::create_dir_all(&custom_out).unwrap();

                    let source = if is_dir {
                        let d = src_root.join("bundle");
                        fs::create_dir_all(d.join("sub")).unwrap();
                        fs::write(d.join("a.txt"), b"wipe folder a").unwrap();
                        fs::write(d.join("sub/b.txt"), b"wipe folder b").unwrap();
                        d
                    } else {
                        let f = src_root.join("secret.txt");
                        fs::write(&f, b"wipe single file payload").unwrap();
                        f
                    };

                    let out_vault = if next_to_source {
                        src_root.join(format!("v_{ran}.vault"))
                    } else {
                        custom_out.join(format!("v_{ran}.vault"))
                    };

                    encrypt_sources_v5(
                        std::slice::from_ref(&source),
                        &out_vault,
                        b"WipePw!1",
                        &EncryptOptions {
                            reed_solomon: mode == EnvelopeMode::ReedSolomon,
                            stealth: mode == EnvelopeMode::Stealth,
                            kdf: fast,
                            chunk_size: TEST_CHUNK_SIZE,
                            ..Default::default()
                        },
                        Arc::clone(&progress),
                        Arc::clone(&cancel),
                        |_| {},
                    )
                    .unwrap();

                    wipe_targets(&SecureWiper::new(passes), std::slice::from_ref(&source));
                    assert!(!source.exists());
                    assert!(out_vault.is_file());

                    let restore = dir.path().join("restored");
                    let summary = decrypt_vault_v5_with_stealth_kdf(
                        &out_vault,
                        &restore,
                        Auth::Password {
                            password: b"WipePw!1",
                            keyfile_hash: None,
                        },
                        None,
                        &fast,
                        Arc::clone(&progress),
                        Arc::clone(&cancel),
                    )
                    .unwrap();
                    if is_dir {
                        assert_eq!(
                            fs::read(summary.output_path.join("a.txt")).unwrap(),
                            b"wipe folder a"
                        );
                        assert_eq!(
                            fs::read(summary.output_path.join("sub/b.txt")).unwrap(),
                            b"wipe folder b"
                        );
                    } else {
                        assert_eq!(
                            fs::read(&summary.output_path).unwrap(),
                            b"wipe single file payload"
                        );
                    }
                }
            }
        }
    }

    assert_eq!(ran, 60);
}

#[test]
fn storage_config_launch_and_shell_integration_matrix() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("config.json");

    let mut seen_mem = std::collections::BTreeSet::new();
    for (idx, theme) in [ThemeMode::Dark, ThemeMode::Light].into_iter().enumerate() {
        for language in [AppLanguage::Tr, AppLanguage::En] {
            for &scale in &[80u16, 90, 100, 110, 120, 130, 150] {
                let scale_step = usize::from(scale / 10);
                let compress = (idx + scale_step) % 2 == 0;
                let wipe = (scale_step % 5 + 1) as u8;
                let mem = [16_384, 65_536, 131_072, 262_144][scale_step % 4];
                seen_mem.insert(mem);
                let iters = [1, 3, 10][usize::from(wipe) % 3];
                let par = [1, 4, 16][scale_step % 3];

                let cfg = AppConfig {
                    ui_scale_percent: scale,
                    theme,
                    language,
                    wipe_passes: wipe,
                    argon_memory_kib: mem,
                    argon_iterations: iters,
                    argon_parallelism: par,
                    compress_by_default: compress,
                    idle_clear_minutes: if idx == 0 { 0 } else { 15 },
                    notify_on_complete: idx % 2 == 0,
                    encrypt_profiles: vec![EncryptProfile {
                        name: format!("Profile-{scale}"),
                        compress,
                        stealth: idx == 1,
                        reed_solomon: idx == 0,
                        secure_wipe: false,
                        container_size_mib: (scale >= 120).then_some(100),
                        split_part_mib: (scale >= 120).then_some(4000),
                        save_next_to_source: true,
                        output_dir: String::new(),
                        keyfile_path: None,
                    }],
                };
                save_config_to(&cfg_path, &cfg).unwrap();
                let raw = fs::read_to_string(&cfg_path).unwrap();
                assert!(!raw.contains("password") && !raw.contains("recovery"));
                assert_eq!(load_config_from(&cfg_path), cfg);
            }
        }
    }
    assert_eq!(seen_mem.len(), 4);

    // Launch intent matrix
    let launch_cases: &[(&[&str], Option<LaunchTab>, usize)] = &[
        (&[], None, 0),
        (
            &["--gui-encrypt", "a.txt", "b_dir"],
            Some(LaunchTab::Encrypt),
            2,
        ),
        (
            &["--gui-decrypt", "one.vault", "two.bin"],
            Some(LaunchTab::Decrypt),
            2,
        ),
        (&["single.vault"], Some(LaunchTab::Decrypt), 1),
        (&["one.VAULT", "two.vault"], Some(LaunchTab::Decrypt), 2),
        (&["plain.txt"], Some(LaunchTab::Encrypt), 1),
        (&["folder"], Some(LaunchTab::Encrypt), 1),
        (&["one.vault", "plain.txt"], Some(LaunchTab::Encrypt), 2),
    ];
    for &(args, ref expected_tab, expected_count) in launch_cases {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let intent: GuiLaunchIntent = parse_gui_launch_args(&owned);
        assert_eq!(&intent.tab, expected_tab);
        assert_eq!(intent.paths.len(), expected_count);
    }

    // Isolated in-memory registry shell integration lifecycle
    let mut reg = MemoryRegistryBackend::default();
    let st0 = get_status_with_backend(&reg);
    assert!(!st0.installed);
    let icon = Path::new(r"C:\Apps\rpm-encrypter.exe");
    let st1 = install_with_backend(&mut reg, r#""C:\Apps\rpm-encrypter.exe""#, Some(icon)).unwrap();
    assert!(st1.installed && st1.context_menu_installed && st1.vault_association_installed);
    let st2 = uninstall_with_backend(&mut reg).unwrap();
    assert!(!st2.installed && !st2.context_menu_installed && !st2.vault_association_installed);
}
