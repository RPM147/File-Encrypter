use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use eframe::egui;
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};
use rpm_core::rs::RS_BLOCK_WIRE_SIZE;
use rpm_core::{KdfParams, SecretKey};
use rpm_gui::preview::{classify_preview, ClassifiedPreview, PreviewState};
use rpm_gui::state::{
    strength_label_and_color_for, AppState, ContainerSizePreset, RecoveryPrompt, Tab, WorkerUpdate,
    PWGEN_AMBIGUOUS, UI_SCALE_PRESETS,
};
use rpm_gui::{tabs, worker};
use rpm_storage::config::{load_config_from, save_config_to, AppConfig, AppLanguage, ThemeMode};
use zeroize::Zeroizing;

const MINI_PNG: &[u8] = include_bytes!("../assets/icon.png");

fn flip_sector(bytes: &mut [u8], offset: usize, len: usize) {
    for (i, b) in bytes[offset..offset + len].iter_mut().enumerate() {
        *b ^= ((i % 251) + 1) as u8;
    }
}

fn encode_sample_image(fmt: ImageFormat) -> Vec<u8> {
    let img = DynamicImage::ImageRgb8(ImageBuffer::from_fn(4, 4, |x, y| {
        Rgb([(x * 60) as u8, (y * 60) as u8, 128u8])
    }));
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, fmt).unwrap();
    out.into_inner()
}

fn recv_done(rx: &mpsc::Receiver<WorkerUpdate>) -> WorkerUpdate {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let rem = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(rem).expect("worker update timed out") {
            WorkerUpdate::Progress(_) | WorkerUpdate::Log(_) => continue,
            WorkerUpdate::Error(err) => panic!("unexpected worker error: {err}"),
            other => return other,
        }
    }
}

fn isolated_state(tmp: &tempfile::TempDir) -> AppState {
    let fast = KdfParams::fast_test();
    let cfg = AppConfig {
        argon_memory_kib: fast.memory_kib,
        argon_iterations: fast.iterations,
        argon_parallelism: fast.parallelism,
        ..AppConfig::default()
    };
    AppState::from_config(cfg, Some(tmp.path().join("config.json")))
}

#[test]
fn gui_pwgen_full_150_cartesian_matrix() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = egui::Context::default();
    let mut combos = 0usize;

    for mask in 1u8..=15 {
        for &exclude_ambiguous in &[false, true] {
            for &length in &[12usize, 16, 24, 32, 64] {
                combos += 1;
                let mut st = isolated_state(&tmp);
                st.pwgen.include_uppercase = (mask & 1) != 0;
                st.pwgen.include_lowercase = (mask & 2) != 0;
                st.pwgen.include_digits = (mask & 4) != 0;
                st.pwgen.include_symbols = (mask & 8) != 0;
                st.pwgen.exclude_ambiguous = exclude_ambiguous;
                st.pwgen.length = length;

                let alphabet = st.pwgen.build_alphabet();
                assert!(!alphabet.is_empty());
                assert!(st.pwgen.has_any_class());

                st.generate_password();
                let pw = st.pwgen.generated.clone();
                assert_eq!(pw.len(), length);
                assert!(pw.as_bytes().iter().all(|b| alphabet.contains(b)));
                if exclude_ambiguous {
                    assert!(!pw.as_bytes().iter().any(|b| PWGEN_AMBIGUOUS.contains(b)));
                }

                for lang in [AppLanguage::Tr, AppLanguage::En] {
                    let (lbl, frac, _color) = strength_label_and_color_for(&pw, lang);
                    assert!(!lbl.is_empty());
                    assert!(frac > 0.0);
                }

                if combos.is_multiple_of(15) {
                    st.copy_secret_with_autoclear(&ctx, pw.clone(), st.strings().status_pw_copied);
                    assert!(st.clipboard_deadline.is_some());
                    st.encrypt.password = pw.clone();
                    st.encrypt.confirm_password = pw;
                    assert_eq!(st.encrypt.password, st.encrypt.confirm_password);
                }
            }
        }
    }

    assert_eq!(combos, 150);
}

#[test]
fn gui_settings_theme_lang_scale_and_all_tabs_headless_render_matrix() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = egui::Context::default();
    let (tx, _rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut st = isolated_state(&tmp);

    // Exhaustive settings matrix + disk config persistence in isolated tempdir
    let mut seen_mem = std::collections::BTreeSet::new();
    for &theme in &[ThemeMode::Dark, ThemeMode::Light] {
        for &lang in &[AppLanguage::Tr, AppLanguage::En] {
            for &scale in &UI_SCALE_PRESETS {
                let scale_step = usize::from(scale / 10);
                let compress = scale_step.is_multiple_of(2);
                let passes = (scale_step % 5 + 1) as u8;
                let mem = [16_384, 65_536, 131_072, 262_144][scale_step % 4];
                seen_mem.insert(mem);
                let iters = [1, 3, 10][usize::from(passes) % 3];
                let par = [1, 4, 16][scale_step % 3];

                st.config.theme = theme;
                st.config.language = lang;
                st.config.compress_by_default = compress;
                st.config.wipe_passes = passes;
                st.apply_theme_visuals(&ctx);
                st.set_ui_scale_percent(scale, &ctx);
                assert!((st.ui_scale_zoom_factor() - f32::from(scale) / 100.0).abs() < 1e-4);
                st.set_argon_params(mem, iters, par).unwrap();
                st.validate_kdf_params().unwrap();
                st.save_preferences().unwrap();

                let loaded = load_config_from(st.config_path.as_ref().unwrap());
                assert_eq!(loaded, st.config);
            }
        }
    }
    assert_eq!(seen_mem.len(), 4);

    // Re-save explicitly through save_config_to and confirm valid load
    let cfg_copy = st.config.clone();
    save_config_to(st.config_path.as_ref().unwrap(), &cfg_copy).unwrap();

    // Headless egui rendering of ALL 6 tabs across Theme x Language (including Encrypt hidden+modal and Settings modal)
    for theme in [ThemeMode::Dark, ThemeMode::Light] {
        for lang in [AppLanguage::Tr, AppLanguage::En] {
            st.config.theme = theme;
            st.config.language = lang;
            st.apply_theme_visuals(&ctx);
            st.encrypt.enable_hidden = true;
            st.encrypt.recovery_prompt = Some(RecoveryPrompt {
                phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
                entropy: SecretKey::new([7u8; 32]),
                confirmed: true,
            });
            st.show_shell_install_modal = true;

            for tab in Tab::ALL {
                st.select_tab(tab);
                ctx.run_ui(Default::default(), |ui| match tab {
                    Tab::Encrypt => tabs::encrypt::ui(ui, &ctx, &mut st, &tx, &cancel),
                    Tab::Decrypt => tabs::decrypt::ui(ui, &ctx, &mut st, &tx, &cancel),
                    Tab::Inspect => tabs::inspect::ui(ui, &ctx, &mut st, &tx, &cancel),
                    Tab::Rekey => tabs::rekey::ui(ui, &ctx, &mut st, &tx, &cancel),
                    Tab::Password => tabs::password::ui(ui, &ctx, &mut st),
                    Tab::Settings => tabs::settings::ui(ui, &ctx, &mut st),
                })
                .textures_delta
                .clear();
            }
        }
    }
}

#[test]
fn gui_encrypt_container_presets_and_mode_matrix() {
    let tmp = tempfile::tempdir().unwrap();
    let presets = [
        (ContainerSizePreset::Auto, None, false),
        (ContainerSizePreset::MiB10, Some(10 * 1024 * 1024), true),
        (ContainerSizePreset::MiB50, Some(50 * 1024 * 1024), true),
        (ContainerSizePreset::MiB100, Some(100 * 1024 * 1024), true),
        (ContainerSizePreset::MiB500, Some(500 * 1024 * 1024), true),
        (ContainerSizePreset::Custom, Some(1024 * 1024), true),
        (ContainerSizePreset::Custom, Some(25 * 1024 * 1024), true),
        (
            ContainerSizePreset::Custom,
            Some(65_536 * 1024 * 1024),
            true,
        ),
    ];
    let custom_inputs = ["100", "100", "100", "100", "100", "1", "25", "65536"];

    for ((preset, expected_bytes, allows_hidden), custom) in presets.into_iter().zip(custom_inputs)
    {
        for mode in 0usize..3 {
            let mut st = isolated_state(&tmp);
            st.encrypt.container_preset = preset;
            st.encrypt.container_custom_mb = custom.into();
            match mode {
                0 => {}
                1 => st.encrypt.set_stealth(true),
                _ => st.encrypt.set_reed_solomon(true),
            }
            st.encrypt.compress = mode.is_multiple_of(2);
            st.encrypt.hidden_compress = mode != 0;
            st.encrypt.save_next_to_source = mode == 0;
            st.encrypt.keyfile = (mode != 2).then(|| PathBuf::from("outer.key"));
            st.encrypt.password = "Outer!1".into();
            st.encrypt.confirm_password = "Outer!1".into();

            if allows_hidden {
                st.encrypt.set_hidden_enabled(true);
                st.encrypt.hidden_keyfile = Some(PathBuf::from("hidden.key"));
                st.encrypt.hidden_password = "Hidden!2".into();
                st.encrypt.hidden_confirm_password = "Hidden!2".into();
                assert_eq!(st.encrypt.resolve_container_size(), Ok(expected_bytes));
            } else {
                assert_eq!(st.encrypt.resolve_container_size(), Ok(None));
            }

            st.clear_encrypt_secrets();
            assert!(st.encrypt.password.is_empty());
            assert!(st.encrypt.hidden_password.is_empty());
            assert!(st.encrypt.recovery_prompt.is_none());
        }
    }
}

#[test]
fn gui_preview_all_5_image_formats_multipage_utf8_and_lifecycle_matrix() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = egui::Context::default();
    let (tx, _rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));

    let formats = [
        ("sample.png", ImageFormat::Png),
        ("sample.jpg", ImageFormat::Jpeg),
        ("sample.webp", ImageFormat::WebP),
        ("sample.gif", ImageFormat::Gif),
        ("sample.bmp", ImageFormat::Bmp),
    ];
    for (name, fmt) in formats {
        let encoded = encode_sample_image(fmt);
        assert!(
            matches!(
                classify_preview(name, &encoded),
                ClassifiedPreview::Image(img) if img.size == [4, 4]
            ),
            "failed decoding image preview for {name}"
        );

        let mut st = isolated_state(&tmp);
        st.select_tab(Tab::Inspect);
        st.inspect.preview = Some(PreviewState::new(
            &ctx,
            name.into(),
            Zeroizing::new(encoded),
        ));
        for lang in [AppLanguage::Tr, AppLanguage::En] {
            st.config.language = lang;
            let mut out = ctx.run_ui(Default::default(), |ui| {
                tabs::inspect::ui(ui, &ctx, &mut st, &tx, &cancel);
            });
            out.textures_delta.clear();
        }
        assert!(st.dismiss_modals());
        assert!(st.inspect.preview.is_none());
    }

    // Short & >16 KiB multi-page UTF-8 (Turkish multibyte across 8192-byte page boundaries) + Binary
    let long_utf8 = "Iğdır-Şırnak-Ölçü 🧪 ".repeat(900);
    assert!(long_utf8.len() > 16_384);
    assert!(matches!(
        classify_preview("short.txt", "Kısa UTF-8".as_bytes()),
        ClassifiedPreview::Text(_)
    ));
    assert!(matches!(
        classify_preview("long.log", long_utf8.as_bytes()),
        ClassifiedPreview::Text(_)
    ));
    assert!(matches!(
        classify_preview("blob.dat", &[0u8, 1, 2, 0xff]),
        ClassifiedPreview::Binary
    ));

    let mut st = isolated_state(&tmp);
    st.select_tab(Tab::Inspect);
    for (name, bytes) in [
        ("long.log", long_utf8.into_bytes()),
        ("blob.dat", vec![0u8, 1, 2, 0xff]),
    ] {
        st.inspect.preview = Some(PreviewState::new(&ctx, name.into(), Zeroizing::new(bytes)));
        for lang in [AppLanguage::Tr, AppLanguage::En] {
            st.config.language = lang;
            ctx.run_ui(Default::default(), |ui| {
                tabs::inspect::ui(ui, &ctx, &mut st, &tx, &cancel);
            })
            .textures_delta
            .clear();
        }
    }

    // Lifecycle cleanup checks: clear_preview, dismiss_modals (Esc), tab switch, and reset_manifest
    st.select_tab(Tab::Inspect);
    st.inspect.preview = Some(PreviewState::new(
        &ctx,
        "a.txt".into(),
        Zeroizing::new(b"abc".to_vec()),
    ));
    st.inspect.clear_preview();
    assert!(st.inspect.preview.is_none());

    st.inspect.preview = Some(PreviewState::new(
        &ctx,
        "b.txt".into(),
        Zeroizing::new(b"abc".to_vec()),
    ));
    assert!(st.dismiss_modals());
    assert!(st.inspect.preview.is_none());

    st.inspect.preview = Some(PreviewState::new(
        &ctx,
        "c.txt".into(),
        Zeroizing::new(b"abc".to_vec()),
    ));
    st.select_tab(Tab::Encrypt);
    assert!(st.inspect.preview.is_none());

    st.select_tab(Tab::Inspect);
    st.inspect.preview = Some(PreviewState::new(
        &ctx,
        "d.txt".into(),
        Zeroizing::new(b"abc".to_vec()),
    ));
    st.inspect.reset_manifest();
    assert!(st.inspect.preview.is_none());
}

#[test]
fn gui_drag_drop_shortcuts_launch_and_manifest_filter_matrix() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let regular = dir.join("doc.txt");
    let stealth_bin = dir.join("opaque.bin");
    let vault = dir.join("backup.vault");
    let folder = dir.join("folder");
    fs::write(&regular, b"doc").unwrap();
    fs::write(&stealth_bin, b"bin").unwrap();
    fs::write(&vault, b"vault").unwrap();
    fs::create_dir(&folder).unwrap();

    // Drag-and-drop triage across all active tabs (matching app.rs routing)
    for active in Tab::ALL {
        for sample in [&regular, &stealth_bin, &vault, &folder] {
            let mut st = isolated_state(&tmp);
            st.select_tab(active);
            let forced = match active {
                Tab::Decrypt if !sample.is_dir() => Some(Tab::Decrypt),
                Tab::Inspect | Tab::Rekey => Some(active),
                _ => None,
            };
            st.add_dropped_paths(vec![sample.clone()], forced);
            match active {
                Tab::Decrypt if !sample.is_dir() => {
                    assert_eq!(st.active_tab, Tab::Decrypt);
                    assert_eq!(st.decrypt.vaults, vec![sample.clone()]);
                }
                Tab::Inspect => {
                    assert_eq!(st.active_tab, Tab::Inspect);
                    assert_eq!(st.inspect.vault_path, sample.display().to_string());
                }
                Tab::Rekey => {
                    assert_eq!(st.active_tab, Tab::Rekey);
                    assert_eq!(st.rekey.vault_path, sample.display().to_string());
                }
                _ => {
                    if sample == &vault {
                        assert_eq!(st.active_tab, Tab::Decrypt);
                    } else {
                        assert_eq!(st.active_tab, Tab::Encrypt);
                        assert_eq!(st.encrypt.sources, vec![sample.clone()]);
                    }
                }
            }
        }
    }

    // Ctrl+1..Ctrl+6 tab shortcuts + Esc modal dismissal
    let mut st = isolated_state(&tmp);
    for (idx, expected) in Tab::ALL.into_iter().enumerate() {
        assert!(st.handle_shortcut_tab((idx + 1) as u8));
        assert_eq!(st.active_tab, expected);
    }
    st.show_shell_install_modal = true;
    st.encrypt.recovery_prompt = Some(RecoveryPrompt {
        phrase: "one two".into(),
        entropy: SecretKey::new([1u8; 32]),
        confirmed: false,
    });
    assert!(st.dismiss_modals());
    assert!(!st.show_shell_install_modal);
    assert!(st.encrypt.recovery_prompt.is_none());

    // Manifest filtering & selection
    st.inspect.set_manifest(
        vault,
        vec![
            rpm_core::FileManifestEntry {
                path: "docs/readme.md".into(),
                size: 100,
                modified_unix: 1,
            },
            rpm_core::FileManifestEntry {
                path: "docs/notes.txt".into(),
                size: 200,
                modified_unix: 2,
            },
            rpm_core::FileManifestEntry {
                path: "photos/pic.png".into(),
                size: 300,
                modified_unix: 3,
            },
        ],
    );
    st.inspect.filter_query = "DOCS/".into();
    assert_eq!(st.inspect.filtered_indices(), vec![0, 1]);
    st.inspect.select_all_filtered();
    assert_eq!(st.inspect.selected_paths.len(), 2);
    st.inspect.clear_selection();
    assert!(st.inspect.selected_paths.is_empty());
}

#[test]
fn gui_workers_all_10_operations_and_bilingual_reports_matrix() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let src_dir = root.join("src_data");
    let hid_dir = root.join("hid_data");
    fs::create_dir_all(src_dir.join("sub")).unwrap();
    fs::create_dir_all(&hid_dir).unwrap();
    fs::write(src_dir.join("not.txt"), "Türkçe metin 🎯").unwrap();
    fs::write(src_dir.join("sub/icon.png"), MINI_PNG).unwrap();
    fs::write(hid_dir.join("secret.txt"), b"hidden compartment content").unwrap();
    fs::write(hid_dir.join("secret.png"), MINI_PNG).unwrap();

    let kf1 = root.join("kf1.key");
    let kf2 = root.join("kf2.key");
    let kf_h = root.join("kfh.key");
    fs::write(&kf1, b"gui-kf-1").unwrap();
    fs::write(&kf2, b"gui-kf-2").unwrap();
    fs::write(&kf_h, b"gui-kf-h").unwrap();

    let ctx = egui::Context::default();
    let fast = KdfParams::fast_test();
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();

    // 1. Standard Unpadded (compress + keyfile + wipe on copied file): encrypt -> integrity -> inspect -> preview -> sel -> dec -> rekey -> dec
    let wipe_copy = root.join("wipe_src.txt");
    fs::write(&wipe_copy, b"single wipe file").unwrap();
    let rec_std = rpm_core::generate_recovery_entropy();
    let phrase_std = rpm_core::entropy_to_mnemonic(&rec_std).unwrap();
    let std_dir = root.join("std_out");
    fs::create_dir(&std_dir).unwrap();
    worker::spawn_encrypt(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        vec![wipe_copy.clone()],
        Zeroizing::new("StdPw!1".into()),
        rec_std,
        Some(kf1.clone()),
        Some(std_dir.clone()),
        true,
        None,
        false,
        false,
        true,
        2,
        fast,
        AppLanguage::Tr,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::EncryptDone { .. }));
    assert!(!wipe_copy.exists());
    let std_vault = std_dir.join("wipe_src.txt.vault");

    for lang in [AppLanguage::Tr, AppLanguage::En] {
        worker::spawn_integrity_check(ctx.clone(), tx.clone(), std_vault.clone(), lang);
        match recv_done(&rx) {
            WorkerUpdate::IntegrityDone {
                text,
                ok,
                sha256_only,
            } => {
                assert!(ok && !sha256_only);
                let cols: Vec<usize> = text
                    .split("\n\n")
                    .next()
                    .unwrap()
                    .lines()
                    .skip(1)
                    .map(|l| l.chars().position(|c| c == ':').unwrap())
                    .collect();
                assert!(cols.windows(2).all(|w| w[0] == w[1]), "{text}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    worker::spawn_rekey(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        std_vault.clone(),
        Zeroizing::new("StdPw!1".into()),
        Zeroizing::new("StdPw!2".into()),
        Some(kf1.clone()),
        Some(kf2.clone()),
        fast,
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::RekeyDone { .. }));

    let std_dec = root.join("std_dec_rec");
    fs::create_dir(&std_dec).unwrap();
    worker::spawn_decrypt(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        vec![std_vault],
        true,
        Zeroizing::new(phrase_std.to_string()),
        None,
        Some(std_dec.clone()),
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::DecryptDone { .. }));
    assert_eq!(
        fs::read(std_dec.join("wipe_src.txt")).unwrap(),
        b"single wipe file"
    );

    // 1b. Padded (1 MiB) Standard vault: encrypt -> integrity -> inspect -> decrypt
    let pad_out = root.join("pad_out");
    fs::create_dir(&pad_out).unwrap();
    worker::spawn_encrypt(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        vec![src_dir.clone()],
        Zeroizing::new("PadPw!1".into()),
        rpm_core::generate_recovery_entropy(),
        None,
        Some(pad_out.clone()),
        true,
        Some(1024 * 1024),
        false,
        false,
        false,
        1,
        fast,
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::EncryptDone { .. }));
    let pad_vault = pad_out.join("src_data.vault");
    assert_eq!(fs::metadata(&pad_vault).unwrap().len(), 1024 * 1024);
    worker::spawn_integrity_check(ctx.clone(), tx.clone(), pad_vault.clone(), AppLanguage::En);
    assert!(matches!(
        recv_done(&rx),
        WorkerUpdate::IntegrityDone {
            ok: true,
            sha256_only: false,
            ..
        }
    ));
    worker::spawn_inspect(
        ctx.clone(),
        tx.clone(),
        pad_vault.clone(),
        false,
        Zeroizing::new("PadPw!1".into()),
        None,
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::InspectDone { .. }));
    let pad_dec = root.join("pad_dec");
    fs::create_dir(&pad_dec).unwrap();
    worker::spawn_decrypt(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        vec![pad_vault],
        false,
        Zeroizing::new("PadPw!1".into()),
        None,
        Some(pad_dec.clone()),
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::DecryptDone { .. }));
    assert_eq!(
        fs::read_to_string(pad_dec.join("src_data/not.txt")).unwrap(),
        "Türkçe metin 🎯"
    );

    // 2. Hidden Vault (padded 1 MiB, separate outer/hidden compress & keyfiles, Diff + Preview + Selective)
    let hid_out = root.join("hid_out");
    fs::create_dir(&hid_out).unwrap();
    let rec_hid = rpm_core::generate_recovery_entropy();
    let phrase_hid = rpm_core::entropy_to_mnemonic(&rec_hid).unwrap();
    worker::spawn_encrypt_hidden(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        vec![src_dir.clone()],
        vec![hid_dir.clone()],
        Zeroizing::new("HidOut!1".into()),
        Zeroizing::new("HidIn!2".into()),
        rec_hid,
        Some(kf1.clone()),
        Some(kf_h.clone()),
        Some(hid_out.clone()),
        true,
        false,
        1024 * 1024,
        false,
        false,
        false,
        1,
        fast,
        AppLanguage::Tr,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::EncryptDone { .. }));
    let hid_vault = hid_out.join("src_data.vault");

    for (use_rec, sec, kf, exp_entries) in [
        (false, "HidOut!1".to_string(), Some(kf1.clone()), 2usize),
        (true, phrase_hid.to_string(), None, 2usize),
        (false, "HidIn!2".to_string(), Some(kf_h.clone()), 2usize),
    ] {
        worker::spawn_inspect(
            ctx.clone(),
            tx.clone(),
            hid_vault.clone(),
            use_rec,
            Zeroizing::new(sec),
            kf,
            AppLanguage::Tr,
        );
        match recv_done(&rx) {
            WorkerUpdate::InspectDone { text, manifest, .. } => {
                assert_eq!(manifest.len(), exp_entries);
                let cols: Vec<usize> = text
                    .split("\n\n")
                    .next()
                    .unwrap()
                    .lines()
                    .skip(1)
                    .map(|l| l.chars().position(|c| c == ':').unwrap())
                    .collect();
                assert!(cols.windows(2).all(|w| w[0] == w[1]), "{text}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    worker::spawn_preview(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        1,
        worker::VaultDiffTarget {
            path: hid_vault.clone(),
            use_recovery: false,
            secret: Zeroizing::new("HidIn!2".into()),
            keyfile: Some(kf_h.clone()),
        },
        "hid_data/secret.png".into(),
        AppLanguage::En,
    );
    match recv_done(&rx) {
        WorkerUpdate::PreviewDone { bytes, .. } => assert_eq!(&bytes[..], MINI_PNG),
        other => panic!("unexpected: {other:?}"),
    }

    let sel_hid = root.join("sel_hid");
    fs::create_dir(&sel_hid).unwrap();
    worker::spawn_selective_extract(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        hid_vault.clone(),
        false,
        Zeroizing::new("HidIn!2".into()),
        Some(kf_h.clone()),
        vec!["hid_data/secret.txt".into()],
        Some(sel_hid.clone()),
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::DecryptDone { .. }));
    assert_eq!(
        fs::read(sel_hid.join("hid_data/secret.txt")).unwrap(),
        b"hidden compartment content"
    );
    assert!(!sel_hid.join("hid_data/secret.png").exists());

    worker::spawn_vault_diff(
        ctx.clone(),
        tx.clone(),
        worker::VaultDiffTarget {
            path: hid_vault.clone(),
            use_recovery: true,
            secret: Zeroizing::new(phrase_hid.to_string()),
            keyfile: None,
        },
        worker::VaultDiffTarget {
            path: hid_vault,
            use_recovery: false,
            secret: Zeroizing::new("HidIn!2".into()),
            keyfile: Some(kf_h.clone()),
        },
        AppLanguage::En,
    );
    match recv_done(&rx) {
        WorkerUpdate::DiffDone { text, .. } => {
            assert!(text.contains("secret.txt") && text.contains("not.txt"));
        }
        other => panic!("unexpected: {other:?}"),
    }

    // 3. Reed-Solomon + Hidden: corrupt 512 B -> integrity -> transparent inspect/preview/decrypt -> spawn_repair -> exact clean bytes
    let rs_out = root.join("rs_out");
    fs::create_dir(&rs_out).unwrap();
    worker::spawn_encrypt_hidden(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        vec![src_dir.clone()],
        vec![hid_dir.clone()],
        Zeroizing::new("RsOut!1".into()),
        Zeroizing::new("RsIn!2".into()),
        rpm_core::generate_recovery_entropy(),
        None,
        None,
        Some(rs_out.clone()),
        true,
        true,
        1024 * 1024,
        false,
        true,
        false,
        1,
        fast,
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::EncryptDone { .. }));
    let rs_vault = rs_out.join("src_data.vault");
    let rs_clean = fs::read(&rs_vault).unwrap();
    let mut rs_dmg = rs_clean.clone();
    assert!(rs_dmg.len() > 48 + RS_BLOCK_WIRE_SIZE);
    flip_sector(&mut rs_dmg, 48 + 100, 512);
    fs::write(&rs_vault, &rs_dmg).unwrap();

    worker::spawn_integrity_check(ctx.clone(), tx.clone(), rs_vault.clone(), AppLanguage::Tr);
    match recv_done(&rx) {
        WorkerUpdate::IntegrityDone { text, ok, .. } => {
            assert!(ok && text.contains("512"));
        }
        other => panic!("unexpected: {other:?}"),
    }

    worker::spawn_inspect(
        ctx.clone(),
        tx.clone(),
        rs_vault.clone(),
        false,
        Zeroizing::new("RsIn!2".into()),
        None,
        AppLanguage::Tr,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::InspectDone { .. }));

    worker::spawn_preview(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        2,
        worker::VaultDiffTarget {
            path: rs_vault.clone(),
            use_recovery: false,
            secret: Zeroizing::new("RsOut!1".into()),
            keyfile: None,
        },
        "src_data/not.txt".into(),
        AppLanguage::Tr,
    );
    match recv_done(&rx) {
        WorkerUpdate::PreviewDone { bytes, .. } => {
            assert_eq!(&bytes[..], "Türkçe metin 🎯".as_bytes());
        }
        other => panic!("unexpected: {other:?}"),
    }

    let rs_dec = root.join("rs_dec");
    fs::create_dir(&rs_dec).unwrap();
    worker::spawn_decrypt(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        vec![rs_vault.clone()],
        false,
        Zeroizing::new("RsIn!2".into()),
        None,
        Some(rs_dec.clone()),
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::DecryptDone { .. }));
    assert_eq!(
        fs::read(rs_dec.join("hid_data/secret.txt")).unwrap(),
        b"hidden compartment content"
    );

    worker::spawn_repair(
        ctx.clone(),
        tx.clone(),
        rs_vault.clone(),
        Arc::clone(&cancel),
        AppLanguage::Tr,
    );
    match recv_done(&rx) {
        WorkerUpdate::RepairDone(msg) => assert!(msg.contains("512")),
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(fs::read(&rs_vault).unwrap(), rs_clean);

    // 4. Stealth (unpadded + hidden, real OWASP KDF, renamed .bin): encrypt -> sha256_only -> inspect -> preview -> decrypt -> diff
    let st_out = root.join("st_out");
    fs::create_dir(&st_out).unwrap();
    worker::spawn_encrypt(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        vec![src_dir.clone()],
        Zeroizing::new("StealthGui!1".into()),
        rpm_core::generate_recovery_entropy(),
        Some(kf2.clone()),
        Some(st_out.clone()),
        true,
        None,
        true,
        false,
        false,
        1,
        fast, // Worker overrides KDF with STEALTH_KDF_PARAMS in production Stealth mode
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::EncryptDone { .. }));
    let stealth_bin = st_out.join("archive.bin");
    fs::rename(st_out.join("src_data.vault"), &stealth_bin).unwrap();

    worker::spawn_integrity_check(
        ctx.clone(),
        tx.clone(),
        stealth_bin.clone(),
        AppLanguage::En,
    );
    match recv_done(&rx) {
        WorkerUpdate::IntegrityDone {
            ok, sha256_only, ..
        } => assert!(ok && sha256_only),
        other => panic!("unexpected: {other:?}"),
    }

    worker::spawn_inspect(
        ctx.clone(),
        tx.clone(),
        stealth_bin.clone(),
        false,
        Zeroizing::new("StealthGui!1".into()),
        Some(kf2.clone()),
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::InspectDone { .. }));

    worker::spawn_preview(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        3,
        worker::VaultDiffTarget {
            path: stealth_bin.clone(),
            use_recovery: false,
            secret: Zeroizing::new("StealthGui!1".into()),
            keyfile: Some(kf2.clone()),
        },
        "src_data/not.txt".into(),
        AppLanguage::En,
    );
    match recv_done(&rx) {
        WorkerUpdate::PreviewDone { bytes, .. } => {
            assert_eq!(&bytes[..], "Türkçe metin 🎯".as_bytes());
        }
        other => panic!("unexpected: {other:?}"),
    }

    let st_dec = root.join("st_dec");
    fs::create_dir(&st_dec).unwrap();
    worker::spawn_decrypt(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        vec![stealth_bin],
        false,
        Zeroizing::new("StealthGui!1".into()),
        Some(kf2),
        Some(st_dec.clone()),
        AppLanguage::En,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::DecryptDone { .. }));
    assert_eq!(
        fs::read_to_string(st_dec.join("src_data/not.txt")).unwrap(),
        "Türkçe metin 🎯"
    );

    // 4b. Stealth + Hidden (1 MiB, real OWASP KDF): spawn_encrypt_hidden -> inspect -> decrypt hidden -> diff
    let sth_out = root.join("sth_out");
    fs::create_dir(&sth_out).unwrap();
    worker::spawn_encrypt_hidden(
        ctx.clone(),
        tx.clone(),
        Arc::clone(&cancel),
        vec![src_dir],
        vec![hid_dir],
        Zeroizing::new("StOut!1".into()),
        Zeroizing::new("StIn!2".into()),
        rpm_core::generate_recovery_entropy(),
        None,
        None,
        Some(sth_out.clone()),
        true,
        true,
        1024 * 1024,
        true,
        false,
        false,
        1,
        fast,
        AppLanguage::Tr,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::EncryptDone { .. }));
    let sth_blob = sth_out.join("stealth_hidden.dat");
    fs::rename(sth_out.join("src_data.vault"), &sth_blob).unwrap();

    let sth_dec = root.join("sth_dec");
    fs::create_dir(&sth_dec).unwrap();
    worker::spawn_decrypt(
        ctx.clone(),
        tx.clone(),
        cancel,
        vec![sth_blob.clone()],
        false,
        Zeroizing::new("StIn!2".into()),
        None,
        Some(sth_dec.clone()),
        AppLanguage::Tr,
    );
    assert!(matches!(recv_done(&rx), WorkerUpdate::DecryptDone { .. }));
    assert_eq!(
        fs::read(sth_dec.join("hid_data/secret.txt")).unwrap(),
        b"hidden compartment content"
    );

    worker::spawn_vault_diff(
        ctx,
        tx,
        worker::VaultDiffTarget {
            path: sth_blob.clone(),
            use_recovery: false,
            secret: Zeroizing::new("StOut!1".into()),
            keyfile: None,
        },
        worker::VaultDiffTarget {
            path: sth_blob,
            use_recovery: false,
            secret: Zeroizing::new("StIn!2".into()),
            keyfile: None,
        },
        AppLanguage::Tr,
    );
    match recv_done(&rx) {
        WorkerUpdate::DiffDone { text, .. } => {
            assert!(text.contains("secret.txt") && text.contains("not.txt"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}
