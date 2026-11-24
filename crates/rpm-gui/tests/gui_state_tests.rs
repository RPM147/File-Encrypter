use std::fs::{self, File};
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use rpm_core::constants::MIN_CHUNK_SIZE;
use rpm_core::{
    diff_metadata, inspect_header_seekable, Auth, ChangedEntry, CryptoError, FileManifestEntry,
    HiddenEncryptOptions, IntegrityReport, KdfParams, SecretKey, VaultDiff, VaultInfo,
    VaultMetadata,
};
use rpm_gui::estimator::{
    estimate_encrypt_preflight, rs_wire_size, scan_sources_sync, ContainerFitStatus,
    SourceSizeSummary,
};
use rpm_gui::progress::{
    format_bytes, format_eta, format_rate, format_transfer_summary, format_transfer_tooltip,
    TransferMeter, TransferSnapshot,
};
use rpm_gui::queue::QueuedJobKind;
use rpm_gui::reveal::reveal_command_spec;
use rpm_gui::state::{
    clamp_ui_scale_percent, strength_label_and_color_for, ui_scale_zoom_factor, AppState,
    BuiltinEncryptPreset, ContainerSizeError, ContainerSizePreset, PasswordGenFields,
    RecoveryPrompt, SessionClearReason, Tab, ARGON_ITERATIONS_RANGE, ARGON_PARALLELISM_RANGE,
    CONTAINER_MAX_MIB, CONTAINER_MIB, PWGEN_AMBIGUOUS, PWGEN_DIGITS, PWGEN_LOWERCASE,
    PWGEN_SYMBOLS, PWGEN_UPPERCASE, UI_SCALE_DEFAULT, UI_SCALE_MAX, UI_SCALE_MIN, UI_SCALE_PRESETS,
};
use rpm_gui::{fonts, i18n, load_app_icon, worker};
use rpm_storage::config::{load_config_from, AppConfig, AppLanguage, EncryptProfile, ThemeMode};
use rpm_storage::{encrypt_hidden_sources_v5, GuiLaunchIntent, LaunchTab};

fn fresh_state() -> AppState {
    AppState::from_config(AppConfig::default(), None)
}

#[test]
fn dropped_files_route_vaults_to_decrypt_and_regular_to_encrypt() {
    let mut st = fresh_state();
    st.add_dropped_paths(vec![PathBuf::from("a.txt"), PathBuf::from("folder")], None);
    assert_eq!(st.active_tab, Tab::Encrypt);
    assert_eq!(st.encrypt.sources.len(), 2);

    st.add_dropped_paths(vec![PathBuf::from("secret.vault")], None);
    assert_eq!(st.active_tab, Tab::Decrypt);
    assert_eq!(st.decrypt.vaults, vec![PathBuf::from("secret.vault")]);

    // An explicit Decrypt selection accepts an existing file with any extension.
    let dir = tempfile::tempdir().unwrap();
    let opaque = dir.path().join("archive.bin");
    fs::write(&opaque, b"opaque").unwrap();
    st.add_dropped_paths(vec![opaque.clone()], Some(Tab::Decrypt));
    assert!(st.decrypt.vaults.contains(&opaque));
    // Missing non-vault paths and directories are rejected on Decrypt.
    let missing = dir.path().join("missing.txt");
    st.add_dropped_paths(vec![missing], Some(Tab::Decrypt));
    assert!(st.is_error);
    let sub = dir.path().join("folder");
    fs::create_dir(&sub).unwrap();
    st.is_error = false;
    st.add_dropped_paths(vec![sub], Some(Tab::Decrypt));
    assert!(st.is_error);
}

#[test]
fn launch_intent_and_password_gen_and_secret_clearing() {
    let mut st = fresh_state();
    st.apply_launch_intent(GuiLaunchIntent {
        tab: Some(LaunchTab::Decrypt),
        paths: vec!["one.vault".into()],
    });
    assert_eq!(st.active_tab, Tab::Decrypt);
    assert_eq!(st.decrypt.vaults, vec![PathBuf::from("one.vault")]);

    st.generate_password();
    assert_eq!(st.pwgen.generated.len(), 24);

    st.encrypt.password = "Secret1!".into();
    st.encrypt.confirm_password = "Secret1!".into();
    st.clear_encrypt_secrets();
    assert!(st.encrypt.password.is_empty());
    assert!(st.encrypt.confirm_password.is_empty());
}

#[test]
fn app_icon_and_system_fonts_load_cleanly() {
    let icon = load_app_icon().expect("embedded icon.png decodes cleanly");
    assert!(icon.width > 0 && icon.height > 0);
    assert!(!icon.rgba.is_empty());

    let ctx = egui::Context::default();
    let report = fonts::configure_fonts(&ctx);
    #[cfg(target_os = "windows")]
    assert!(
        report.proportional_loaded,
        "expected a Windows Turkish-capable system font to load"
    );
    let _ = report;
}

#[test]
fn bilingual_tr_en_strings_and_keyboard_shortcuts_and_modals() {
    let tr = i18n::strings(AppLanguage::Tr);
    let en = i18n::strings(AppLanguage::En);
    assert_eq!(tr.tab_encrypt, "Şifrele");
    assert_eq!(tr.tab_decrypt, "Çöz");
    assert_eq!(tr.tab_settings, "Ayarlar");
    assert_eq!(en.tab_encrypt, "Encrypt");
    assert_eq!(en.tab_settings, "Settings");
    assert_ne!(tr.enc_heading, en.enc_heading);

    let mut st = fresh_state();
    for (idx, tab) in Tab::ALL.into_iter().enumerate() {
        assert!(st.handle_shortcut_tab((idx + 1) as u8));
        assert_eq!(st.active_tab, tab);
    }
    assert!(!st.handle_shortcut_tab(0));
    assert!(!st.handle_shortcut_tab(7));

    st.show_shell_install_modal = true;
    st.encrypt.recovery_prompt = Some(RecoveryPrompt {
        phrase: "word ".repeat(24),
        entropy: SecretKey::new([0x55u8; 32]),
        confirmed: false,
        queue_after_confirm: false,
    });
    assert!(st.dismiss_modals());
    assert!(!st.show_shell_install_modal);
    assert!(st.encrypt.recovery_prompt.is_none());
    assert!(!st.dismiss_modals());

    let initial_lang = st.config.language;
    st.toggle_language();
    assert_ne!(st.config.language, initial_lang);
}

#[test]
fn config_backward_compat_and_strength_meter() {
    let dir = tempfile::tempdir().unwrap();
    let old_cfg = dir.path().join("legacy_v5_cfg.json");
    fs::write(
        &old_cfg,
        br#"{"theme":"Light","wipe_passes":2,"argon_memory_kib":65536,"argon_iterations":3,"argon_parallelism":4,"compress_by_default":true}"#,
    )
    .unwrap();
    let loaded = load_config_from(&old_cfg);
    assert_eq!(loaded.theme, ThemeMode::Light);
    assert_eq!(loaded.wipe_passes, 2);
    assert_eq!(loaded.language, AppLanguage::Tr);

    let (_, empty_frac, _) = strength_label_and_color_for("", AppLanguage::Tr);
    assert_eq!(empty_frac, 0.0);

    let (weak_tr, weak_frac, _) = strength_label_and_color_for("12345", AppLanguage::Tr);
    let (strong_tr, strong_frac, _) =
        strength_label_and_color_for("K9#mP2$vL8@qR4!zX7", AppLanguage::Tr);
    let (strong_en, strong_frac_en, _) =
        strength_label_and_color_for("K9#mP2$vL8@qR4!zX7", AppLanguage::En);
    assert!(strong_frac > weak_frac);
    assert_eq!(strong_frac, strong_frac_en);
    assert_ne!(weak_tr, strong_tr);
    assert_ne!(strong_tr, strong_en);
}

#[test]
fn inspect_manifest_selection_filtering_and_vault_change_reset() {
    let mut st = fresh_state();
    let entries = vec![
        FileManifestEntry {
            path: "docs/rapor.pdf".into(),
            size: 1024,
            modified_unix: 0,
        },
        FileManifestEntry {
            path: "docs/notlar.txt".into(),
            size: 256,
            modified_unix: 0,
        },
        FileManifestEntry {
            path: "images/foto.png".into(),
            size: 2048,
            modified_unix: 0,
        },
    ];
    let fake_dir = PathBuf::from("tmp_vault_dir");
    let fake_vault = fake_dir.join("arsiv.vault");
    st.inspect.set_manifest(fake_vault, entries);
    assert_eq!(st.inspect.manifest.len(), 3);
    assert_eq!(
        st.inspect.extract_output_dir,
        fake_dir.display().to_string()
    );

    st.inspect.filter_query = "docs".into();
    assert_eq!(st.inspect.filtered_indices(), vec![0, 1]);
    st.inspect.select_all_filtered();
    assert_eq!(st.inspect.selected_paths.len(), 2);
    assert!(st.inspect.selected_paths.contains("docs/rapor.pdf"));
    assert!(st.inspect.selected_paths.contains("docs/notlar.txt"));

    st.inspect.clear_selection();
    assert!(st.inspect.selected_paths.is_empty());

    // Dropping another vault on Inspect clears previous manifest cleanly
    st.add_dropped_paths(vec![PathBuf::from("other.vault")], Some(Tab::Inspect));
    assert!(st.inspect.manifest.is_empty());
    assert!(st.inspect.manifest_vault.is_none());
}

#[test]
fn worker_reports_format_cleanly_in_tr_and_en() {
    let rep = IntegrityReport {
        has_reed_solomon: true,
        rs_repaired_bytes: 13,
        sha256_only: false,
        ok: true,
        version: 5,
        file_size: 4096,
        sha256_hex: "0".repeat(64),
        message: "ok".into(),
        has_keyfile: true,
        has_recovery: false,
        chunk_count: 2,
    };
    let rep_tr = worker::format_integrity_report(&rep, AppLanguage::Tr);
    let rep_en = worker::format_integrity_report(&rep, AppLanguage::En);
    assert!(rep_tr.contains("BÜTÜNLÜK KONTROLÜ"));
    assert!(rep_tr.contains("Evet") && rep_tr.contains("Hayır"));
    assert!(rep_en.contains("INTEGRITY CHECK"));
    assert!(rep_en.contains("Yes") && rep_en.contains("No"));

    for (lang, report) in [(AppLanguage::Tr, &rep_tr), (AppLanguage::En, &rep_en)] {
        assert!(report
            .lines()
            .any(|l| l.starts_with(i18n::strings(lang).rs_bytes) && l.ends_with(": 13")));
        let cols: Vec<usize> = report
            .split("\n\n")
            .next()
            .unwrap()
            .lines()
            .skip(1)
            .map(|l| l.chars().position(|c| c == ':').unwrap())
            .collect();
        assert!(cols.windows(2).all(|w| w[0] == w[1]), "{report}");
    }
    let mut non_rs_rep = rep.clone();
    non_rs_rep.has_reed_solomon = false;
    non_rs_rep.rs_repaired_bytes = 0;
    for lang in [AppLanguage::Tr, AppLanguage::En] {
        let non_rs_txt = worker::format_integrity_report(&non_rs_rep, lang);
        assert!(!non_rs_txt.contains(i18n::strings(lang).rs_bytes));
    }
    let info = VaultInfo {
        has_reed_solomon: true,
        rs_repaired_bytes: 17,
        is_stealth: false,
        version: 5,
        vault_id: "0123456789abcdef".into(),
        cipher: "AES-256-GCM-CHUNKED".into(),
        chunk_size: 1024 * 1024,
        has_recovery: true,
        has_keyfile: false,
        compressed: true,
        argon_memory_kib: 65_536,
        argon_iterations: 3,
        argon_parallelism: 4,
        container_size: None,
        is_hidden_compartment: false,
        metadata: VaultMetadata {
            filename: "belgeler".into(),
            source_type: "folder".into(),
            original_size: 2048,
            file_count: 1,
            created_at: "2026-11-20T00:00:00Z".into(),
            compressed: true,
            files: vec![FileManifestEntry {
                path: "belgeler/not.txt".into(),
                size: 2048,
                modified_unix: 0,
            }],
        },
    };
    for lang in [AppLanguage::Tr, AppLanguage::En] {
        let txt = worker::format_inspect_report(&info, lang);
        assert!(txt
            .lines()
            .any(|l| l.starts_with(i18n::strings(lang).rs_seen) && l.ends_with(": 17")));
        let cols: Vec<usize> = txt
            .split("\n\n")
            .next()
            .unwrap()
            .lines()
            .skip(1)
            .map(|l| l.chars().position(|c| c == ':').unwrap())
            .collect();
        assert!(cols.windows(2).all(|w| w[0] == w[1]), "{txt}");
    }
    let mut non_rs_info = info.clone();
    non_rs_info.has_reed_solomon = false;
    non_rs_info.rs_repaired_bytes = 0;
    for lang in [AppLanguage::Tr, AppLanguage::En] {
        let non_rs_txt = worker::format_inspect_report(&non_rs_info, lang);
        assert!(!non_rs_txt.contains(i18n::strings(lang).rs_seen));
    }
    let ins_tr = worker::format_inspect_report(&info, AppLanguage::Tr);
    let ins_en = worker::format_inspect_report(&info, AppLanguage::En);
    assert!(ins_tr.contains("KASA META VERİSİ"));
    assert!(ins_tr.contains("Evet") && ins_tr.contains("Hayır"));
    assert!(ins_en.contains("VAULT METADATA"));
    assert!(ins_en.contains("Yes") && ins_en.contains("No"));
}

#[test]
fn transfer_meter_and_bilingual_formatting_handle_edge_cases() {
    let t0 = Instant::now();
    let total = 10 * 1024 * 1024;

    // 1. Sub-50ms initial buffer suppresses artificial spike; second sample initializes rate
    let mut quick = TransferMeter::new(t0);
    let s1 = quick.update_at(t0 + Duration::from_millis(10), 1024 * 1024, total);
    assert!(s1.bytes_per_sec.is_none());
    assert!(s1.eta.is_none());
    assert!(format_transfer_summary(&s1, AppLanguage::Tr).is_none());

    let s2 = quick.update_at(t0 + Duration::from_millis(260), 2 * 1024 * 1024, total);
    let bps2 = s2
        .bytes_per_sec
        .expect("rate initialized after second sample");
    assert!(bps2 > 3_500_000.0 && bps2 < 4_500_000.0, "bps2={bps2}");
    assert!(s2.eta.is_some());

    // 2. EMA smoothing across multi-second ticks + clamping when done > total
    let mut meter = TransferMeter::with_item(t0, 2, 4);
    let a = meter.update_at(t0 + Duration::from_secs(1), 1024 * 1024, total);
    assert!((a.fraction - 0.1).abs() < 1e-4);
    let bps_a = a.bytes_per_sec.unwrap();
    assert!((bps_a - 1_048_576.0).abs() < 1024.0);
    assert_eq!(a.eta, Some(Duration::from_secs(9)));

    // Jump +2 MiB in 1s -> smoothed = 0.65 * 1 MiB/s + 0.35 * 2 MiB/s = 1.35 MiB/s
    let b = meter.update_at(t0 + Duration::from_secs(2), 3 * 1024 * 1024, total);
    let bps_b = b.bytes_per_sec.unwrap();
    assert!((bps_b - 1.35 * 1_048_576.0).abs() < 4096.0, "bps_b={bps_b}");
    let tr_sum = format_transfer_summary(&b, AppLanguage::Tr).unwrap();
    let en_sum = format_transfer_summary(&b, AppLanguage::En).unwrap();
    assert!(tr_sum.starts_with("[2/4] ") && tr_sum.contains("MiB/s") && tr_sum.contains("Kalan:"));
    assert!(en_sum.starts_with("[2/4] ") && en_sum.contains("MiB/s") && en_sum.contains("ETA"));

    // done > total clamps cleanly without underflow or overflow
    let done_snap = meter.update_at(t0 + Duration::from_secs(5), total + 4096, total);
    assert_eq!(done_snap.fraction, 1.0);
    assert_eq!(done_snap.bytes_done, total);
    assert_eq!(done_snap.eta, Some(Duration::ZERO));

    // total == 0 does not divide by zero
    let mut zero_meter = TransferMeter::new(t0);
    let z = zero_meter.update_at(t0 + Duration::from_millis(100), 512, 0);
    assert_eq!(z.fraction, 1.0);
    assert_eq!(z.eta, None);

    // 3. Unit & duration formatters
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1536), "1.5 KiB");
    assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 GiB");
    assert_eq!(format_rate(f64::NAN), "0 B/s");
    assert_eq!(format_rate(-10.0), "0 B/s");
    assert_eq!(
        format_eta(Duration::from_secs(45), AppLanguage::Tr),
        "45 sn"
    );
    assert_eq!(format_eta(Duration::from_secs(45), AppLanguage::En), "45s");
    assert_eq!(
        format_eta(Duration::from_secs(125), AppLanguage::Tr),
        "2 dk 05 sn"
    );
    assert_eq!(
        format_eta(Duration::from_secs(3665), AppLanguage::En),
        "1h 01m"
    );

    let tip = format_transfer_tooltip(&b, AppLanguage::En);
    assert!(tip.contains("3.0 MiB / 10.0 MiB"));
    assert!(tip.contains("MiB/s"));

    // 4. AppState::begin_transfer clears stale snapshot
    let mut st = fresh_state();
    st.transfer = Some(TransferSnapshot {
        fraction: 0.5,
        bytes_done: 100,
        bytes_total: 200,
        bytes_per_sec: Some(1024.0),
        eta: Some(Duration::from_secs(1)),
        item_index: None,
    });
    st.begin_transfer("Starting");
    assert!(st.busy);
    assert_eq!(st.progress, 0.0);
    assert!(st.transfer.is_none());
    assert_eq!(st.status, "Starting");
}

#[test]
fn password_generator_character_classes_ambiguous_exclusion_and_guard() {
    // 1. Defaults preserve existing behavior (all 4 classes enabled, ambiguous excluded)
    let def = PasswordGenFields::default();
    assert_eq!(def.length, 24);
    assert!(def.include_uppercase);
    assert!(def.include_lowercase);
    assert!(def.include_digits);
    assert!(def.include_symbols);
    assert!(def.exclude_ambiguous);
    assert_eq!(def.enabled_class_count(), 4);
    assert!(def.has_any_class());

    let default_alpha = def.build_alphabet();
    // 25 lowercase + 24 uppercase + 8 digits + 18 symbols = 75 unique bytes
    assert_eq!(default_alpha.len(), 75);
    for &amb in PWGEN_AMBIGUOUS {
        assert!(
            !default_alpha.contains(&amb),
            "default alphabet must exclude ambiguous char {}",
            amb as char
        );
    }

    // Including ambiguous chars adds all 5 back (0, O, 1, l, I) -> 80 bytes
    let mut with_amb = PasswordGenFields::default();
    with_amb.exclude_ambiguous = false;
    let full_alpha = with_amb.build_alphabet();
    assert_eq!(full_alpha.len(), 80);
    for &amb in PWGEN_AMBIGUOUS {
        assert!(
            full_alpha.contains(&amb),
            "full alphabet must include ambiguous char {}",
            amb as char
        );
    }

    // 2. Single-class combinations (with & without ambiguous exclusion)
    let mut st = fresh_state();
    st.pwgen.length = 64;

    // Uppercase only, exclude ambiguous
    st.pwgen.include_uppercase = true;
    st.pwgen.include_lowercase = false;
    st.pwgen.include_digits = false;
    st.pwgen.include_symbols = false;
    st.pwgen.exclude_ambiguous = true;
    assert_eq!(st.pwgen.enabled_class_count(), 1);
    assert_eq!(st.pwgen.build_alphabet().len(), 24);
    st.generate_password();
    assert!(!st.is_error);
    assert_eq!(st.pwgen.generated.len(), 64);
    assert!(st
        .pwgen
        .generated
        .bytes()
        .all(|b| { PWGEN_UPPERCASE.contains(&b) && !PWGEN_AMBIGUOUS.contains(&b) }));

    // Lowercase only, include ambiguous
    st.pwgen.include_uppercase = false;
    st.pwgen.include_lowercase = true;
    st.pwgen.exclude_ambiguous = false;
    assert_eq!(st.pwgen.build_alphabet().len(), 26);
    st.generate_password();
    assert!(!st.is_error);
    assert!(st
        .pwgen
        .generated
        .bytes()
        .all(|b| PWGEN_LOWERCASE.contains(&b)));

    // Digits only, exclude ambiguous -> only '2'..='9'
    st.pwgen.include_lowercase = false;
    st.pwgen.include_digits = true;
    st.pwgen.exclude_ambiguous = true;
    assert_eq!(st.pwgen.build_alphabet(), b"23456789");
    st.generate_password();
    assert!(!st.is_error);
    assert!(st
        .pwgen
        .generated
        .bytes()
        .all(|b| { PWGEN_DIGITS.contains(&b) && !PWGEN_AMBIGUOUS.contains(&b) }));

    // Symbols only (ambiguous exclusion does not empty symbols)
    st.pwgen.include_digits = false;
    st.pwgen.include_symbols = true;
    st.pwgen.exclude_ambiguous = true;
    assert_eq!(st.pwgen.build_alphabet(), PWGEN_SYMBOLS);
    st.generate_password();
    assert!(!st.is_error);
    assert!(st
        .pwgen
        .generated
        .bytes()
        .all(|b| PWGEN_SYMBOLS.contains(&b)));

    // Mixed subset: uppercase + digits, no lowercase/symbols
    st.pwgen.include_uppercase = true;
    st.pwgen.include_digits = true;
    st.pwgen.include_symbols = false;
    st.pwgen.exclude_ambiguous = false;
    assert_eq!(st.pwgen.enabled_class_count(), 2);
    assert_eq!(st.pwgen.build_alphabet().len(), 36);
    st.generate_password();
    assert!(!st.is_error);
    assert!(st
        .pwgen
        .generated
        .bytes()
        .all(|b| { PWGEN_UPPERCASE.contains(&b) || PWGEN_DIGITS.contains(&b) }));

    // Length clamping: below 12 clamps to 12, above 64 clamps to 64
    st.pwgen.length = 4;
    st.generate_password();
    assert_eq!(st.pwgen.generated.len(), 12);
    st.pwgen.length = 200;
    st.generate_password();
    assert_eq!(st.pwgen.generated.len(), 64);

    // Non-determinism via OsRng
    let first = st.pwgen.generated.clone();
    st.generate_password();
    assert_ne!(first, st.pwgen.generated);

    // 3. All-disabled guard: non-panicking, clears previous secret, sets localized error
    st.pwgen.include_uppercase = false;
    st.pwgen.include_lowercase = false;
    st.pwgen.include_digits = false;
    st.pwgen.include_symbols = false;
    assert_eq!(st.pwgen.enabled_class_count(), 0);
    assert!(!st.pwgen.has_any_class());
    assert!(st.pwgen.build_alphabet().is_empty());

    st.config.language = AppLanguage::Tr;
    st.pwgen.generated = "stale-secret".into();
    st.generate_password();
    assert!(st.is_error);
    assert!(st.pwgen.generated.is_empty());
    assert_eq!(st.status, i18n::TR.err_pw_no_class);

    st.config.language = AppLanguage::En;
    st.pwgen.generated = "stale-secret".into();
    st.generate_password();
    assert!(st.is_error);
    assert!(st.pwgen.generated.is_empty());
    assert_eq!(st.status, i18n::EN.err_pw_no_class);

    // Re-enabling a class recovers cleanly
    st.pwgen.include_lowercase = true;
    st.pwgen.length = 20;
    st.generate_password();
    assert!(!st.is_error);
    assert_eq!(st.pwgen.generated.len(), 20);
    assert_eq!(st.status, i18n::EN.status_pw_generated);
}

#[test]
fn argon2id_settings_validation_and_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("prefs.json");

    let mut st = AppState::from_config(AppConfig::default(), Some(cfg_path.clone()));
    st.config.language = AppLanguage::En;

    // Every UI slider endpoint for iterations (1..=10) & parallelism (1..=16) is valid
    assert_eq!(ARGON_ITERATIONS_RANGE, 1..=10);
    assert_eq!(ARGON_PARALLELISM_RANGE, 1..=16);
    for mem in [16_384, 65_536, 131_072, 262_144] {
        for iters in [
            *ARGON_ITERATIONS_RANGE.start(),
            *ARGON_ITERATIONS_RANGE.end(),
        ] {
            for par in [
                *ARGON_PARALLELISM_RANGE.start(),
                *ARGON_PARALLELISM_RANGE.end(),
            ] {
                let kdf = st
                    .set_argon_params(mem, iters, par)
                    .expect("UI Argon2id range must satisfy KdfParams::validate");
                assert_eq!(kdf.memory_kib, mem);
                assert_eq!(kdf.iterations, iters);
                assert_eq!(kdf.parallelism, par);
                assert!(st.validate_kdf_params().is_ok());
            }
        }
    }

    // Valid params save and reload cleanly
    st.set_argon_params(131_072, 5, 8).unwrap();
    assert!(st.save_preferences().is_ok());
    assert!(!st.is_error);
    assert_eq!(st.status, i18n::EN.status_prefs_saved);
    let reloaded = load_config_from(&cfg_path);
    assert_eq!(reloaded.argon_memory_kib, 131_072);
    assert_eq!(reloaded.argon_iterations, 5);
    assert_eq!(reloaded.argon_parallelism, 8);

    // Invalid params are rejected by set_argon_params without mutating existing config
    assert!(st.set_argon_params(65_536, 0, 4).is_err());
    assert!(st.set_argon_params(65_536, 65, 4).is_err());
    assert!(st.set_argon_params(65_536, 3, 0).is_err());
    assert!(st.set_argon_params(65_536, 3, 65).is_err());
    assert!(st.set_argon_params(1024, 3, 4).is_err());
    assert_eq!(st.config.argon_memory_kib, 131_072);
    assert_eq!(st.config.argon_iterations, 5);
    assert_eq!(st.config.argon_parallelism, 8);

    // Direct invalid mutation blocks both save_preferences and persist_config_best_effort
    let bad_path = dir.path().join("should_not_exist.json");
    st.config_path = Some(bad_path.clone());
    st.config.argon_iterations = 0;
    assert!(st.validate_kdf_params().is_err());
    st.persist_config_best_effort();
    assert!(!bad_path.exists());

    let err_en = st.save_preferences().unwrap_err();
    assert!(st.is_error);
    assert!(err_en.starts_with(i18n::EN.err_invalid_kdf));
    assert!(!bad_path.exists());

    st.config.language = AppLanguage::Tr;
    st.config.argon_iterations = 3;
    st.config.argon_parallelism = 0;
    let err_tr = st.save_preferences().unwrap_err();
    assert!(st.is_error);
    assert!(err_tr.starts_with(i18n::TR.err_invalid_kdf));
    assert!(!bad_path.exists());
}

#[test]
fn ui_scale_clamping_zoom_factor_and_context_application() {
    assert_eq!(UI_SCALE_PRESETS, [80, 90, 100, 110, 120, 130, 150]);
    assert_eq!(UI_SCALE_MIN, 80);
    assert_eq!(UI_SCALE_MAX, 150);
    assert_eq!(UI_SCALE_DEFAULT, 100);

    // Clamping bounds (80..=150 matching AppConfig)
    assert_eq!(clamp_ui_scale_percent(0), 80);
    assert_eq!(clamp_ui_scale_percent(50), 80);
    assert_eq!(clamp_ui_scale_percent(79), 80);
    assert_eq!(clamp_ui_scale_percent(80), 80);
    assert_eq!(clamp_ui_scale_percent(100), 100);
    assert_eq!(clamp_ui_scale_percent(125), 125);
    assert_eq!(clamp_ui_scale_percent(150), 150);
    assert_eq!(clamp_ui_scale_percent(151), 150);
    assert_eq!(clamp_ui_scale_percent(300), 150);
    assert_eq!(clamp_ui_scale_percent(u16::MAX), 150);

    // Zoom factor conversion across presets, custom in-range, and out-of-range values
    for (pct, expected) in [
        (50, 0.8_f32),
        (80, 0.8_f32),
        (90, 0.9_f32),
        (100, 1.0_f32),
        (110, 1.1_f32),
        (120, 1.2_f32),
        (125, 1.25_f32),
        (130, 1.3_f32),
        (150, 1.5_f32),
        (250, 1.5_f32),
    ] {
        assert!(
            (ui_scale_zoom_factor(pct) - expected).abs() < 1e-6,
            "pct={pct}"
        );
    }

    // AppState config binding and egui::Context integration
    let mut st = fresh_state();
    st.config.ui_scale_percent = UI_SCALE_DEFAULT;
    assert_eq!(st.config.ui_scale_percent, 100);
    assert!((st.ui_scale_zoom_factor() - 1.0).abs() < 1e-6);

    let ctx = egui::Context::default();
    let flush_zoom = |ctx: &egui::Context| -> f32 {
        ctx.begin_pass(egui::RawInput::default());
        let mut output = ctx.end_pass();
        output.textures_delta.clear();
        ctx.zoom_factor()
    };

    st.set_ui_scale_percent(130, &ctx);
    assert_eq!(st.config.ui_scale_percent, 130);
    assert!((flush_zoom(&ctx) - 1.3).abs() < 1e-6);

    st.set_ui_scale_percent(40, &ctx);
    assert_eq!(st.config.ui_scale_percent, 80);
    assert!((flush_zoom(&ctx) - 0.8).abs() < 1e-6);

    st.set_ui_scale_percent(250, &ctx);
    assert_eq!(st.config.ui_scale_percent, 150);
    assert!((flush_zoom(&ctx) - 1.5).abs() < 1e-6);

    // Direct field mutation still clamps safely in apply_ui_scale
    st.config.ui_scale_percent = 999;
    st.apply_ui_scale(&ctx);
    assert!((flush_zoom(&ctx) - 1.5).abs() < 1e-6);

    // Persistent round-trip via save_preferences -> load_config_from
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("ui_scale_prefs.json");
    st.config_path = Some(cfg_path.clone());
    st.set_ui_scale_percent(125, &ctx);
    assert!(st.save_preferences().is_ok());
    let reloaded = load_config_from(&cfg_path);
    assert_eq!(reloaded.ui_scale_percent, 125);

    // Out-of-range direct mutation is clamped before writing to disk
    st.config.ui_scale_percent = 300;
    assert!(st.save_preferences().is_ok());
    assert_eq!(st.config.ui_scale_percent, 150);
    assert_eq!(load_config_from(&cfg_path).ui_scale_percent, 150);

    st.config.ui_scale_percent = 20;
    st.persist_config_best_effort();
    assert_eq!(load_config_from(&cfg_path).ui_scale_percent, 80);
}

#[test]
fn vault_diff_report_formatting_and_secret_clearing() {
    let diff = VaultDiff {
        added: vec![FileManifestEntry {
            path: "docs/new.txt".into(),
            size: 512,
            modified_unix: 1_700_000_100,
        }],
        removed: vec![FileManifestEntry {
            path: "docs/old.txt".into(),
            size: 128,
            modified_unix: 1_700_000_000,
        }],
        changed: vec![
            ChangedEntry {
                before: FileManifestEntry {
                    path: "notes.md".into(),
                    size: 100,
                    modified_unix: 1_000,
                },
                after: FileManifestEntry {
                    path: "notes.md".into(),
                    size: 150,
                    modified_unix: 1_060,
                },
            },
            ChangedEntry {
                before: FileManifestEntry {
                    path: "shrink.bin".into(),
                    size: 300,
                    modified_unix: 2_000,
                },
                after: FileManifestEntry {
                    path: "shrink.bin".into(),
                    size: 200,
                    modified_unix: 1_950,
                },
            },
        ],
        unchanged: vec![FileManifestEntry {
            path: "same.txt".into(),
            size: 64,
            modified_unix: 500,
        }],
    };

    let tr_report = worker::format_diff_report(&diff, AppLanguage::Tr);
    assert!(tr_report.contains("KASA KARŞILAŞTIRMA"));
    assert!(tr_report.contains("+1 eklenen, -1 silinen, ~2 değişen, =1 değişmeyen"));
    assert!(tr_report.contains("EKLENEN (1):"));
    assert!(tr_report.contains("docs/new.txt (512 bayt)"));
    assert!(tr_report.contains("SİLİNEN (1):"));
    assert!(tr_report.contains("docs/old.txt (128 bayt)"));
    assert!(tr_report.contains("DEĞİŞEN (2):"));
    assert!(
        tr_report.contains("notes.md (boyut: 100 -> 150 bayt [+50], mtime: 1000 -> 1060 [+60 sn])")
    );
    assert!(tr_report
        .contains("shrink.bin (boyut: 300 -> 200 bayt [-100], mtime: 2000 -> 1950 [-50 sn])"));
    assert!(tr_report.contains("DEĞİŞMEYEN (1):"));
    assert!(tr_report.contains("same.txt (64 bayt)"));

    let en_report = worker::format_diff_report(&diff, AppLanguage::En);
    assert!(en_report.contains("VAULT DIFF"));
    assert!(en_report.contains("+1 added, -1 removed, ~2 changed, =1 unchanged"));
    assert!(en_report.contains("ADDED (1):"));
    assert!(en_report.contains("docs/new.txt (512 bytes)"));
    assert!(en_report.contains("REMOVED (1):"));
    assert!(en_report.contains("docs/old.txt (128 bytes)"));
    assert!(en_report.contains("CHANGED (2):"));
    assert!(
        en_report.contains("notes.md (size: 100 -> 150 bytes [+50], mtime: 1000 -> 1060 [+60s])")
    );
    assert!(en_report
        .contains("shrink.bin (size: 300 -> 200 bytes [-100], mtime: 2000 -> 1950 [-50s])"));
    assert!(en_report.contains("UNCHANGED (1):"));
    assert!(en_report.contains("same.txt (64 bytes)"));

    // Identical vaults message in both languages
    let identical = VaultDiff {
        unchanged: vec![FileManifestEntry {
            path: "only.txt".into(),
            size: 10,
            modified_unix: 10,
        }],
        ..Default::default()
    };
    let id_tr = worker::format_diff_report(&identical, AppLanguage::Tr);
    let id_en = worker::format_diff_report(&identical, AppLanguage::En);
    assert!(id_tr.contains("Fark bulunamadı"));
    assert!(id_tr.contains("DEĞİŞMEYEN (1):"));
    assert!(id_en.contains("No differences found"));
    assert!(id_en.contains("UNCHANGED (1):"));

    // Long list truncation (> 150 entries)
    let many_added = VaultDiff {
        added: (0..155)
            .map(|i| FileManifestEntry {
                path: format!("file_{i:03}.dat"),
                size: i as u64,
                modified_unix: 0,
            })
            .collect(),
        ..Default::default()
    };
    assert!(
        worker::format_diff_report(&many_added, AppLanguage::Tr).contains("... ve 5 girdi daha")
    );
    assert!(worker::format_diff_report(&many_added, AppLanguage::En).contains("... and 5 more"));

    // clear_diff_secrets wipes all 4 secret fields cleanly
    let mut st = fresh_state();
    st.diff.password_a = "SecretA!".into();
    st.diff.recovery_phrase_a = "alpha beta gamma".into();
    st.diff.password_b = "SecretB!".into();
    st.diff.recovery_phrase_b = "delta epsilon zeta".into();
    st.clear_diff_secrets();
    assert!(st.diff.password_a.is_empty());
    assert!(st.diff.recovery_phrase_a.is_empty());
    assert!(st.diff.password_b.is_empty());
    assert!(st.diff.recovery_phrase_b.is_empty());
}

#[test]
fn phase2_settings_and_password_gen_bilingual_strings_parity() {
    let tr = i18n::strings(AppLanguage::Tr);
    let en = i18n::strings(AppLanguage::En);

    let pairs = [
        (tr.chk_uppercase, en.chk_uppercase),
        (tr.chk_lowercase, en.chk_lowercase),
        (tr.chk_digits, en.chk_digits),
        (tr.chk_symbols, en.chk_symbols),
        (tr.chk_exclude_ambiguous, en.chk_exclude_ambiguous),
        (tr.err_pw_no_class, en.err_pw_no_class),
        (tr.lbl_ui_scale, en.lbl_ui_scale),
        (tr.lbl_argon_iterations, en.lbl_argon_iterations),
        (tr.lbl_argon_parallelism, en.lbl_argon_parallelism),
        (tr.err_invalid_kdf, en.err_invalid_kdf),
        (tr.err_save_prefs, en.err_save_prefs),
        (tr.diff_heading, en.diff_heading),
        (tr.diff_subtitle, en.diff_subtitle),
        (tr.lbl_vault_a, en.lbl_vault_a),
        (tr.lbl_vault_b, en.lbl_vault_b),
        (tr.btn_compare_vaults, en.btn_compare_vaults),
        (tr.diff_default_results, en.diff_default_results),
        (tr.err_diff_select_vaults, en.err_diff_select_vaults),
        (tr.err_diff_enter_creds, en.err_diff_enter_creds),
        (tr.status_comparing_vaults, en.status_comparing_vaults),
    ];

    for (t, e) in pairs {
        assert!(!t.trim().is_empty(), "TR string must be non-empty");
        assert!(!e.trim().is_empty(), "EN string must be non-empty");
        assert_ne!(t, e, "TR and EN strings should be localized distinctly");
    }

    assert!(tr.chk_exclude_ambiguous.contains("0, O, 1, l, I"));
    assert!(en.chk_exclude_ambiguous.contains("0, O, 1, l, I"));
    assert!(tr.lbl_argon_iterations.contains("Argon2id"));
    assert!(en.lbl_argon_iterations.contains("Argon2id"));
    assert!(tr.lbl_argon_parallelism.contains("Argon2id"));
    assert!(en.lbl_argon_parallelism.contains("Argon2id"));
}

#[test]
fn container_size_preset_resolution_and_hidden_validation() {
    assert_eq!(ContainerSizePreset::Auto.resolve_bytes(""), Ok(None));
    assert_eq!(
        ContainerSizePreset::MiB10.resolve_bytes(""),
        Ok(Some(10 * CONTAINER_MIB))
    );
    assert_eq!(
        ContainerSizePreset::MiB50.resolve_bytes(""),
        Ok(Some(50 * CONTAINER_MIB))
    );
    assert_eq!(
        ContainerSizePreset::MiB100.resolve_bytes(""),
        Ok(Some(100 * CONTAINER_MIB))
    );
    assert_eq!(
        ContainerSizePreset::MiB500.resolve_bytes(""),
        Ok(Some(500 * CONTAINER_MIB))
    );

    // Custom valid bounds (whitespace trimmed)
    assert_eq!(
        ContainerSizePreset::Custom.resolve_bytes(" 1 "),
        Ok(Some(CONTAINER_MIB))
    );
    assert_eq!(
        ContainerSizePreset::Custom.resolve_bytes("256"),
        Ok(Some(256 * CONTAINER_MIB))
    );
    assert_eq!(
        ContainerSizePreset::Custom.resolve_bytes(&CONTAINER_MAX_MIB.to_string()),
        Ok(Some(CONTAINER_MAX_MIB * CONTAINER_MIB))
    );

    // Custom invalid / zero / out-of-range
    assert_eq!(
        ContainerSizePreset::Custom.resolve_bytes("0"),
        Err(ContainerSizeError::InvalidCustomValue)
    );
    assert_eq!(
        ContainerSizePreset::Custom.resolve_bytes("-5"),
        Err(ContainerSizeError::InvalidCustomValue)
    );
    assert_eq!(
        ContainerSizePreset::Custom.resolve_bytes("abc"),
        Err(ContainerSizeError::InvalidCustomValue)
    );
    assert_eq!(
        ContainerSizePreset::Custom.resolve_bytes(""),
        Err(ContainerSizeError::InvalidCustomValue)
    );
    assert_eq!(
        ContainerSizePreset::Custom.resolve_bytes(&(CONTAINER_MAX_MIB + 1).to_string()),
        Err(ContainerSizeError::OutOfRange)
    );
    assert_eq!(
        ContainerSizePreset::Custom.resolve_bytes(&u64::MAX.to_string()),
        Err(ContainerSizeError::OutOfRange)
    );

    // Hidden mode auto-switches preset away from Auto and requires fixed container size
    let mut st = fresh_state();
    assert_eq!(st.encrypt.container_preset, ContainerSizePreset::Auto);
    assert_eq!(st.encrypt.resolve_container_size(), Ok(None));

    st.encrypt.set_hidden_enabled(true);
    assert!(st.encrypt.enable_hidden);
    assert_eq!(st.encrypt.container_preset, ContainerSizePreset::MiB50);
    assert_eq!(
        st.encrypt.resolve_container_size(),
        Ok(Some(50 * CONTAINER_MIB))
    );

    // Even if forced back to Auto, resolve_container_size rejects hidden without container size
    st.encrypt.container_preset = ContainerSizePreset::Auto;
    assert_eq!(
        st.encrypt.resolve_container_size(),
        Err(ContainerSizeError::RequiredForHidden)
    );

    // Hidden source deduplication
    assert_eq!(
        st.encrypt.add_hidden_sources(vec![
            PathBuf::from("secret.txt"),
            PathBuf::from("secret.txt")
        ]),
        1
    );
    assert_eq!(st.encrypt.hidden_sources, vec![PathBuf::from("secret.txt")]);
}

#[test]
fn clear_encrypt_secrets_wipes_outer_and_hidden_passwords() {
    let mut st = fresh_state();
    st.encrypt.password = "OuterSecret!1".into();
    st.encrypt.confirm_password = "OuterSecret!1".into();
    st.encrypt.hidden_password = "HiddenSecret!2".into();
    st.encrypt.hidden_confirm_password = "HiddenSecret!2".into();
    st.encrypt.recovery_prompt = Some(RecoveryPrompt {
        phrase: "alpha beta gamma".into(),
        entropy: SecretKey::new([0x33u8; 32]),
        confirmed: true,
        queue_after_confirm: false,
    });

    st.clear_encrypt_secrets();
    assert!(st.encrypt.password.is_empty());
    assert!(st.encrypt.confirm_password.is_empty());
    assert!(st.encrypt.hidden_password.is_empty());
    assert!(st.encrypt.hidden_confirm_password.is_empty());
    assert!(st.encrypt.recovery_prompt.is_none());
}

#[test]
fn format_inspect_report_shows_container_size_and_hidden_compartment() {
    let info = VaultInfo {
        has_reed_solomon: true,
        rs_repaired_bytes: 17,
        is_stealth: false,
        version: 5,
        vault_id: "0123456789abcdef".into(),
        cipher: "AES-256-GCM-CHUNKED".into(),
        chunk_size: 1024 * 1024,
        has_recovery: false,
        has_keyfile: true,
        compressed: true,
        argon_memory_kib: 65_536,
        argon_iterations: 3,
        argon_parallelism: 4,
        container_size: Some(50 * 1024 * 1024),
        is_hidden_compartment: true,
        metadata: VaultMetadata {
            filename: "secret".into(),
            source_type: "folder".into(),
            original_size: 1024,
            file_count: 1,
            created_at: "2026-11-21T00:00:00Z".into(),
            compressed: true,
            files: vec![],
        },
    };

    let tr = worker::format_inspect_report(&info, AppLanguage::Tr);
    assert!(tr.contains("Konteyner Boyutu: 52428800 bayt (50.00 MiB)"));
    assert!(tr.contains("Bölme           : Gizli Kasa"));

    let en = worker::format_inspect_report(&info, AppLanguage::En);
    assert!(en.contains("Container Size : 52428800 bytes (50.00 MiB)"));
    assert!(en.contains("Compartment    : Hidden Vault"));
}

#[test]
fn phase3_container_and_hidden_bilingual_strings_parity() {
    let tr = i18n::strings(AppLanguage::Tr);
    let en = i18n::strings(AppLanguage::En);

    let pairs = [
        (tr.lbl_container_size, en.lbl_container_size),
        (tr.container_auto, en.container_auto),
        (tr.container_custom, en.container_custom),
        (tr.hint_container_padding, en.hint_container_padding),
        (tr.hidden_section_title, en.hidden_section_title),
        (tr.chk_enable_hidden, en.chk_enable_hidden),
        (tr.hidden_section_hint, en.hidden_section_hint),
        (tr.hidden_sources_hint, en.hidden_sources_hint),
        (tr.hidden_no_sources, en.hidden_no_sources),
        (tr.lbl_hidden_password, en.lbl_hidden_password),
        (tr.lbl_hidden_confirm, en.lbl_hidden_confirm),
        (tr.lbl_hidden_keyfile_opt, en.lbl_hidden_keyfile_opt),
        (tr.chk_hidden_compress, en.chk_hidden_compress),
        (tr.hidden_recovery_note, en.hidden_recovery_note),
        (tr.err_container_invalid_mb, en.err_container_invalid_mb),
        (tr.err_container_out_of_range, en.err_container_out_of_range),
        (
            tr.err_hidden_requires_container,
            en.err_hidden_requires_container,
        ),
        (tr.err_hidden_add_source, en.err_hidden_add_source),
        (tr.err_hidden_enter_pw, en.err_hidden_enter_pw),
        (tr.err_hidden_pw_mismatch, en.err_hidden_pw_mismatch),
        (tr.err_hidden_same_pw, en.err_hidden_same_pw),
        (tr.status_enc_hidden_running, en.status_enc_hidden_running),
    ];

    for (t, e) in pairs {
        assert!(!t.trim().is_empty(), "TR string must be non-empty");
        assert!(!e.trim().is_empty(), "EN string must be non-empty");
        assert_ne!(t, e, "TR and EN strings should be localized distinctly");
    }

    assert_eq!(tr.container_10_mib, "10 MiB");
    assert_eq!(en.container_10_mib, "10 MiB");
    assert_eq!(tr.container_50_mib, "50 MiB");
    assert_eq!(en.container_50_mib, "50 MiB");
    assert_eq!(tr.container_100_mib, "100 MiB");
    assert_eq!(en.container_100_mib, "100 MiB");
    assert_eq!(tr.container_500_mib, "500 MiB");
    assert_eq!(en.container_500_mib, "500 MiB");
}

#[test]
fn seekable_inspect_and_diff_support_hidden_vault_end_to_end() {
    for stealth in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let decoy_file = dir.path().join("public_readme.txt");
        let hidden_file = dir.path().join("private_keys.txt");
        fs::write(&decoy_file, b"public decoy contents").unwrap();
        fs::write(&hidden_file, b"secret hidden contents").unwrap();

        let vault = dir.path().join("container.vault");
        let container_size = 512 * 1024;
        let cancel = Arc::new(AtomicBool::new(false));
        if stealth {
            use rpm_gui::state::WorkerUpdate;
            use zeroize::Zeroizing;
            let (tx, rx) = std::sync::mpsc::channel();
            worker::spawn_encrypt_hidden(
                egui::Context::default(),
                tx,
                cancel,
                vec![decoy_file.clone()],
                vec![hidden_file],
                Zeroizing::new("DecoyPw!1".into()),
                Zeroizing::new("HiddenPw!2".into()),
                SecretKey::new([5; 32]),
                None,
                None,
                None,
                true,
                true,
                container_size,
                true,
                false,
                false,
                1,
                KdfParams::fast_test(),
                AppLanguage::En,
            );
            loop {
                match rx.recv_timeout(Duration::from_secs(60)).unwrap() {
                    WorkerUpdate::EncryptDone { .. } => break,
                    WorkerUpdate::Error(err) => panic!("{err}"),
                    _ => {}
                }
            }
            fs::rename(dir.path().join("public_readme.txt.vault"), &vault).unwrap();
        } else {
            let opts = HiddenEncryptOptions {
                reed_solomon: false,
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

            encrypt_hidden_sources_v5(
                std::slice::from_ref(&decoy_file),
                std::slice::from_ref(&hidden_file),
                &vault,
                b"DecoyPw!1",
                b"HiddenPw!2",
                &opts,
                Arc::new(|_, _| {}),
                cancel,
                |_| {},
            )
            .unwrap();
        }
        let mut reader_outer = BufReader::new(File::open(&vault).unwrap());
        let outer_info = inspect_header_seekable(
            &mut reader_outer,
            Auth::Password {
                password: b"DecoyPw!1",
                keyfile_hash: None,
            },
        )
        .unwrap();
        assert!(!outer_info.is_hidden_compartment);
        assert_eq!(outer_info.container_size, Some(container_size));

        let mut reader_hidden = BufReader::new(File::open(&vault).unwrap());
        let hidden_info = inspect_header_seekable(
            &mut reader_hidden,
            Auth::Password {
                password: b"HiddenPw!2",
                keyfile_hash: None,
            },
        )
        .unwrap();
        assert_eq!(outer_info.is_stealth, stealth);
        assert_eq!(hidden_info.is_stealth, stealth);
        for lang in [AppLanguage::Tr, AppLanguage::En] {
            let report = worker::format_inspect_report(&hidden_info, lang);
            assert_eq!(report.contains(i18n::strings(lang).stealth_mode), stealth);
            if stealth {
                let prefix = match lang {
                    AppLanguage::Tr => "Başlık Modu     : ",
                    AppLanguage::En => "Header Mode    : ",
                };
                assert!(report.contains(prefix));
            }
        }
        assert!(hidden_info.is_hidden_compartment);
        assert_eq!(hidden_info.container_size, Some(container_size));

        let hidden_tr = worker::format_inspect_report(&hidden_info, AppLanguage::Tr);
        let hidden_en = worker::format_inspect_report(&hidden_info, AppLanguage::En);
        assert!(hidden_tr.contains("Gizli Kasa"));
        assert!(hidden_en.contains("Hidden Vault"));
        assert!(hidden_tr.contains("Konteyner Boyutu"));
        assert!(hidden_en.contains("Container Size"));

        let diff = diff_metadata(&outer_info.metadata, &hidden_info.metadata).unwrap();
        let diff_report = worker::format_diff_report(&diff, AppLanguage::En);
        assert!(diff_report.contains("+1 added, -1 removed"));
        assert!(diff_report.contains("private_keys.txt"));
        assert!(diff_report.contains("public_readme.txt"));
    }
}

#[test]
fn rekey_unsupported_error_is_neutral_and_localized() {
    let err = rpm_storage::StorageError::Crypto(CryptoError::UnsupportedOperation(
        "in-place re-key is not available".into(),
    ));
    let tr = worker::format_rekey_error(&err, AppLanguage::Tr);
    let en = worker::format_rekey_error(&err, AppLanguage::En);

    assert!(!tr.trim().is_empty());
    assert!(!en.trim().is_empty());
    assert_ne!(tr, en);

    for bad in ["padded", "padding", "dolgu", "hidden", "gizli", "container"] {
        assert!(
            !tr.to_ascii_lowercase().contains(bad),
            "TR message leaked '{bad}': {tr}"
        );
        assert!(
            !en.to_ascii_lowercase().contains(bad),
            "EN message leaked '{bad}': {en}"
        );
    }
}

#[test]
fn preview_types_cleanup_and_localization() {
    use rpm_gui::preview::{classify_preview, ClassifiedPreview, PreviewState};
    use zeroize::Zeroizing;
    assert!(
        matches!(classify_preview("notes","Türkçe".as_bytes()),ClassifiedPreview::Text(t) if *t=="Türkçe")
    );
    assert!(matches!(
        classify_preview("data", &[65, 0]),
        ClassifiedPreview::Binary
    ));
    assert!(matches!(
        classify_preview("data", &[255]),
        ClassifiedPreview::Binary
    ));
    assert!(matches!(
        classify_preview("broken.jpg", b"hello"),
        ClassifiedPreview::InvalidImage
    ));
    let png = include_bytes!("../assets/icon.png");
    assert!(matches!(classify_preview("icon.PNG",png),ClassifiedPreview::Image(i) if i.width()>0));
    let ctx = egui::Context::default();
    let preview = || {
        Some(PreviewState::new(
            &ctx,
            "notes.txt".into(),
            Zeroizing::new(b"secret".to_vec()),
        ))
    };
    let mut st = fresh_state();
    st.inspect.preview = preview();
    st.inspect.clear_preview();
    assert!(st.inspect.preview.is_none());
    st.inspect.preview = preview();
    assert!(st.dismiss_modals());
    assert!(st.inspect.preview.is_none());
    st.inspect.preview = preview();
    st.inspect.reset_manifest();
    assert!(st.inspect.preview.is_none());
    st.select_tab(Tab::Inspect);
    st.inspect.preview = preview();
    st.select_tab(Tab::Settings);
    assert!(st.inspect.preview.is_none());
    let labels = |s: &i18n::Strings| {
        [
            s.btn_preview,
            s.preview_title,
            s.preview_ram,
            s.preview_binary,
            s.preview_image_error,
            s.preview_loading,
            s.preview_ready,
            s.preview_cancelled,
            s.preview_failed,
            s.preview_limit,
            s.preview_close,
            s.preview_prev,
            s.preview_next,
        ]
    };
    for (tr, en) in labels(&i18n::TR).into_iter().zip(labels(&i18n::EN)) {
        assert!(!tr.is_empty() && !en.is_empty());
        assert_ne!(tr, en);
    }
}

#[test]
fn stealth_preferences_and_digest_only_reports_are_bilingual_and_neutral() {
    assert!(!fresh_state().encrypt.stealth);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.dat");
    fs::write(&path, b"example").unwrap();
    let report = rpm_core::check_integrity(&path).unwrap();
    assert!(report.sha256_only);
    for (lang, size) in [
        (AppLanguage::Tr, "Dosya boyutu"),
        (AppLanguage::En, "File size"),
    ] {
        let s = i18n::strings(lang);
        let text = worker::format_integrity_report(&report, lang);
        assert_eq!(
            text,
            format!(
                "{size}: 7 B\nSHA-256: {}\n{}",
                report.sha256_hex, s.digest_computed
            )
        );
        assert!(s.stealth_help.contains("64 MiB") && s.stealth_help.contains("SHA-256"));
    }
    for (tr, en) in [
        (i18n::TR.stealth_mode, i18n::EN.stealth_mode),
        (i18n::TR.stealth_help, i18n::EN.stealth_help),
        (i18n::TR.digest_computed, i18n::EN.digest_computed),
    ] {
        assert!(!tr.is_empty() && !en.is_empty() && tr != en);
    }
}

#[test]
fn rs_and_stealth_are_mutually_exclusive_and_localized() {
    let mut state = fresh_state();
    let fields = &mut state.encrypt;
    assert!(!fields.reed_solomon);
    fields.set_stealth(true);
    fields.set_reed_solomon(true);
    assert!(fields.reed_solomon && !fields.stealth);
    fields.set_stealth(true);
    assert!(fields.stealth && !fields.reed_solomon);
    fields.set_reed_solomon(false);
    assert!(fields.stealth);
    let labels = |s: &'static i18n::Strings| {
        [
            s.rs_mode,
            s.rs_help,
            s.rs_bytes,
            s.rs_seen,
            s.btn_repair,
            s.repair_done,
            s.repair_error,
            s.repair_running,
            s.repair_requires_rs,
            s.repair_invalid,
            s.repair_cancelled,
        ]
    };
    for (tr, en) in labels(&i18n::TR).into_iter().zip(labels(&i18n::EN)) {
        assert!(!tr.is_empty() && !en.is_empty() && tr != en);
    }
}

#[test]
fn upfront_gui_constraint_hints_parity_and_preview_limit_render() {
    let tr = i18n::strings(AppLanguage::Tr);
    let en = i18n::strings(AppLanguage::En);

    let pairs = [
        (tr.stealth_disabled_tip, en.stealth_disabled_tip),
        (tr.rs_disabled_tip, en.rs_disabled_tip),
        (tr.wipe_warning_note, en.wipe_warning_note),
        (tr.hidden_limits_note, en.hidden_limits_note),
        (tr.dec_stealth_drop_hint, en.dec_stealth_drop_hint),
        (tr.dec_recovery_hidden_note, en.dec_recovery_hidden_note),
        (tr.ins_actions_note, en.ins_actions_note),
        (tr.ins_preview_limits_note, en.ins_preview_limits_note),
        (tr.preview_too_large_tip, en.preview_too_large_tip),
        (tr.rek_limits_note, en.rek_limits_note),
        (tr.set_argon_scope_note, en.set_argon_scope_note),
        (tr.stealth_help, en.stealth_help),
        (tr.rs_help, en.rs_help),
        (tr.ins_reenter_creds_hint, en.ins_reenter_creds_hint),
    ];
    for (t, e) in pairs {
        assert!(!t.trim().is_empty());
        assert!(!e.trim().is_empty());
        assert_ne!(t, e);
    }

    for s in [tr, en] {
        assert!(s.stealth_help.contains("Re-Key"));
        assert!(s.rs_help.contains("Re-Key"));
        assert!(s.hidden_limits_note.contains("Re-Key"));
        assert!(s.rek_limits_note.contains("Stealth") && s.rek_limits_note.contains("24"));
        assert!(s.ins_preview_limits_note.contains("16 MiB"));
        assert!(s.preview_too_large_tip.contains("16 MiB"));
        assert!(s.wipe_warning_note.contains("SSD"));
        assert!(s.set_argon_scope_note.contains("64 MiB"));
    }
    assert!(tr.rek_limits_note.contains("standart"));
    assert!(en.rek_limits_note.contains("standard"));

    let ctx = egui::Context::default();
    let (tx, _rx) = std::sync::mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut st = fresh_state();
    st.encrypt.secure_wipe = true;
    st.encrypt.set_stealth(true);
    st.encrypt.set_hidden_enabled(true);
    st.decrypt.use_recovery = true;
    st.inspect.set_manifest(
        PathBuf::from("sample.vault"),
        vec![
            FileManifestEntry {
                path: "small.txt".into(),
                size: 1024,
                modified_unix: 0,
            },
            FileManifestEntry {
                path: "large.bin".into(),
                size: (rpm_storage::DEFAULT_PREVIEW_MAX_BYTES as u64) + 1,
                modified_unix: 0,
            },
        ],
    );

    for lang in [AppLanguage::Tr, AppLanguage::En] {
        st.config.language = lang;

        st.encrypt.set_stealth(true);
        ctx.run_ui(Default::default(), |ui| {
            rpm_gui::tabs::encrypt::ui(ui, &ctx, &mut st, &tx, &cancel);
        })
        .textures_delta
        .clear();

        st.encrypt.set_reed_solomon(true);
        ctx.run_ui(Default::default(), |ui| {
            rpm_gui::tabs::encrypt::ui(ui, &ctx, &mut st, &tx, &cancel);
        })
        .textures_delta
        .clear();

        ctx.run_ui(Default::default(), |ui| {
            rpm_gui::tabs::decrypt::ui(ui, &ctx, &mut st, &tx, &cancel);
        })
        .textures_delta
        .clear();

        ctx.run_ui(Default::default(), |ui| {
            rpm_gui::tabs::inspect::ui(ui, &ctx, &mut st, &tx, &cancel);
        })
        .textures_delta
        .clear();

        ctx.run_ui(Default::default(), |ui| {
            rpm_gui::tabs::rekey::ui(ui, &ctx, &mut st, &tx, &cancel);
        })
        .textures_delta
        .clear();

        ctx.run_ui(Default::default(), |ui| {
            rpm_gui::tabs::settings::ui(ui, &ctx, &mut st);
        })
        .textures_delta
        .clear();
    }
}

fn populate_all_sensitive_fields(st: &mut AppState) {
    st.encrypt.password = "Outer!1".into();
    st.encrypt.confirm_password = "Outer!1".into();
    st.encrypt.hidden_password = "Hidden!2".into();
    st.encrypt.hidden_confirm_password = "Hidden!2".into();
    st.encrypt.recovery_prompt = Some(RecoveryPrompt {
        phrase: "word ".repeat(24),
        entropy: SecretKey::new([0x44u8; 32]),
        confirmed: false,
        queue_after_confirm: false,
    });
    st.decrypt.password = "Dec!1".into();
    st.decrypt.recovery_phrase = "rec words".into();
    st.inspect.password = "Ins!1".into();
    st.inspect.recovery_phrase = "ins rec".into();
    st.inspect.results = "custom metadata output".into();
    st.inspect.set_manifest(
        PathBuf::from("secret.vault"),
        vec![FileManifestEntry {
            path: "secret.txt".into(),
            size: 42,
            modified_unix: 0,
        }],
    );
    st.diff.password_a = "DiffA!1".into();
    st.diff.recovery_phrase_a = "diff rec a".into();
    st.diff.password_b = "DiffB!2".into();
    st.diff.recovery_phrase_b = "diff rec b".into();
    st.diff.results = "diff results".into();
    st.rekey.current_password = "Old!1".into();
    st.rekey.new_password = "New!2".into();
    st.rekey.confirm_password = "New!2".into();
    st.pwgen.generated = "GenPass!12345".into();
    st.push_log("sensitive activity");
    st.enqueue_job(QueuedJobKind::IntegrityCheck {
        path: PathBuf::from("queued.vault"),
    });
    st.last_action = Some(rpm_gui::state::LastCompletedAction {
        summary: "done".into(),
        reveal_path: PathBuf::from("secret.vault"),
        verify_vault: Some(PathBuf::from("secret.vault")),
    });
}

#[test]
fn panic_and_idle_clear_reset_all_in_app_secrets_without_touching_clipboard() {
    let mut st = fresh_state();
    assert!(!st.has_sensitive_session_data());

    let clip_deadline = Instant::now() + Duration::from_secs(25);
    st.clipboard_deadline = Some(clip_deadline);
    st.show_shell_install_modal = true;
    populate_all_sensitive_fields(&mut st);
    assert!(st.has_sensitive_session_data());

    st.clear_sensitive_session(SessionClearReason::ManualPanic);
    assert!(!st.has_sensitive_session_data());
    assert!(!st.show_shell_install_modal);
    assert!(st.encrypt.password.is_empty());
    assert!(st.encrypt.hidden_password.is_empty());
    assert!(st.encrypt.recovery_prompt.is_none());
    assert!(st.decrypt.password.is_empty());
    assert!(st.decrypt.recovery_phrase.is_empty());
    assert!(st.inspect.password.is_empty());
    assert!(st.inspect.recovery_phrase.is_empty());
    assert!(st.inspect.manifest.is_empty());
    assert!(st.diff.password_a.is_empty() && st.diff.password_b.is_empty());
    assert!(st.rekey.current_password.is_empty() && st.rekey.new_password.is_empty());
    assert!(st.pwgen.generated.is_empty());
    assert!(st.logs.is_empty());
    assert!(st.job_queue.is_empty());
    assert!(st.last_action.is_none());
    assert_eq!(st.clipboard_deadline, Some(clip_deadline));

    // Idle clear disabled (0 minutes) does nothing
    st.config.idle_clear_minutes = 0;
    st.encrypt.password = "KeepMe!1".into();
    let t0 = st.last_activity;
    assert!(!st.check_idle_timeout(t0 + Duration::from_secs(3600)));
    assert_eq!(st.encrypt.password, "KeepMe!1");

    // Idle timeout skipped while a non-preview transfer is busy (and refreshes activity)
    st.config.idle_clear_minutes = 5;
    st.busy = true;
    let t_busy = t0 + Duration::from_secs(400);
    assert!(!st.check_idle_timeout(t_busy));
    assert_eq!(st.last_activity, t_busy);
    assert_eq!(st.encrypt.password, "KeepMe!1");

    // Once transfer completes and 5 minutes elapse, idle timeout clears session while preserving clipboard
    st.busy = false;
    assert!(!st.check_idle_timeout(t_busy + Duration::from_secs(299)));
    assert!(st.check_idle_timeout(t_busy + Duration::from_secs(300)));
    assert!(st.encrypt.password.is_empty());
    assert!(!st.has_sensitive_session_data());
    assert_eq!(st.clipboard_deadline, Some(clip_deadline));
}

#[test]
fn encryption_profiles_presets_crud_and_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("config.json");
    let mut st = AppState::from_config(AppConfig::default(), Some(cfg_path.clone()));

    let s = st.strings();
    // Apply each built-in preset
    st.apply_encrypt_profile(&BuiltinEncryptPreset::LongTermArchiveRs.to_profile(s));
    assert!(st.encrypt.reed_solomon);
    assert!(!st.encrypt.stealth);
    assert_eq!(st.encrypt.container_preset, ContainerSizePreset::Auto);

    st.apply_encrypt_profile(&BuiltinEncryptPreset::MaximumPrivacyStealth.to_profile(s));
    assert!(st.encrypt.stealth);
    assert!(!st.encrypt.reed_solomon);
    assert_eq!(st.encrypt.container_preset, ContainerSizePreset::MiB100);

    // Applying Auto preset while hidden vault is enabled must keep a fixed container
    st.encrypt.set_hidden_enabled(true);
    st.apply_encrypt_profile(&BuiltinEncryptPreset::DailyBackup.to_profile(s));
    assert_eq!(st.encrypt.container_preset, ContainerSizePreset::MiB50);
    assert!(st.encrypt.resolve_container_size().unwrap().is_some());

    // Save custom user profile (with custom MiB & password populated — secrets must NOT be persisted!)
    st.encrypt.set_hidden_enabled(false);
    st.encrypt.password = "NeverPersistPassword!99".into();
    st.encrypt.container_preset = ContainerSizePreset::Custom;
    st.encrypt.container_custom_mb = "250".into();
    st.encrypt.save_next_to_source = false;
    st.encrypt.output_dir = dir.path().display().to_string();

    assert!(st.save_current_encrypt_profile("   ").is_err());
    st.save_current_encrypt_profile("My Archive").unwrap();
    assert_eq!(st.config.encrypt_profiles.len(), 1);
    assert_eq!(st.config.encrypt_profiles[0].container_size_mib, Some(250));

    // Upsert case-insensitively replaces existing entry
    st.encrypt.compress = false;
    st.save_current_encrypt_profile("my archive").unwrap();
    assert_eq!(st.config.encrypt_profiles.len(), 1);
    assert!(!st.config.encrypt_profiles[0].compress);

    let raw = fs::read_to_string(&cfg_path).unwrap();
    assert!(!raw.contains("NeverPersistPassword"));
    let reloaded = load_config_from(&cfg_path);
    assert_eq!(reloaded.encrypt_profiles, st.config.encrypt_profiles);

    // Enforce max limit and delete
    assert!(st.delete_encrypt_profile("MY ARCHIVE"));
    assert!(st.config.encrypt_profiles.is_empty());
    let mut cfg_full = AppConfig::default();
    for i in 0..32 {
        cfg_full.encrypt_profiles.push(EncryptProfile {
            name: format!("P{i}"),
            ..EncryptProfile::default()
        });
    }
    let mut st_full = AppState::from_config(cfg_full, None);
    assert!(st_full.save_current_encrypt_profile("33rd").is_err());
}

#[test]
fn preflight_scan_rs_wire_size_and_fit_estimation() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let f1 = dir.path().join("a.bin");
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    let f2 = sub.join("b.bin");
    fs::write(&f1, vec![0xAAu8; 4096]).unwrap();
    fs::write(&f2, vec![0xBBu8; 1024]).unwrap();

    #[cfg(unix)]
    let _ = std::os::unix::fs::symlink(&f1, dir.path().join("link.bin"));

    let cancel = AtomicBool::new(false);
    let summary = scan_sources_sync(&[dir.path().to_path_buf()], &cancel).unwrap();
    assert_eq!(summary.file_count, 2);
    assert_eq!(summary.raw_bytes, 5120);
    assert!(summary.dir_count >= 2);
    #[cfg(unix)]
    assert_eq!(summary.skipped_symlinks, 1);

    let cancelled = AtomicBool::new(true);
    assert!(scan_sources_sync(&[dir.path().to_path_buf()], &cancelled).is_none());

    // Verify rs_wire_size matches RsEncoderWriter byte-for-byte across block boundaries
    for &len in &[0usize, 100, 15_292, 15_293, 65_536] {
        let mut encoded = Vec::new();
        let mut enc = rpm_core::RsEncoderWriter::new(&mut encoded).unwrap();
        if len > 0 {
            enc.write_all(&vec![0x5Au8; len]).unwrap();
        }
        enc.finish().unwrap();
        assert_eq!(
            rs_wire_size(len as u64),
            encoded.len() as u64,
            "rs_wire_size mismatch for inner len {len}"
        );
    }

    // Fit estimation scenarios
    let small = SourceSizeSummary {
        file_count: 1,
        dir_count: 0,
        raw_bytes: 1024,
        ..Default::default()
    };
    let hidden_empty = SourceSizeSummary::default();
    let auto_rs = estimate_encrypt_preflight(
        &small,
        &hidden_empty,
        false,
        true,
        true,
        true,
        ContainerSizePreset::Auto,
        "100",
    );
    assert_eq!(auto_rs.fit, ContainerFitStatus::NoContainer);
    assert!(auto_rs.rs_overhead_bytes > 0);
    assert_eq!(
        auto_rs.estimated_disk_bytes,
        rs_wire_size(auto_rs.total_inner_required_bytes)
    );

    let fits = estimate_encrypt_preflight(
        &small,
        &hidden_empty,
        false,
        false,
        false,
        false,
        ContainerSizePreset::MiB10,
        "100",
    );
    assert!(matches!(fits.fit, ContainerFitStatus::Fits { .. }));

    let large = SourceSizeSummary {
        file_count: 1,
        dir_count: 0,
        raw_bytes: 15 * 1024 * 1024,
        ..Default::default()
    };
    let exceeds = estimate_encrypt_preflight(
        &large,
        &hidden_empty,
        false,
        false,
        false,
        false,
        ContainerSizePreset::MiB10,
        "100",
    );
    match exceeds.fit {
        ContainerFitStatus::ExceedsContainer { suggested_mib, .. } => {
            assert!(suggested_mib >= 16);
        }
        other => panic!("expected ExceedsContainer, got {other:?}"),
    }

    let comp_dep = estimate_encrypt_preflight(
        &large,
        &hidden_empty,
        false,
        true,
        false,
        false,
        ContainerSizePreset::MiB10,
        "100",
    );
    assert!(matches!(
        comp_dep.fit,
        ContainerFitStatus::CompressionDependent { .. }
    ));

    let invalid = estimate_encrypt_preflight(
        &small,
        &hidden_empty,
        false,
        true,
        false,
        false,
        ContainerSizePreset::Custom,
        "0",
    );
    assert_eq!(
        invalid.fit,
        ContainerFitStatus::InvalidContainer(ContainerSizeError::InvalidCustomValue)
    );
}

#[test]
fn reveal_command_spec_and_queue_operations_work_safely() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("archive.vault");
    fs::write(&file, b"vault").unwrap();

    assert!(reveal_command_spec(PathBuf::new().as_path()).is_none());

    let (prog_dir, args_dir) = reveal_command_spec(dir.path()).unwrap();
    let (prog_file, args_file) = reveal_command_spec(&file).unwrap();
    if cfg!(target_os = "windows") {
        assert_eq!(prog_dir, "explorer.exe");
        assert_eq!(args_dir, vec![dir.path().as_os_str()]);
        assert_eq!(prog_file, "explorer.exe");
        assert_eq!(
            args_file,
            vec![
                std::ffi::OsString::from("/select,"),
                file.as_os_str().to_os_string()
            ]
        );
    } else if cfg!(target_os = "macos") {
        assert_eq!(prog_dir, "open");
        assert_eq!(prog_file, "open");
    } else {
        assert_eq!(prog_dir, "xdg-open");
        assert_eq!(args_dir, vec![dir.path().as_os_str()]);
        assert_eq!(prog_file, "xdg-open");
        assert_eq!(args_file, vec![dir.path().as_os_str()]);
    }

    // Queue ordering, removal, clear, and Debug redaction
    let mut st = fresh_state();
    let id1 = st.enqueue_job(QueuedJobKind::Decrypt {
        vaults: vec![file.clone()],
        use_recovery: false,
        secret: zeroize::Zeroizing::new("TopSecretQueuePw!9".into()),
        keyfile: None,
        output_dir: None,
    });
    let id2 = st.enqueue_job(QueuedJobKind::IntegrityCheck { path: file.clone() });
    let id3 = st.enqueue_job(QueuedJobKind::Repair { path: file.clone() });

    let dbg = format!("{:?}", st.job_queue);
    assert!(!dbg.contains("TopSecretQueuePw"));
    assert!(dbg.contains("[REDACTED]"));

    assert!(st.move_queued_job_up(2));
    assert_eq!(st.job_queue[1].id, id3);
    assert!(st.move_queued_job_down(0));
    assert_eq!(st.job_queue[1].id, id1);
    assert!(st.remove_queued_job(id2));
    assert_eq!(st.job_queue.len(), 2);
    assert_eq!(st.clear_pending_queue(), 2);
    assert!(st.job_queue.is_empty());
}

#[test]
fn vault_explorer_tree_building_folder_selection_and_filters() {
    use rpm_gui::explorer::{
        build_manifest_tree, category_badge, classify_file_category, file_basename,
        folder_selection_state, set_folder_selection, FileCategory, FileCategoryFilter,
        FolderSelectionState, ManifestViewMode, SizeFilter,
    };

    let entries = vec![
        FileManifestEntry {
            path: "docs/readme.txt".into(),
            size: 512,
            modified_unix: 0,
        },
        FileManifestEntry {
            path: "docs\\sub\\photo.PNG".into(),
            size: 2 * 1024 * 1024,
            modified_unix: 0,
        },
        FileManifestEntry {
            path: "media/clip.mp4".into(),
            size: 5 * 1024 * 1024,
            modified_unix: 0,
        },
        FileManifestEntry {
            path: "archive/backup.zip".into(),
            size: 20 * 1024 * 1024,
            modified_unix: 0,
        },
        FileManifestEntry {
            path: "root.bin".into(),
            size: 128,
            modified_unix: 0,
        },
    ];

    assert_eq!(
        classify_file_category("docs/readme.txt"),
        FileCategory::Text
    );
    assert_eq!(
        classify_file_category("docs/sub/photo.PNG"),
        FileCategory::Image
    );
    assert_eq!(
        classify_file_category("archive/backup.zip"),
        FileCategory::Archive
    );
    assert_eq!(
        classify_file_category("media/clip.mp4"),
        FileCategory::Media
    );
    assert_eq!(classify_file_category("root.bin"), FileCategory::Other);
    assert_eq!(category_badge(FileCategory::Text), "[TXT]");
    assert_eq!(file_basename("docs\\sub\\photo.PNG"), "photo.PNG");

    let mut st = fresh_state();
    st.inspect
        .set_manifest(PathBuf::from("vault.vault"), entries);
    assert_eq!(st.inspect.view_mode, ManifestViewMode::Tree);
    assert_eq!(st.inspect.filtered_indices(), vec![0, 1, 2, 3, 4]);

    let all_idx = st.inspect.filtered_indices();
    let tree = build_manifest_tree(&st.inspect.manifest, &all_idx);
    assert_eq!(tree.total_files, 5);
    assert_eq!(tree.files, vec![4]);
    let docs_node = tree.dirs.get("docs").expect("docs dir present");
    assert_eq!(docs_node.total_files, 2);
    assert_eq!(docs_node.total_bytes, 512 + 2 * 1024 * 1024);
    assert_eq!(
        folder_selection_state(docs_node, &st.inspect.manifest, &st.inspect.selected_paths),
        FolderSelectionState::None
    );

    // Select one file -> Partial
    st.inspect.selected_paths.insert("docs/readme.txt".into());
    assert_eq!(
        folder_selection_state(docs_node, &st.inspect.manifest, &st.inspect.selected_paths),
        FolderSelectionState::Partial
    );

    // Folder checkbox selects entire subtree without affecting siblings
    set_folder_selection(
        docs_node,
        &st.inspect.manifest,
        &mut st.inspect.selected_paths,
        true,
    );
    assert_eq!(
        folder_selection_state(docs_node, &st.inspect.manifest, &st.inspect.selected_paths),
        FolderSelectionState::All
    );
    assert_eq!(st.inspect.selected_paths.len(), 2);
    assert_eq!(st.inspect.selected_total_bytes(), 512 + 2 * 1024 * 1024);

    set_folder_selection(
        docs_node,
        &st.inspect.manifest,
        &mut st.inspect.selected_paths,
        false,
    );
    assert_eq!(
        folder_selection_state(docs_node, &st.inspect.manifest, &st.inspect.selected_paths),
        FolderSelectionState::None
    );

    // Combined Category + Size + Text filters
    st.inspect.category_filter = FileCategoryFilter::Image;
    assert_eq!(st.inspect.filtered_indices(), vec![1]);
    st.inspect.category_filter = FileCategoryFilter::All;
    st.inspect.size_filter = SizeFilter::Over16MiB;
    assert_eq!(st.inspect.filtered_indices(), vec![3]);
    st.inspect.size_filter = SizeFilter::PreviewableOnly;
    assert_eq!(st.inspect.filtered_indices(), vec![0, 1, 2, 4]);
    st.inspect.size_filter = SizeFilter::From1To16MiB;
    assert_eq!(st.inspect.filtered_indices(), vec![1, 2]);
    st.inspect.filter_query = "sub/photo".into();
    assert_eq!(st.inspect.filtered_indices(), vec![1]);
    assert!(st.inspect.has_active_filters());
    st.inspect.reset_filters();
    assert!(!st.inspect.has_active_filters());
    assert_eq!(st.inspect.filtered_indices(), vec![0, 1, 2, 3, 4]);

    // Headless render across Tree, Flat, TR, EN + expand/collapse epochs
    let prev_epoch = st.inspect.tree_id_epoch;
    st.inspect.collapse_all_tree();
    assert!(!st.inspect.tree_default_open);
    assert!(st.inspect.tree_id_epoch > prev_epoch);
    st.inspect.expand_all_tree();
    assert!(st.inspect.tree_default_open);

    let ctx = egui::Context::default();
    let (tx, _rx) = std::sync::mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    for lang in [AppLanguage::Tr, AppLanguage::En] {
        st.config.language = lang;
        for mode in [ManifestViewMode::Tree, ManifestViewMode::Flat] {
            st.inspect.view_mode = mode;
            ctx.run_ui(Default::default(), |ui| {
                rpm_gui::tabs::inspect::ui(ui, &ctx, &mut st, &tx, &cancel);
            })
            .textures_delta
            .clear();
        }
    }

    // Package 2 i18n parity check (universal numeric size ranges checked non-empty separately)
    let pkg2_localized = |s: &i18n::Strings| {
        [
            s.view_tree,
            s.view_flat,
            s.btn_expand_all,
            s.btn_collapse_all,
            s.btn_reset_filters,
            s.lbl_filter_type,
            s.lbl_filter_size,
            s.cat_all,
            s.cat_text,
            s.cat_image,
            s.cat_archive,
            s.cat_media,
            s.cat_other,
            s.size_all,
            s.size_previewable,
            s.ins_no_matching_files,
            s.preview_search_hint,
            s.preview_line_numbers,
            s.preview_match_prev,
            s.preview_match_next,
            s.preview_zoom_fit,
            s.preview_rotate_left,
            s.preview_rotate_right,
            s.preview_empty_binary,
        ]
    };
    for (tr, en) in pkg2_localized(&i18n::TR)
        .into_iter()
        .zip(pkg2_localized(&i18n::EN))
    {
        assert!(!tr.is_empty() && !en.is_empty());
        assert_ne!(tr, en);
    }
    for s in [&i18n::TR, &i18n::EN] {
        assert!(!s.size_under_1m.is_empty());
        assert!(!s.size_1_to_16m.is_empty());
        assert!(!s.size_over_16m.is_empty());
    }
}
