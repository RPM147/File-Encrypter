use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use rpm_core::{
    ChangedEntry, FileManifestEntry, IntegrityReport, SecretKey, VaultDiff, VaultInfo,
    VaultMetadata,
};
use rpm_gui::progress::{
    format_bytes, format_eta, format_rate, format_transfer_summary, format_transfer_tooltip,
    TransferMeter, TransferSnapshot,
};
use rpm_gui::state::{
    clamp_ui_scale_percent, strength_label_and_color_for, ui_scale_zoom_factor, AppState,
    PasswordGenFields, RecoveryPrompt, Tab, ARGON_ITERATIONS_RANGE, ARGON_PARALLELISM_RANGE,
    PWGEN_AMBIGUOUS, PWGEN_DIGITS, PWGEN_LOWERCASE, PWGEN_SYMBOLS, PWGEN_UPPERCASE,
    UI_SCALE_DEFAULT, UI_SCALE_MAX, UI_SCALE_MIN, UI_SCALE_PRESETS,
};
use rpm_gui::{fonts, i18n, load_app_icon, worker};
use rpm_storage::config::{load_config_from, AppLanguage, ThemeMode};
use rpm_storage::{GuiLaunchIntent, LaunchTab};

#[test]
fn dropped_files_route_vaults_to_decrypt_and_regular_to_encrypt() {
    let mut st = AppState::default();
    st.add_dropped_paths(vec![PathBuf::from("a.txt"), PathBuf::from("folder")], None);
    assert_eq!(st.active_tab, Tab::Encrypt);
    assert_eq!(st.encrypt.sources.len(), 2);

    st.add_dropped_paths(vec![PathBuf::from("secret.vault")], None);
    assert_eq!(st.active_tab, Tab::Decrypt);
    assert_eq!(st.decrypt.vaults, vec![PathBuf::from("secret.vault")]);

    // Non-.vault dropped onto Decrypt is rejected cleanly
    st.add_dropped_paths(vec![PathBuf::from("plain.txt")], Some(Tab::Decrypt));
    assert!(st.is_error);
}

#[test]
fn launch_intent_and_password_gen_and_secret_clearing() {
    let mut st = AppState::default();
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

    let mut st = AppState::default();
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
    let mut st = AppState::default();
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

    let info = VaultInfo {
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
    let mut st = AppState {
        transfer: Some(TransferSnapshot {
            fraction: 0.5,
            bytes_done: 100,
            bytes_total: 200,
            bytes_per_sec: Some(1024.0),
            eta: Some(Duration::from_secs(1)),
            item_index: None,
        }),
        ..Default::default()
    };
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
    let mut st = AppState::default();
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

    let mut st = AppState {
        config_path: Some(cfg_path.clone()),
        ..Default::default()
    };
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
    let mut st = AppState::default();
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
    let mut st = AppState::default();
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
