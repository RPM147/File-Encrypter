use std::fs;
use std::path::PathBuf;

use eframe::egui;
use rpm_core::{FileManifestEntry, IntegrityReport, SecretKey, VaultInfo, VaultMetadata};
use rpm_gui::state::{strength_label_and_color_for, AppState, RecoveryPrompt, Tab};
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
