use std::fs;
use std::path::PathBuf;

use eframe::egui;
use rpm_core::SecretKey;
use rpm_gui::state::{strength_label_and_color_for, AppState, RecoveryPrompt, Tab};
use rpm_gui::{fonts, i18n, load_app_icon};
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
