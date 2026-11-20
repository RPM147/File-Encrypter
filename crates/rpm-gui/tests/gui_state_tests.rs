use std::path::PathBuf;

use rpm_gui::state::{AppState, Tab};
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
