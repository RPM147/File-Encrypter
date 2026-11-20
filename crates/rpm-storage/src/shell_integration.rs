//! User-scoped Windows Explorer context menu and .vault file association helpers.
//!
//! All registry writes target HKCU\Software\Classes (no Administrator rights
//! needed) through a pluggable `RegistryBackend` trait so unit tests never touch
//! the real Windows registry.

use std::collections::HashMap;
use std::path::Path;

use crate::error::StorageError;

pub const VAULT_PROG_ID: &str = "RPMEncrypter.Vault";
pub const VAULT_EXT_KEY: &str = r"Software\Classes\.vault";
pub const PROG_ID_KEY: &str = r"Software\Classes\RPMEncrypter.Vault";
pub const FILE_MENU_KEY: &str = r"Software\Classes\*\shell\RPMEncrypter.Encrypt";
pub const DIR_MENU_KEY: &str = r"Software\Classes\Directory\shell\RPMEncrypter.Encrypt";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellIntegrationStatus {
    pub supported: bool,
    pub installed: bool,
    pub context_menu_installed: bool,
    pub vault_association_installed: bool,
    pub command_preview: String,
}

pub trait RegistryBackend {
    fn get_value(&self, subkey: &str, name: &str) -> Option<String>;
    fn set_value(&mut self, subkey: &str, name: &str, value: &str) -> Result<(), StorageError>;
    fn delete_tree(&mut self, subkey: &str) -> Result<(), StorageError>;
    fn notify_shell(&self);
}

#[derive(Default)]
pub struct MemoryRegistryBackend {
    pub keys: HashMap<String, HashMap<String, String>>,
    pub notifications: usize,
}

impl RegistryBackend for MemoryRegistryBackend {
    fn get_value(&self, subkey: &str, name: &str) -> Option<String> {
        self.keys.get(subkey).and_then(|m| m.get(name)).cloned()
    }

    fn set_value(&mut self, subkey: &str, name: &str, value: &str) -> Result<(), StorageError> {
        self.keys
            .entry(subkey.to_string())
            .or_default()
            .insert(name.to_string(), value.to_string());
        Ok(())
    }

    fn delete_tree(&mut self, subkey: &str) -> Result<(), StorageError> {
        let prefix = format!("{subkey}\\");
        self.keys
            .retain(|k, _| k != subkey && !k.starts_with(&prefix));
        Ok(())
    }

    fn notify_shell(&self) {
        // Test stub; count kept read-only on `&self` (interior mutability avoided).
    }
}

#[cfg(windows)]
pub struct WinRegBackend;

#[cfg(windows)]
impl RegistryBackend for WinRegBackend {
    fn get_value(&self, subkey: &str, name: &str) -> Option<String> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu.open_subkey(subkey).ok()?;
        key.get_value::<String, _>(name).ok()
    }

    fn set_value(&mut self, subkey: &str, name: &str, value: &str) -> Result<(), StorageError> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(subkey)
            .map_err(|e| StorageError::ShellIntegration(e.to_string()))?;
        key.set_value(name, &value)
            .map_err(|e| StorageError::ShellIntegration(e.to_string()))?;
        Ok(())
    }

    fn delete_tree(&mut self, subkey: &str) -> Result<(), StorageError> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        match hkcu.delete_subkey_all(subkey) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::ShellIntegration(e.to_string())),
        }
    }

    fn notify_shell(&self) {
        unsafe {
            windows_sys::Win32::UI::Shell::SHChangeNotify(
                0x0800_0000, // SHCNE_ASSOCCHANGED
                0x0000,      // SHCNF_IDLIST
                std::ptr::null(),
                std::ptr::null(),
            );
        }
    }
}

pub fn is_supported() -> bool {
    cfg!(windows)
}

pub fn resolve_gui_exe_prefix() -> String {
    if let Ok(exe) = std::env::current_exe() {
        let gui_sibling = exe.with_file_name("rpm-encrypter.exe");
        if gui_sibling.is_file() {
            return format!("\"{}\"", gui_sibling.display());
        }
        return format!("\"{}\"", exe.display());
    }
    "\"rpm-encrypter.exe\"".to_string()
}

pub fn get_status_with_backend(backend: &dyn RegistryBackend) -> ShellIntegrationStatus {
    let ext_prog = backend.get_value(VAULT_EXT_KEY, "");
    let open_cmd = backend.get_value(&format!("{PROG_ID_KEY}\\shell\\open\\command"), "");
    let file_cmd = backend.get_value(&format!("{FILE_MENU_KEY}\\command"), "");
    let dir_cmd = backend.get_value(&format!("{DIR_MENU_KEY}\\command"), "");

    let vault_assoc = ext_prog.as_deref() == Some(VAULT_PROG_ID) && open_cmd.is_some();
    let ctx_menu = file_cmd.is_some() && dir_cmd.is_some();
    let preview = file_cmd.or(open_cmd).unwrap_or_else(resolve_gui_exe_prefix);

    ShellIntegrationStatus {
        supported: true,
        installed: vault_assoc && ctx_menu,
        context_menu_installed: ctx_menu,
        vault_association_installed: vault_assoc,
        command_preview: preview,
    }
}

pub fn install_with_backend(
    backend: &mut dyn RegistryBackend,
    cmd_prefix: &str,
    icon_path: Option<&Path>,
) -> Result<ShellIntegrationStatus, StorageError> {
    let icon_str = icon_path.map(|p| p.display().to_string());

    backend.set_value(VAULT_EXT_KEY, "", VAULT_PROG_ID)?;
    backend.set_value(PROG_ID_KEY, "", "RPM Encrypter Vault")?;
    if let Some(ico) = icon_str.as_deref() {
        backend.set_value(
            &format!("{PROG_ID_KEY}\\DefaultIcon"),
            "",
            &format!("\"{ico}\",0"),
        )?;
    }
    backend.set_value(
        &format!("{PROG_ID_KEY}\\shell\\open"),
        "",
        "Decrypt with RPM Encrypter",
    )?;
    backend.set_value(
        &format!("{PROG_ID_KEY}\\shell\\open\\command"),
        "",
        &format!("{cmd_prefix} --gui-decrypt \"%1\""),
    )?;

    for menu_key in [FILE_MENU_KEY, DIR_MENU_KEY] {
        backend.set_value(menu_key, "", "Encrypt with RPM Encrypter")?;
        if let Some(ico) = icon_str.as_deref() {
            backend.set_value(menu_key, "Icon", ico)?;
        }
        backend.set_value(
            &format!("{menu_key}\\command"),
            "",
            &format!("{cmd_prefix} --gui-encrypt \"%1\""),
        )?;
    }

    backend.notify_shell();
    Ok(get_status_with_backend(backend))
}

pub fn uninstall_with_backend(
    backend: &mut dyn RegistryBackend,
) -> Result<ShellIntegrationStatus, StorageError> {
    if backend.get_value(VAULT_EXT_KEY, "").as_deref() == Some(VAULT_PROG_ID) {
        backend.delete_tree(VAULT_EXT_KEY)?;
    }
    backend.delete_tree(PROG_ID_KEY)?;
    backend.delete_tree(FILE_MENU_KEY)?;
    backend.delete_tree(DIR_MENU_KEY)?;
    backend.notify_shell();
    Ok(get_status_with_backend(backend))
}

pub fn get_status() -> ShellIntegrationStatus {
    #[cfg(windows)]
    {
        get_status_with_backend(&WinRegBackend)
    }
    #[cfg(not(windows))]
    {
        ShellIntegrationStatus {
            supported: false,
            installed: false,
            context_menu_installed: false,
            vault_association_installed: false,
            command_preview: String::new(),
        }
    }
}

pub fn install_shell_integration() -> Result<ShellIntegrationStatus, StorageError> {
    #[cfg(windows)]
    {
        let mut backend = WinRegBackend;
        let prefix = resolve_gui_exe_prefix();
        let gui_exe = std::env::current_exe()
            .ok()
            .map(|e| e.with_file_name("rpm-encrypter.exe"))
            .filter(|p| p.is_file());
        install_with_backend(&mut backend, &prefix, gui_exe.as_deref())
    }
    #[cfg(not(windows))]
    {
        Err(StorageError::ShellIntegration(
            "Windows shell integration is only supported on Windows.".into(),
        ))
    }
}

pub fn uninstall_shell_integration() -> Result<ShellIntegrationStatus, StorageError> {
    #[cfg(windows)]
    {
        let mut backend = WinRegBackend;
        uninstall_with_backend(&mut backend)
    }
    #[cfg(not(windows))]
    {
        Err(StorageError::ShellIntegration(
            "Windows shell integration is only supported on Windows.".into(),
        ))
    }
}
