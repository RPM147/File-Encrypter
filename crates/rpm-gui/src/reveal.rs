//! Cross-platform helper to reveal output vaults or extracted folders in the OS file manager.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

/// Build the OS file-manager command and arguments without spawning a process.
pub fn reveal_command_spec(path: &Path) -> Option<(&'static str, Vec<OsString>)> {
    if path.as_os_str().is_empty() {
        return None;
    }

    #[cfg(target_os = "windows")]
    {
        if path.is_dir() {
            return Some(("explorer.exe", vec![path.as_os_str().to_os_string()]));
        }
        if path.exists() {
            return Some((
                "explorer.exe",
                vec![OsString::from("/select,"), path.as_os_str().to_os_string()],
            ));
        }
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty())?;
        return parent
            .is_dir()
            .then(|| ("explorer.exe", vec![parent.as_os_str().to_os_string()]));
    }

    #[cfg(target_os = "macos")]
    {
        if path.is_dir() {
            return Some(("open", vec![path.as_os_str().to_os_string()]));
        }
        if path.exists() {
            return Some((
                "open",
                vec![OsString::from("-R"), path.as_os_str().to_os_string()],
            ));
        }
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty())?;
        return parent
            .is_dir()
            .then(|| ("open", vec![parent.as_os_str().to_os_string()]));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let target = if path.is_dir() {
            Some(path)
        } else {
            path.parent()
                .filter(|p| !p.as_os_str().is_empty() && p.is_dir())
        }?;
        return Some(("xdg-open", vec![target.as_os_str().to_os_string()]));
    }

    #[allow(unreachable_code)]
    None
}

pub fn reveal_in_file_manager(path: &Path) -> Result<(), String> {
    let Some((prog, args)) = reveal_command_spec(path) else {
        return Err(format!("Path does not exist: {}", path.display()));
    };
    Command::new(prog)
        .args(args)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("{prog}: {e}"))
}
