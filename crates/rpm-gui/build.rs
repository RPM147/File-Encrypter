use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ico_path = manifest_dir.join("assets").join("icon.ico");
    if !ico_path.is_file() {
        println!("cargo:warning=Missing icon asset at {}", ico_path.display());
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let rc_path = out_dir.join("rpm_gui.rc");
    let ico_norm = ico_path.to_string_lossy().replace('\\', "/");

    let pkg_ver = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let parse_part = |key: &str| -> u16 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(0)
    };
    let ver_major = parse_part("CARGO_PKG_VERSION_MAJOR");
    let ver_minor = parse_part("CARGO_PKG_VERSION_MINOR");
    let ver_patch = parse_part("CARGO_PKG_VERSION_PATCH");

    let rc_content = format!(
        r#"1 ICON "{ico_norm}"

1 VERSIONINFO
FILEVERSION {ver_major},{ver_minor},{ver_patch},0
PRODUCTVERSION {ver_major},{ver_minor},{ver_patch},0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "RPM Encrypter"
            VALUE "FileDescription", "RPM Encrypter (Vault Format v5)"
            VALUE "FileVersion", "{pkg_ver}"
            VALUE "InternalName", "rpm-encrypter"
            VALUE "LegalCopyright", "AGPL-3.0-or-later"
            VALUE "OriginalFilename", "rpm-encrypter.exe"
            VALUE "ProductName", "RPM Encrypter"
            VALUE "ProductVersion", "{pkg_ver}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"#
    );

    if let Err(err) = fs::write(&rc_path, rc_content) {
        println!("cargo:warning=Could not write RC file: {err}");
        return;
    }

    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "gnu" {
        let obj_path = out_dir.join("rpm_gui_res.o");
        for tool in ["x86_64-w64-mingw32-windres", "windres", "llvm-windres"] {
            if let Ok(status) = Command::new(tool)
                .args(["-i"])
                .arg(&rc_path)
                .args(["-O", "coff", "-o"])
                .arg(&obj_path)
                .status()
            {
                if status.success() {
                    println!(
                        "cargo:rustc-link-arg-bin=rpm-encrypter={}",
                        obj_path.display()
                    );
                    return;
                }
            }
        }
        println!(
            "cargo:warning=windres not found; building without embedded Windows icon/metadata"
        );
    } else if target_env == "msvc" {
        let res_path = out_dir.join("rpm_gui.res");
        if let Some(rc_exe) = find_msvc_rc() {
            if let Ok(status) = Command::new(&rc_exe)
                .arg("/nologo")
                .arg("/fo")
                .arg(&res_path)
                .arg(&rc_path)
                .status()
            {
                if status.success() {
                    println!(
                        "cargo:rustc-link-arg-bin=rpm-encrypter={}",
                        res_path.display()
                    );
                    return;
                }
            }
        }
        println!("cargo:warning=rc.exe not found; building without embedded Windows icon/metadata");
    }
}

fn find_msvc_rc() -> Option<PathBuf> {
    if Command::new("rc.exe").arg("/?").output().is_ok() {
        return Some(PathBuf::from("rc.exe"));
    }
    let kits_root = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let entries = fs::read_dir(kits_root).ok()?;
    let mut versions: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    versions.sort();
    versions.reverse();

    let arch_dir = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86") => "x86",
        Ok("aarch64") => "arm64",
        _ => "x64",
    };
    for ver in versions {
        let candidate = ver.join(arch_dir).join("rc.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
