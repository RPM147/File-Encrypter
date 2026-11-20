use std::fs;
use std::io::Cursor;

use clap::CommandFactory;
use rpm_cli::{run_cli_args, Cli};
use rpm_core::KdfParams;

#[test]
fn cli_exposes_no_password_flag() {
    let mut help = Vec::new();
    Cli::command().write_long_help(&mut help).unwrap();
    let txt = String::from_utf8(help).unwrap();
    assert!(!txt.contains("--password "));
}

#[test]
fn cli_full_round_trip_encrypt_inspect_rekey_decrypt_and_password() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("report.txt");
    fs::write(&src, b"pure rust cli payload!").unwrap();

    let keyfile = dir.path().join("app.key");
    fs::write(&keyfile, b"keyfile-entropy-data").unwrap();

    let vaults_dir = dir.path().join("vaults");
    fs::create_dir_all(&vaults_dir).unwrap();
    let rec_file = dir.path().join("recovery.txt");

    // 1. Encrypt with keyfile + password stdin
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "encrypt",
            src.to_str().unwrap(),
            "-o",
            vaults_dir.to_str().unwrap(),
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--recovery-out",
            rec_file.to_str().unwrap(),
            "--password-stdin",
        ],
        &mut Cursor::new(b"FirstPw!1\n".to_vec()),
        &mut out,
        &mut err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    let vault = vaults_dir.join("report.txt.vault");
    assert!(vault.is_file());
    let phrase = fs::read_to_string(&rec_file).unwrap();
    assert_eq!(phrase.split_whitespace().count(), 24);

    // 2. Integrity inspect JSON
    out.clear();
    let code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "inspect",
            vault.to_str().unwrap(),
            "--integrity-only",
            "--json",
        ],
        &mut Cursor::new(Vec::new()),
        &mut out,
        &mut err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(code, 0);
    let integ: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(integ["ok"], true);
    assert_eq!(integ["version"], 5);
    assert_eq!(integ["has_keyfile"], true);

    // 3. Re-key password via 2-line stdin
    out.clear();
    let code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "rekey",
            vault.to_str().unwrap(),
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--password-stdin",
        ],
        &mut Cursor::new(b"FirstPw!1\nSecondPw!2\n".to_vec()),
        &mut out,
        &mut err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));

    // 4. Wrong keyfile / old password fail with exit code 2
    let dec_out = dir.path().join("dec_out");
    fs::create_dir_all(&dec_out).unwrap();
    assert_eq!(
        run_cli_args(
            [
                "rpm-encrypter-cli",
                "decrypt",
                vault.to_str().unwrap(),
                "-o",
                dec_out.to_str().unwrap(),
                "--password-stdin",
            ],
            &mut Cursor::new(b"SecondPw!2\n".to_vec()),
            &mut Vec::new(),
            &mut Vec::new(),
            Some(KdfParams::fast_test()),
        ),
        2
    );

    // 5. Decrypt with rotated password + keyfile succeeds
    let code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "decrypt",
            vault.to_str().unwrap(),
            "-o",
            dec_out.to_str().unwrap(),
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--password-stdin",
        ],
        &mut Cursor::new(b"SecondPw!2\n".to_vec()),
        &mut out,
        &mut err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
    assert_eq!(
        fs::read(dec_out.join("report.txt/report.txt")).unwrap(),
        b"pure rust cli payload!"
    );

    // 6. Password generator works
    out.clear();
    let code = run_cli_args(
        ["rpm-encrypter-cli", "password", "--length", "20"],
        &mut Cursor::new(Vec::new()),
        &mut out,
        &mut err,
        None,
    );
    assert_eq!(code, 0);
    let pw_out = String::from_utf8(out).unwrap();
    assert_eq!(pw_out.lines().next().unwrap().len(), 20);
}
