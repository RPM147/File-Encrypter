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
    assert!(integ["chunk_count"].as_u64().unwrap() >= 1);

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
        fs::read(dec_out.join("report.txt")).unwrap(),
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

#[test]
fn cli_recovery_rekey_keyfile_and_corrupt_integrity_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("notes.md");
    fs::write(&src, b"recovery + rekey keyfile e2e").unwrap();

    let vaults_dir = dir.path().join("v");
    fs::create_dir_all(&vaults_dir).unwrap();
    let rec_file = dir.path().join("rec.txt");
    let kf2 = dir.path().join("second.key");
    fs::write(&kf2, b"second-keyfile-entropy").unwrap();

    // 1. Encrypt without keyfile
    assert_eq!(
        run_cli_args(
            [
                "rpm-encrypter-cli",
                "encrypt",
                src.to_str().unwrap(),
                "-o",
                vaults_dir.to_str().unwrap(),
                "--recovery-out",
                rec_file.to_str().unwrap(),
                "--password-stdin",
            ],
            &mut Cursor::new(b"Alpha!1\n".to_vec()),
            &mut Vec::new(),
            &mut Vec::new(),
            Some(KdfParams::fast_test()),
        ),
        0
    );
    let vault = vaults_dir.join("notes.md.vault");
    let phrase = fs::read_to_string(&rec_file).unwrap();

    // 2. Re-key adding a new keyfile
    assert_eq!(
        run_cli_args(
            [
                "rpm-encrypter-cli",
                "rekey",
                vault.to_str().unwrap(),
                "--new-keyfile",
                kf2.to_str().unwrap(),
                "--password-stdin",
            ],
            &mut Cursor::new(b"Alpha!1\nBeta!2\n".to_vec()),
            &mut Vec::new(),
            &mut Vec::new(),
            Some(KdfParams::fast_test()),
        ),
        0
    );

    // 3. Decrypt via --recovery-stdin directly (bypasses password & keyfile)
    let out_rec = dir.path().join("rec_dec");
    fs::create_dir_all(&out_rec).unwrap();
    assert_eq!(
        run_cli_args(
            [
                "rpm-encrypter-cli",
                "decrypt",
                vault.to_str().unwrap(),
                "-o",
                out_rec.to_str().unwrap(),
                "--recovery-stdin",
            ],
            &mut Cursor::new(phrase.as_bytes().to_vec()),
            &mut Vec::new(),
            &mut Vec::new(),
            Some(KdfParams::fast_test()),
        ),
        0
    );
    assert_eq!(
        fs::read(out_rec.join("notes.md")).unwrap(),
        b"recovery + rekey keyfile e2e"
    );

    // 4. Inspect via --recovery-stdin JSON
    let mut inspect_out = Vec::new();
    assert_eq!(
        run_cli_args(
            [
                "rpm-encrypter-cli",
                "inspect",
                vault.to_str().unwrap(),
                "--json",
                "--recovery-stdin",
            ],
            &mut Cursor::new(phrase.as_bytes().to_vec()),
            &mut inspect_out,
            &mut Vec::new(),
            Some(KdfParams::fast_test()),
        ),
        0
    );
    let info: serde_json::Value = serde_json::from_slice(&inspect_out).unwrap();
    assert_eq!(info["has_keyfile"], true);
    assert_eq!(info["metadata"]["filename"], "notes.md");

    // 5. Corrupt integrity_only returns exit code 1
    let mut corrupted = fs::read(&vault).unwrap();
    corrupted.push(0x00);
    fs::write(&vault, corrupted).unwrap();
    let mut bad_json = Vec::new();
    assert_eq!(
        run_cli_args(
            [
                "rpm-encrypter-cli",
                "inspect",
                vault.to_str().unwrap(),
                "--integrity-only",
                "--json",
            ],
            &mut Cursor::new(Vec::new()),
            &mut bad_json,
            &mut Vec::new(),
            None,
        ),
        1
    );
    let bad_val: serde_json::Value = serde_json::from_slice(&bad_json).unwrap();
    assert_eq!(bad_val["ok"], false);
}

#[test]
fn cli_selective_decrypt_with_only_flag_and_errors() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("bundle");
    fs::create_dir_all(folder.join("sub")).unwrap();
    fs::write(folder.join("keep.txt"), b"kept").unwrap();
    fs::write(folder.join("skip.txt"), b"skipped").unwrap();
    fs::write(folder.join("sub/deep.txt"), b"deep-kept").unwrap();

    let vaults = dir.path().join("vaults");
    fs::create_dir_all(&vaults).unwrap();
    assert_eq!(
        run_cli_args(
            [
                "rpm-encrypter-cli",
                "encrypt",
                folder.to_str().unwrap(),
                "-o",
                vaults.to_str().unwrap(),
                "--password-stdin",
            ],
            &mut Cursor::new(b"CliSel!1\n".to_vec()),
            &mut Vec::new(),
            &mut Vec::new(),
            Some(KdfParams::fast_test()),
        ),
        0
    );
    let vault = vaults.join("bundle.vault");

    let out_dir = dir.path().join("sel_out");
    fs::create_dir_all(&out_dir).unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "decrypt",
            vault.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
            "--only",
            "bundle/keep.txt",
            "--only",
            "bundle/sub",
            "--password-stdin",
        ],
        &mut Cursor::new(b"CliSel!1\n".to_vec()),
        &mut stdout,
        &mut stderr,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&stderr));
    assert_eq!(fs::read(out_dir.join("bundle/keep.txt")).unwrap(), b"kept");
    assert_eq!(
        fs::read(out_dir.join("bundle/sub/deep.txt")).unwrap(),
        b"deep-kept"
    );
    assert!(!out_dir.join("bundle/skip.txt").exists());

    // Passing --only with multiple vaults returns exit code 1 cleanly
    assert_eq!(
        run_cli_args(
            [
                "rpm-encrypter-cli",
                "decrypt",
                vault.to_str().unwrap(),
                vault.to_str().unwrap(),
                "--only",
                "bundle/keep.txt",
                "--password-stdin",
            ],
            &mut Cursor::new(b"CliSel!1\n".to_vec()),
            &mut Vec::new(),
            &mut Vec::new(),
            None,
        ),
        1
    );
}
