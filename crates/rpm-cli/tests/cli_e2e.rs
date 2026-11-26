use std::fs;
use std::io::Cursor;
use std::time::{Duration, Instant};

use clap::CommandFactory;
use rpm_cli::progress::{
    format_bytes, format_eta, format_progress_line, format_rate, CliProgressMeter,
};
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

#[test]
fn cli_progress_modes_and_meter_formatting() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("payload.bin");
    fs::write(&src, vec![0xABu8; 4096]).unwrap();
    let vaults = dir.path().join("vaults");
    fs::create_dir_all(&vaults).unwrap();

    // 1. --progress always emits progress lines on stderr without polluting stdout
    let mut enc_out = Vec::new();
    let mut enc_err = Vec::new();
    let code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "encrypt",
            src.to_str().unwrap(),
            "-o",
            vaults.to_str().unwrap(),
            "--password-stdin",
            "--progress",
            "always",
        ],
        &mut Cursor::new(b"ProgPw!1\n".to_vec()),
        &mut enc_out,
        &mut enc_err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&enc_err));
    let enc_stdout = String::from_utf8(enc_out).unwrap();
    let enc_stderr = String::from_utf8(enc_err).unwrap();
    assert!(enc_stdout.starts_with("Encrypted: "));
    assert!(
        enc_stderr.contains("Encrypting:") && enc_stderr.contains('%'),
        "expected progress lines in stderr, got: {enc_stderr:?}"
    );
    assert!(!enc_stdout.contains("Encrypting:"));

    let vault = vaults.join("payload.bin.vault");

    // 2. Default (--progress auto) with non-TTY stderr emits zero progress lines
    let out_auto = dir.path().join("out_auto");
    fs::create_dir_all(&out_auto).unwrap();
    let mut auto_out = Vec::new();
    let mut auto_err = Vec::new();
    let code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "decrypt",
            vault.to_str().unwrap(),
            "-o",
            out_auto.to_str().unwrap(),
            "--password-stdin",
        ],
        &mut Cursor::new(b"ProgPw!1\n".to_vec()),
        &mut auto_out,
        &mut auto_err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&auto_err));
    assert!(
        auto_err.is_empty(),
        "expected empty stderr under non-TTY auto mode, got: {}",
        String::from_utf8_lossy(&auto_err)
    );

    // 3. --progress never emits zero progress lines, while --progress always emits Decrypting
    let out_never = dir.path().join("out_never");
    fs::create_dir_all(&out_never).unwrap();
    let mut never_err = Vec::new();
    assert_eq!(
        run_cli_args(
            [
                "rpm-encrypter-cli",
                "decrypt",
                vault.to_str().unwrap(),
                "-o",
                out_never.to_str().unwrap(),
                "--password-stdin",
                "--progress",
                "never",
            ],
            &mut Cursor::new(b"ProgPw!1\n".to_vec()),
            &mut Vec::new(),
            &mut never_err,
            Some(KdfParams::fast_test()),
        ),
        0
    );
    assert!(never_err.is_empty());

    let out_always = dir.path().join("out_always");
    fs::create_dir_all(&out_always).unwrap();
    let mut dec_err = Vec::new();
    assert_eq!(
        run_cli_args(
            [
                "rpm-encrypter-cli",
                "decrypt",
                vault.to_str().unwrap(),
                "-o",
                out_always.to_str().unwrap(),
                "--password-stdin",
                "--progress",
                "always",
            ],
            &mut Cursor::new(b"ProgPw!1\n".to_vec()),
            &mut Vec::new(),
            &mut dec_err,
            Some(KdfParams::fast_test()),
        ),
        0
    );
    let dec_stderr = String::from_utf8(dec_err).unwrap();
    assert!(dec_stderr.contains("Decrypting:") && dec_stderr.contains('%'));

    // 4. Deterministic CliProgressMeter clamping & formatting
    let t0 = Instant::now();
    let mut meter = CliProgressMeter::new(t0);
    let snap1 = meter.update_at(
        t0 + Duration::from_secs(1),
        2 * 1024 * 1024,
        8 * 1024 * 1024,
    );
    assert_eq!(snap1.percent, 25);
    assert!(snap1.bytes_per_sec.is_some());
    assert_eq!(snap1.eta, Some(Duration::from_secs(3)));
    let formatted = format_progress_line("[1/2] Decrypting", &snap1);
    assert!(formatted.contains("[1/2] Decrypting:  25%"));
    assert!(formatted.contains("MiB/s"));
    assert!(formatted.contains("ETA 3s"));

    let clamped = meter.update_at(
        t0 + Duration::from_secs(2),
        9 * 1024 * 1024,
        8 * 1024 * 1024,
    );
    assert_eq!(clamped.percent, 100);
    assert_eq!(clamped.bytes_done, 8 * 1024 * 1024);
    assert_eq!(clamped.eta, Some(Duration::ZERO));

    let mut zero_meter = CliProgressMeter::new(t0);
    let zero_snap = zero_meter.update_at(t0 + Duration::from_millis(80), 256, 0);
    assert_eq!(zero_snap.percent, 100);
    assert_eq!(zero_snap.eta, None);
    let zero_line = format_progress_line("Encrypting", &zero_snap);
    assert!(zero_line.contains("100% (256 B)"));

    assert_eq!(format_bytes(1024), "1.0 KiB");
    assert_eq!(format_rate(2.0 * 1024.0 * 1024.0), "2.0 MiB/s");
    assert_eq!(format_eta(Duration::from_secs(125)), "2m 05s");
    assert_eq!(format_eta(Duration::from_secs(3660)), "1h 01m");
}

fn extract_words_from_recovery_sheet(html: &str) -> Vec<String> {
    let marker = r#"<span class="word-text">"#;
    let mut words = Vec::new();
    let mut rest = html;
    while let Some(pos) = rest.find(marker) {
        let after = &rest[pos + marker.len()..];
        let end = after.find("</span>").expect("closing </span> for word");
        words.push(after[..end].to_owned());
        rest = &after[end + "</span>".len()..];
    }
    words
}

#[test]
fn cli_recovery_sheet_encrypt_round_trip_and_standalone_subcommand() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("secret.txt");
    let payload = b"recovery sheet offline round-trip payload!";
    fs::write(&src, payload).unwrap();

    let vaults_dir = dir.path().join("vaults");
    fs::create_dir_all(&vaults_dir).unwrap();
    let sheet_tr = dir.path().join("cards").join("secret-tr.html");

    // 1. Help must never expose a --phrase / --recovery-phrase flag (INV-02)
    let mut rs_help_out = Vec::new();
    let mut rs_help_err = Vec::new();
    let help_code = run_cli_args(
        ["rpm-encrypter-cli", "recovery-sheet", "--help"],
        &mut Cursor::new(Vec::new()),
        &mut rs_help_out,
        &mut rs_help_err,
        None,
    );
    assert_eq!(help_code, 0);
    let help_txt = String::from_utf8(rs_help_out).unwrap();
    assert!(!help_txt.contains("--phrase"));
    assert!(!help_txt.contains("--recovery-phrase"));

    // 2. --recovery-sheet-lang without --recovery-sheet is rejected by clap (exit 2)
    let mut lang_err = Vec::new();
    let lang_code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "encrypt",
            src.to_str().unwrap(),
            "--recovery-sheet-lang",
            "tr",
            "--password-stdin",
        ],
        &mut Cursor::new(b"Pw123!@#\n".to_vec()),
        &mut Vec::new(),
        &mut lang_err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(lang_code, 2);

    // 3. Encrypt with --recovery-sheet + --recovery-sheet-lang tr
    let mut enc_out = Vec::new();
    let mut enc_err = Vec::new();
    let enc_code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "encrypt",
            src.to_str().unwrap(),
            "-o",
            vaults_dir.to_str().unwrap(),
            "--recovery-sheet",
            sheet_tr.to_str().unwrap(),
            "--recovery-sheet-lang",
            "tr",
            "--password-stdin",
        ],
        &mut Cursor::new(b"SheetPw!2026\n".to_vec()),
        &mut enc_out,
        &mut enc_err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(enc_code, 0, "stderr: {}", String::from_utf8_lossy(&enc_err));
    let enc_stdout = String::from_utf8(enc_out).unwrap();
    assert!(enc_stdout.contains("Recovery sheet (HTML) written to:"));
    assert!(
        !enc_stdout.contains("IMPORTANT -"),
        "phrase must not be printed to stdout when --recovery-sheet is set: {enc_stdout}"
    );

    let html_tr = fs::read_to_string(&sheet_tr).unwrap();
    assert!(html_tr.contains(r#"<html lang="tr">"#));
    assert!(html_tr.contains("default-src 'none'; style-src 'unsafe-inline';"));
    assert!(!html_tr.contains("<script"));
    assert!(!html_tr.contains("http://") && !html_tr.contains("https://"));
    assert!(html_tr.contains("secret.txt.vault"));

    let words = extract_words_from_recovery_sheet(&html_tr);
    assert_eq!(words.len(), 24);
    let phrase = words.join(" ");
    assert!(!enc_stdout.contains(&phrase));

    // 4. Decrypt the created vault using ONLY the 24 words extracted from the HTML sheet
    let vault = vaults_dir.join("secret.txt.vault");
    assert!(vault.is_file());
    let dec_dir = dir.path().join("restored");
    fs::create_dir_all(&dec_dir).unwrap();
    let mut dec_err = Vec::new();
    let dec_code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "decrypt",
            vault.to_str().unwrap(),
            "-o",
            dec_dir.to_str().unwrap(),
            "--recovery-stdin",
        ],
        &mut Cursor::new(format!("{phrase}\n").into_bytes()),
        &mut Vec::new(),
        &mut dec_err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(dec_code, 0, "stderr: {}", String::from_utf8_lossy(&dec_err));
    assert_eq!(fs::read(dec_dir.join("secret.txt")).unwrap(), payload);

    // 5. Standalone `recovery-sheet` subcommand (EN + --has-keyfile)
    let sheet_en = dir.path().join("backup-en.html");
    let mut standalone_out = Vec::new();
    let mut standalone_err = Vec::new();
    let st_code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "recovery-sheet",
            "-o",
            sheet_en.to_str().unwrap(),
            "--vault-name",
            "Backup.vault",
            "--has-keyfile",
            "--lang",
            "en",
            "--recovery-stdin",
        ],
        &mut Cursor::new(format!("{phrase}\n").into_bytes()),
        &mut standalone_out,
        &mut standalone_err,
        None,
    );
    assert_eq!(
        st_code,
        0,
        "stderr: {}",
        String::from_utf8_lossy(&standalone_err)
    );
    let html_en = fs::read_to_string(&sheet_en).unwrap();
    assert!(html_en.contains(r#"<html lang="en">"#));
    assert!(html_en.contains("Backup.vault"));
    assert!(html_en.contains("Bound for password unlock — NOT required for 24-word recovery"));
    assert_eq!(extract_words_from_recovery_sheet(&html_en), words);

    // 6. Invalid mnemonic rejected cleanly without creating the file
    let bad_sheet = dir.path().join("bad.html");
    let bad_code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "recovery-sheet",
            "-o",
            bad_sheet.to_str().unwrap(),
            "--recovery-stdin",
        ],
        &mut Cursor::new(b"not a valid bip39 phrase\n".to_vec()),
        &mut Vec::new(),
        &mut Vec::new(),
        None,
    );
    assert_ne!(bad_code, 0);
    assert!(!bad_sheet.exists());

    // 7. --wipe refuses a --recovery-sheet target inside a wiped source folder without wiping
    let wipe_dir = dir.path().join("wipe_src");
    fs::create_dir_all(&wipe_dir).unwrap();
    let victim = wipe_dir.join("keep.txt");
    fs::write(&victim, b"must survive").unwrap();
    let safe_out = dir.path().join("safe_out");
    fs::create_dir_all(&safe_out).unwrap();
    let bad_target = wipe_dir.join("nested").join("sheet.html");
    let mut wipe_err = Vec::new();
    let wipe_code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "encrypt",
            wipe_dir.to_str().unwrap(),
            "-o",
            safe_out.to_str().unwrap(),
            "--wipe",
            "--recovery-sheet",
            bad_target.to_str().unwrap(),
            "--password-stdin",
        ],
        &mut Cursor::new(b"WipeGuard!1\n".to_vec()),
        &mut Vec::new(),
        &mut wipe_err,
        Some(KdfParams::fast_test()),
    );
    assert_ne!(wipe_code, 0);
    assert!(String::from_utf8_lossy(&wipe_err).contains("--wipe"));
    assert!(
        victim.is_file(),
        "source file must not be wiped on guard failure"
    );

    // 8. --recovery-out and --recovery-sheet pointing to the same path is rejected
    let dup = dir.path().join("same_target.html");
    let mut dup_err = Vec::new();
    let dup_code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "encrypt",
            src.to_str().unwrap(),
            "-o",
            safe_out.to_str().unwrap(),
            "--recovery-out",
            dup.to_str().unwrap(),
            "--recovery-sheet",
            dup.to_str().unwrap(),
            "--password-stdin",
        ],
        &mut Cursor::new(b"DupGuard!1\n".to_vec()),
        &mut Vec::new(),
        &mut dup_err,
        Some(KdfParams::fast_test()),
    );
    assert_ne!(dup_code, 0);
    assert!(String::from_utf8_lossy(&dup_err).contains("same path"));
}

#[test]
fn cli_threads_flag_works_across_encrypt_decrypt_inspect_and_repair() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("payload.bin");
    let data: Vec<u8> = (0..(256 * 1024 + 517)).map(|i| (i % 241) as u8).collect();
    fs::write(&src, &data).unwrap();

    let out_dir = dir.path().join("vaults");
    fs::create_dir(&out_dir).unwrap();

    // 1. Encrypt with RS + explicit --threads 4
    let mut enc_out = Vec::new();
    let mut enc_err = Vec::new();
    let code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "encrypt",
            src.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
            "--reed-solomon",
            "--no-compress",
            "--threads",
            "4",
            "--password-stdin",
        ],
        &mut Cursor::new(b"ThreadPw!1\n".to_vec()),
        &mut enc_out,
        &mut enc_err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(
        code,
        0,
        "encrypt failed: {}",
        String::from_utf8_lossy(&enc_err)
    );
    let vault = out_dir.join("payload.bin.vault");
    assert!(vault.is_file());

    // 2. Corrupt 512 bytes in block 1 and verify inspect --integrity-only --threads 2 detects & counts repairs
    let mut damaged = fs::read(&vault).unwrap();
    for b in &mut damaged[48 + 16320 + 10..48 + 16320 + 522] {
        *b ^= 0xA5;
    }
    fs::write(&vault, &damaged).unwrap();

    let mut ins_out = Vec::new();
    let mut ins_err = Vec::new();
    let code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "inspect",
            vault.to_str().unwrap(),
            "--integrity-only",
            "--json",
            "--threads",
            "2",
        ],
        &mut Cursor::new(Vec::<u8>::new()),
        &mut ins_out,
        &mut ins_err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(
        code,
        0,
        "inspect failed: {}",
        String::from_utf8_lossy(&ins_err)
    );
    let val: serde_json::Value = serde_json::from_slice(&ins_out).unwrap();
    assert_eq!(val["ok"], true);
    assert_eq!(val["rs_repaired_bytes"], 512);

    // 3. Repair with --threads 4
    let repaired = dir.path().join("repaired.vault");
    let mut rep_out = Vec::new();
    let mut rep_err = Vec::new();
    let code = run_cli_args(
        [
            "rpm-encrypter-cli",
            "repair",
            vault.to_str().unwrap(),
            "-o",
            repaired.to_str().unwrap(),
            "--json",
            "--threads",
            "4",
        ],
        &mut Cursor::new(Vec::<u8>::new()),
        &mut rep_out,
        &mut rep_err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(
        code,
        0,
        "repair failed: {}",
        String::from_utf8_lossy(&rep_err)
    );
    let rval: serde_json::Value = serde_json::from_slice(&rep_out).unwrap();
    assert_eq!(rval["repaired_bytes"], 512);

    // 4. Decrypt with --threads 1 and --threads 4 and verify identical payload
    for threads in ["1", "4"] {
        let dec_dir = dir.path().join(format!("dec_{threads}"));
        fs::create_dir(&dec_dir).unwrap();
        let mut dec_out = Vec::new();
        let mut dec_err = Vec::new();
        let code = run_cli_args(
            [
                "rpm-encrypter-cli",
                "decrypt",
                repaired.to_str().unwrap(),
                "-o",
                dec_dir.to_str().unwrap(),
                "--threads",
                threads,
                "--password-stdin",
            ],
            &mut Cursor::new(b"ThreadPw!1\n".to_vec()),
            &mut dec_out,
            &mut dec_err,
            Some(KdfParams::fast_test()),
        );
        assert_eq!(
            code,
            0,
            "decrypt threads={threads} failed: {}",
            String::from_utf8_lossy(&dec_err)
        );
        assert_eq!(fs::read(dec_dir.join("payload.bin")).unwrap(), data);
    }

    // 5. Diff damaged vs repaired RS vault with --threads 1 and --threads 4
    for threads in ["1", "4"] {
        let mut diff_out = Vec::new();
        let mut diff_err = Vec::new();
        let code = run_cli_args(
            [
                "rpm-encrypter-cli",
                "diff",
                vault.to_str().unwrap(),
                repaired.to_str().unwrap(),
                "--json",
                "--threads",
                threads,
                "--password-stdin",
            ],
            &mut Cursor::new(b"ThreadPw!1\nThreadPw!1\n".to_vec()),
            &mut diff_out,
            &mut diff_err,
            Some(KdfParams::fast_test()),
        );
        assert_eq!(
            code,
            0,
            "diff threads={threads} failed: {}",
            String::from_utf8_lossy(&diff_err)
        );
        let dval: serde_json::Value = serde_json::from_slice(&diff_out).unwrap();
        assert_eq!(dval["unchanged"][0]["path"], "payload.bin");
        assert!(dval["added"].as_array().unwrap().is_empty());
        assert!(dval["removed"].as_array().unwrap().is_empty());
        assert!(dval["changed"].as_array().unwrap().is_empty());
    }

    // 6. Out-of-range --threads rejected by clap with exit code 2
    for args in [
        vec![
            "rpm-encrypter-cli",
            "encrypt",
            src.to_str().unwrap(),
            "--threads",
            "999",
            "--password-stdin",
        ],
        vec![
            "rpm-encrypter-cli",
            "diff",
            vault.to_str().unwrap(),
            repaired.to_str().unwrap(),
            "--threads",
            "999",
            "--password-stdin",
        ],
    ] {
        let mut bad_err = Vec::new();
        let bad_code = run_cli_args(
            args,
            &mut Cursor::new(b"pw\npw\n".to_vec()),
            &mut Vec::new(),
            &mut bad_err,
            Some(KdfParams::fast_test()),
        );
        assert_eq!(bad_code, 2);
    }
}
