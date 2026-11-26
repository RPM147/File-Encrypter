use rpm_core::KdfParams;
use std::{
    fs,
    io::{Cursor, Write},
    path::Path,
    process::{Command, Output, Stdio},
};

fn fixture(dir: &Path, name: &str) -> String {
    let file = dir.join(name);
    let key = dir.join(format!("{name}.key"));
    let phrase = dir.join(format!("{name}.phrase"));
    fs::write(&file, name).unwrap();
    fs::write(&key, format!("{name}-key")).unwrap();
    let mut errors = Vec::new();
    assert_eq!(
        rpm_cli::run_cli_args(
            [
                "cli",
                "encrypt",
                file.to_str().unwrap(),
                "--keyfile",
                key.to_str().unwrap(),
                "--recovery-out",
                phrase.to_str().unwrap(),
                "--password-stdin"
            ],
            &mut Cursor::new(name),
            &mut Vec::new(),
            &mut errors,
            Some(KdfParams::fast_test())
        ),
        0,
        "{}",
        String::from_utf8_lossy(&errors)
    );
    let path = dir.join(format!("{name}.vault"));
    let data = fs::read(&path).unwrap();
    let (_, _, end) = rpm_core::header::read_header_and_meta(&mut data.as_slice()).unwrap();
    fs::write(path, &data[..end as usize]).unwrap(); // No payload is available to either comparison.
    fs::read_to_string(phrase).unwrap().trim().into()
}

fn compare(dir: &Path, args: &[&str], credentials: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rpm-encrypter-cli"))
        .current_dir(dir)
        .args(["diff", "a.vault", "b.vault", "--password-stdin"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(err) = child
        .stdin
        .take()
        .unwrap()
        .write_all(credentials.as_bytes())
    {
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::BrokenPipe,
            "unexpected stdin write error: {err}"
        );
    }
    child.wait_with_output().unwrap()
}

#[test]
fn compare_headers_with_separate_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let a = fixture(dir.path(), "a");
    let b = fixture(dir.path(), "b");
    let keys = ["--keyfile-a", "a.key", "--keyfile-b", "b.key", "--json"];
    for (args, secrets) in [
        (keys.as_slice(), "a\nb\n".to_owned()),
        (
            &["--recovery-a", "--keyfile-b", "b.key", "--json"][..],
            format!("{a}\nb\n"),
        ),
        (
            &["--keyfile-a", "a.key", "--recovery-b", "--json"][..],
            format!("a\n{b}\n"),
        ),
    ] {
        let output = compare(dir.path(), args, &secrets);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["removed"][0]["path"], "a");
        assert_eq!(result["added"][0]["path"], "b");
    }
    let plain = compare(
        dir.path(),
        &["--recovery-a", "--recovery-b"],
        &format!("{a}\n{b}\n"),
    );
    assert!(plain.status.success());
    assert!(String::from_utf8(plain.stdout)
        .unwrap()
        .contains("Added (1)"));
    let failed = compare(dir.path(), &keys, "a\nwrong\n");
    assert_eq!(failed.status.code(), Some(2));
    assert!(failed.stdout.is_empty());

    let missing = Command::new(env!("CARGO_BIN_EXE_rpm-encrypter-cli"))
        .current_dir(dir.path())
        .args(["diff", "missing.vault", "b.vault", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("vault not found:"));
}

#[test]
fn diff_threads_flag_handles_rs_vaults_and_rejects_out_of_range() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = dir.path().join("manifest_src");
    fs::create_dir(&src_dir).unwrap();

    // Create enough files with ~80-byte names so the encrypted manifest spans multiple RS blocks
    // (each RS block holds 15,292 bytes of inner stream), exercising multi-block RS decode paths.
    let pad = "a".repeat(64);
    for i in 0..320usize {
        let name = format!("entry_{i:04}_{pad}.txt");
        fs::write(src_dir.join(name), b"v1").unwrap();
    }
    let removed_name = format!("entry_0000_{pad}.txt");
    let changed_name = format!("entry_0001_{pad}.txt");
    let added_name = format!("entry_9999_{pad}.txt");

    let out_a = dir.path().join("out_a");
    let out_b = dir.path().join("out_b");
    fs::create_dir(&out_a).unwrap();
    fs::create_dir(&out_b).unwrap();

    let mut err = Vec::new();
    let code = rpm_cli::run_cli_args(
        [
            "cli",
            "encrypt",
            src_dir.to_str().unwrap(),
            "-o",
            out_a.to_str().unwrap(),
            "--reed-solomon",
            "--no-compress",
            "--threads",
            "4",
            "--password-stdin",
        ],
        &mut Cursor::new(b"pw-a\n".to_vec()),
        &mut Vec::new(),
        &mut err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(
        code,
        0,
        "encrypt A failed: {}",
        String::from_utf8_lossy(&err)
    );

    // Mutate source folder deterministically while leaving unchanged files untouched on disk.
    fs::remove_file(src_dir.join(&removed_name)).unwrap();
    fs::write(src_dir.join(&changed_name), b"v2-modified-content").unwrap();
    fs::write(src_dir.join(&added_name), b"new-entry").unwrap();

    err.clear();
    let code = rpm_cli::run_cli_args(
        [
            "cli",
            "encrypt",
            src_dir.to_str().unwrap(),
            "-o",
            out_b.to_str().unwrap(),
            "--reed-solomon",
            "--no-compress",
            "--threads",
            "4",
            "--password-stdin",
        ],
        &mut Cursor::new(b"pw-b\n".to_vec()),
        &mut Vec::new(),
        &mut err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(
        code,
        0,
        "encrypt B failed: {}",
        String::from_utf8_lossy(&err)
    );

    let vault_a = out_a.join("manifest_src.vault");
    let vault_b = out_b.join("manifest_src.vault");

    // Ensure the RS vaults contain at least 4 RS blocks and inject recoverable bit-rot across
    // header/metadata blocks 0, 1, and 2 in both vaults.
    const RS_HEADER_LEN: usize = 48;
    const RS_BLOCK_WIRE: usize = 16_320;
    for vault in [&vault_a, &vault_b] {
        let mut bytes = fs::read(vault).unwrap();
        assert!(
            bytes.len() >= RS_HEADER_LEN + 4 * RS_BLOCK_WIRE,
            "expected multi-block RS vault (>= 4 blocks), got {} bytes",
            bytes.len()
        );
        for blk in 0..3 {
            let start = RS_HEADER_LEN + blk * RS_BLOCK_WIRE + 64;
            for b in &mut bytes[start..start + 400] {
                *b ^= 0x5A;
            }
        }
        fs::write(vault, &bytes).unwrap();
    }

    // Verify --threads 0 (auto), 1 (single-threaded), 4 (multi-threaded), and MAX_PIPELINE_THREADS
    // all succeed and produce identical JSON diff output on the damaged multi-block RS vaults.
    let max_threads = rpm_core::MAX_PIPELINE_THREADS.to_string();
    let mut baseline: Option<serde_json::Value> = None;
    for threads in ["0", "1", "4", max_threads.as_str()] {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = rpm_cli::run_cli_args(
            [
                "cli",
                "diff",
                vault_a.to_str().unwrap(),
                vault_b.to_str().unwrap(),
                "--password-stdin",
                "--json",
                "--threads",
                threads,
            ],
            &mut Cursor::new(b"pw-a\npw-b\n".to_vec()),
            &mut out,
            &mut err,
            Some(KdfParams::fast_test()),
        );
        assert_eq!(
            code,
            0,
            "diff --threads {threads} failed: {}",
            String::from_utf8_lossy(&err)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["added"].as_array().unwrap().len(), 1);
        assert!(parsed["added"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with(&added_name));
        assert_eq!(parsed["removed"].as_array().unwrap().len(), 1);
        assert!(parsed["removed"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with(&removed_name));
        assert_eq!(parsed["changed"].as_array().unwrap().len(), 1);
        assert!(parsed["changed"][0]["after"]["path"]
            .as_str()
            .unwrap()
            .ends_with(&changed_name));
        assert_eq!(parsed["unchanged"].as_array().unwrap().len(), 318);
        if let Some(ref expected) = baseline {
            assert_eq!(
                &parsed, expected,
                "diff output diverged for --threads {threads}"
            );
        } else {
            baseline = Some(parsed);
        }
    }

    // Verify the compiled CLI binary accepts valid --threads and rejects out-of-range values.
    let mut bin_ok = Command::new(env!("CARGO_BIN_EXE_rpm-encrypter-cli"))
        .args([
            "diff",
            vault_a.to_str().unwrap(),
            vault_b.to_str().unwrap(),
            "--password-stdin",
            "--json",
            "--threads",
            "4",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    bin_ok
        .stdin
        .take()
        .unwrap()
        .write_all(b"pw-a\npw-b\n")
        .unwrap();
    let bin_out = bin_ok.wait_with_output().unwrap();
    assert!(
        bin_out.status.success(),
        "binary diff --threads 4 failed: {}",
        String::from_utf8_lossy(&bin_out.stderr)
    );
    let bin_json: serde_json::Value = serde_json::from_slice(&bin_out.stdout).unwrap();
    assert_eq!(Some(bin_json), baseline);

    // Out-of-range --threads values rejected by clap with exit code 2.
    let over_max = (rpm_core::MAX_PIPELINE_THREADS + 1).to_string();
    for bad in [over_max.as_str(), "999", "-1", "abc"] {
        let mut err = Vec::new();
        let code = rpm_cli::run_cli_args(
            [
                "cli",
                "diff",
                vault_a.to_str().unwrap(),
                vault_b.to_str().unwrap(),
                "--password-stdin",
                "--threads",
                bad,
            ],
            &mut Cursor::new(b"pw-a\npw-b\n".to_vec()),
            &mut Vec::new(),
            &mut err,
            Some(KdfParams::fast_test()),
        );
        assert_eq!(
            code,
            2,
            "expected clap exit code 2 for --threads {bad}, stderr: {}",
            String::from_utf8_lossy(&err)
        );
    }

    let bin_bad = Command::new(env!("CARGO_BIN_EXE_rpm-encrypter-cli"))
        .args([
            "diff",
            vault_a.to_str().unwrap(),
            vault_b.to_str().unwrap(),
            "--threads",
            over_max.as_str(),
        ])
        .output()
        .unwrap();
    assert_eq!(bin_bad.status.code(), Some(2));
}

#[test]
fn diff_threads_split_hidden_rs_and_unrecoverable_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let decoy_dir = dir.path().join("decoy_src");
    let hidden_dir = dir.path().join("hidden_src");
    fs::create_dir(&decoy_dir).unwrap();
    fs::create_dir(&hidden_dir).unwrap();

    // Create multi-block manifests (> 30 KiB each -> >= 3 RS blocks per manifest)
    // while keeping total tar size comfortably inside a 2 MiB padded container.
    let pad = "x".repeat(64);
    for i in 0..240usize {
        fs::write(decoy_dir.join(format!("decoy_{i:04}_{pad}.txt")), b"d").unwrap();
        fs::write(hidden_dir.join(format!("hidden_{i:04}_{pad}.txt")), b"h").unwrap();
    }

    let out_dir = dir.path().join("split_out");
    fs::create_dir(&out_dir).unwrap();
    let mut err = Vec::new();
    let code = rpm_cli::run_cli_args(
        [
            "cli",
            "encrypt",
            decoy_dir.to_str().unwrap(),
            "--hidden",
            hidden_dir.to_str().unwrap(),
            "--container-mb",
            "2",
            "--split-mb",
            "1",
            "--reed-solomon",
            "--threads",
            "4",
            "-o",
            out_dir.to_str().unwrap(),
            "--password-stdin",
        ],
        &mut Cursor::new(b"outer-pw\nhidden-pw\n".to_vec()),
        &mut Vec::new(),
        &mut err,
        Some(KdfParams::fast_test()),
    );
    assert_eq!(
        code,
        0,
        "split hidden RS encrypt failed: {}",
        String::from_utf8_lossy(&err)
    );

    let part1 = out_dir.join("decoy_src.vault.001");
    let part2 = out_dir.join("decoy_src.vault.002");
    let part3 = out_dir.join("decoy_src.vault.003");
    assert!(part1.is_file() && part2.is_file() && part3.is_file());

    // Inject recoverable 400-byte bit-rot into RS block 1 (outer header manifest in .001)
    // and into the trailing RS block in .003 (containing the hidden mini-header).
    const RS_HEADER_LEN: usize = 48;
    const RS_BLOCK_WIRE: usize = 16_320;
    {
        let mut p1 = fs::read(&part1).unwrap();
        let blk1_off = RS_HEADER_LEN + RS_BLOCK_WIRE + 32;
        for b in &mut p1[blk1_off..blk1_off + 400] {
            *b ^= 0x3C;
        }
        fs::write(&part1, &p1).unwrap();

        let mut p3 = fs::read(&part3).unwrap();
        let tail_start = p3.len() - RS_BLOCK_WIRE + 32;
        for b in &mut p3[tail_start..tail_start + 400] {
            *b ^= 0x69;
        }
        fs::write(&part3, &p3).unwrap();
    }

    // 1. Diff outer compartment vs hidden compartment across split RS parts with threads=1, 4, MAX.
    let max_threads = rpm_core::MAX_PIPELINE_THREADS.to_string();
    let mut baseline: Option<serde_json::Value> = None;
    for threads in ["1", "4", max_threads.as_str()] {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = rpm_cli::run_cli_args(
            [
                "cli",
                "diff",
                part1.to_str().unwrap(),
                part2.to_str().unwrap(),
                "--password-stdin",
                "--json",
                "--threads",
                threads,
            ],
            &mut Cursor::new(b"outer-pw\nhidden-pw\n".to_vec()),
            &mut out,
            &mut err,
            Some(KdfParams::fast_test()),
        );
        assert_eq!(
            code,
            0,
            "split hidden RS diff --threads {threads} failed: {}",
            String::from_utf8_lossy(&err)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["removed"].as_array().unwrap().len(), 240);
        assert_eq!(parsed["added"].as_array().unwrap().len(), 240);
        assert!(parsed["changed"].as_array().unwrap().is_empty());
        assert!(parsed["unchanged"].as_array().unwrap().is_empty());
        if let Some(ref expected) = baseline {
            assert_eq!(
                &parsed, expected,
                "split hidden RS diff diverged for --threads {threads}"
            );
        } else {
            baseline = Some(parsed);
        }
    }

    // 2. Inject UNRECOVERABLE 1024-byte damage into a payload block (RS block 6 in .001,
    // inside the multi-thread prefetch window 1..17, outside the 3-block outer header):
    // header-only `diff --threads 4` must still succeed identically to `--threads 1`.
    {
        let mut p1 = fs::read(&part1).unwrap();
        let payload_blk_off = RS_HEADER_LEN + 6 * RS_BLOCK_WIRE;
        for b in &mut p1[payload_blk_off..payload_blk_off + 1024] {
            *b ^= 0xFF;
        }
        fs::write(&part1, &p1).unwrap();
    }
    for threads in ["1", "4"] {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = rpm_cli::run_cli_args(
            [
                "cli",
                "diff",
                part1.to_str().unwrap(),
                part1.to_str().unwrap(),
                "--password-stdin",
                "--json",
                "--threads",
                threads,
            ],
            &mut Cursor::new(b"outer-pw\nouter-pw\n".to_vec()),
            &mut out,
            &mut err,
            Some(KdfParams::fast_test()),
        );
        assert_eq!(
            code,
            0,
            "payload-only unrecoverable block should not break header diff --threads {threads}: {}",
            String::from_utf8_lossy(&err)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["unchanged"].as_array().unwrap().len(), 240);
    }

    // 3. Inject UNRECOVERABLE 1024-byte damage into HEADER block 1 (inside outer manifest):
    // both `--threads 1` and `--threads 4` must fail cleanly with exit code 1 (no hang/panic).
    {
        let mut p1 = fs::read(&part1).unwrap();
        let hdr_blk1_off = RS_HEADER_LEN + RS_BLOCK_WIRE;
        for b in &mut p1[hdr_blk1_off..hdr_blk1_off + 1024] {
            *b ^= 0xAA;
        }
        fs::write(&part1, &p1).unwrap();
    }
    for threads in ["1", "4"] {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = rpm_cli::run_cli_args(
            [
                "cli",
                "diff",
                part1.to_str().unwrap(),
                part1.to_str().unwrap(),
                "--password-stdin",
                "--json",
                "--threads",
                threads,
            ],
            &mut Cursor::new(b"outer-pw\nouter-pw\n".to_vec()),
            &mut out,
            &mut err,
            Some(KdfParams::fast_test()),
        );
        assert_eq!(
            code,
            1,
            "expected exit code 1 on unrecoverable header corruption (threads={threads}), stderr={}",
            String::from_utf8_lossy(&err)
        );
        assert!(out.is_empty(), "stdout must stay empty on error");
        let stderr_text = String::from_utf8_lossy(&err);
        assert!(
            stderr_text.contains("Error comparing vaults:"),
            "unexpected stderr: {stderr_text}"
        );
    }
}
