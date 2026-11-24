use std::fs;
use std::io::Cursor;

use rpm_cli::run_cli_args;
use rpm_core::KdfParams;

fn run(args: &[&str], input: &str) -> (i32, String, String) {
    let mut stdin = Cursor::new(input.as_bytes().to_vec());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run_cli_args(
        args,
        &mut stdin,
        &mut stdout,
        &mut stderr,
        Some(KdfParams::fast_test()),
    );
    (
        code,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

fn pseudo_random_bytes(len: usize, seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u32 = u32::from(seed).wrapping_mul(0x9E37_79B1) ^ 0xA5A5_5A5A;
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state & 0xFF) as u8);
    }
    out
}

#[test]
fn cli_split_encrypt_inspect_diff_rekey_decrypt_and_standalone_split_join() {
    let dir = tempfile::tempdir().unwrap();
    let src_dir = dir.path().join("src");
    fs::create_dir(&src_dir).unwrap();
    let big_data = pseudo_random_bytes(1_350_000, 7);
    let note_data = b"hello split cli";
    fs::write(src_dir.join("big.bin"), &big_data).unwrap();
    fs::write(src_dir.join("note.txt"), note_data).unwrap();

    let out_dir = dir.path().join("vaults");
    fs::create_dir(&out_dir).unwrap();

    // 1. Encrypt with --split-mb 1 --no-compress -> 2 parts
    let (code, stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "encrypt",
            src_dir.to_str().unwrap(),
            "--no-compress",
            "--split-mb",
            "1",
            "-o",
            out_dir.to_str().unwrap(),
            "--password-stdin",
        ],
        "SplitCliPw!1\n",
    );
    assert_eq!(code, 0, "encrypt failed: {stderr}");
    assert!(stdout.contains("Encrypted (2 parts):"), "stdout: {stdout}");

    let part1 = out_dir.join("src.vault.001");
    let part2 = out_dir.join("src.vault.002");
    assert!(part1.is_file());
    assert!(part2.is_file());
    assert_eq!(fs::metadata(&part1).unwrap().len(), 1024 * 1024);

    // 2. Inspect --integrity-only --json on .001
    let (code, stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "inspect",
            part1.to_str().unwrap(),
            "--integrity-only",
            "--json",
        ],
        "",
    );
    assert_eq!(code, 0, "integrity failed: {stderr}");
    let j: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(j["ok"], true);
    assert_eq!(j["split_parts"], 2);

    // 3. Inspect metadata passing .002 directly
    let (code, stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "inspect",
            part2.to_str().unwrap(),
            "--json",
            "--password-stdin",
        ],
        "SplitCliPw!1\n",
    );
    assert_eq!(code, 0, "inspect metadata failed: {stderr}");
    let j: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(j["split_parts"], 2);
    assert_eq!(j["metadata"]["file_count"], 2);

    // 4. Decrypt passing BOTH parts (.001 & .002) with --only deduplicates cleanly to one vault
    let sel_out = dir.path().join("sel_out");
    fs::create_dir(&sel_out).unwrap();
    let (code, _stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "decrypt",
            part1.to_str().unwrap(),
            part2.to_str().unwrap(),
            "--only",
            "src/note.txt",
            "-o",
            sel_out.to_str().unwrap(),
            "--password-stdin",
        ],
        "SplitCliPw!1\n",
    );
    assert_eq!(code, 0, "selective split decrypt failed: {stderr}");
    assert_eq!(fs::read(sel_out.join("src/note.txt")).unwrap(), note_data);
    assert!(!sel_out.join("src/big.bin").exists());

    // 5. Create a second single vault with an extra file and run `diff` between split A and single B
    fs::write(src_dir.join("added.txt"), b"added in B").unwrap();
    let single_dir = dir.path().join("single_b");
    fs::create_dir(&single_dir).unwrap();
    let (code, _stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "encrypt",
            src_dir.to_str().unwrap(),
            "--no-compress",
            "-o",
            single_dir.to_str().unwrap(),
            "--password-stdin",
        ],
        "SingleBPw!2\n",
    );
    assert_eq!(code, 0, "single encrypt failed: {stderr}");
    let single_b = single_dir.join("src.vault");

    let (code, stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "diff",
            part1.to_str().unwrap(),
            single_b.to_str().unwrap(),
            "--password-stdin",
            "--json",
        ],
        "SplitCliPw!1\nSingleBPw!2\n",
    );
    assert_eq!(code, 0, "diff failed: {stderr}");
    let diff_j: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(diff_j["added"].as_array().unwrap().len(), 1);
    assert_eq!(diff_j["added"][0]["path"], "src/added.txt");

    // 6. Re-key split volume in place
    let (code, _stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "rekey",
            part1.to_str().unwrap(),
            "--password-stdin",
        ],
        "SplitCliPw!1\nRotatedSplit!3\n",
    );
    assert_eq!(code, 0, "rekey split failed: {stderr}");

    // 7. Join re-keyed split volume into single file and decrypt with new password
    let joined_path = dir.path().join("joined.vault");
    let (code, stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "join",
            part1.to_str().unwrap(),
            "-o",
            joined_path.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(code, 0, "join failed: {stderr}");
    assert!(stdout.contains("Joined:"), "stdout: {stdout}");

    let dec_joined = dir.path().join("dec_joined");
    fs::create_dir(&dec_joined).unwrap();
    let (code, _stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "decrypt",
            joined_path.to_str().unwrap(),
            "-o",
            dec_joined.to_str().unwrap(),
            "--password-stdin",
        ],
        "RotatedSplit!3\n",
    );
    assert_eq!(code, 0, "decrypt joined failed: {stderr}");
    assert_eq!(fs::read(dec_joined.join("src/big.bin")).unwrap(), big_data);

    // 8. Standalone `split` -> `join` roundtrip produces byte-for-byte identical vault
    let split_out = dir.path().join("standalone_split");
    fs::create_dir(&split_out).unwrap();
    let orig_single_bytes = fs::read(&single_b).unwrap();
    let (code, stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "split",
            single_b.to_str().unwrap(),
            "--part-mb",
            "1",
            "-o",
            split_out.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(code, 0, "standalone split failed: {stderr}");
    assert!(stdout.contains("Split (2 parts):"), "stdout: {stdout}");

    let rejoined_single = dir.path().join("rejoined_single.vault");
    let (code, _stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "join",
            split_out.join("src.vault.001").to_str().unwrap(),
            "-o",
            rejoined_single.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(code, 0, "rejoin failed: {stderr}");
    assert_eq!(fs::read(&rejoined_single).unwrap(), orig_single_bytes);
}

#[test]
fn cli_reed_solomon_split_damage_and_in_place_repair() {
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("data.bin");
    let payload = pseudo_random_bytes(1_200_000, 19);
    fs::write(&payload_path, &payload).unwrap();

    let out_dir = dir.path().join("rs_vault");
    fs::create_dir(&out_dir).unwrap();

    let (code, _stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "encrypt",
            payload_path.to_str().unwrap(),
            "--reed-solomon",
            "--no-compress",
            "--split-mb",
            "1",
            "-o",
            out_dir.to_str().unwrap(),
            "--password-stdin",
        ],
        "RsSplitCli!1\n",
    );
    assert_eq!(code, 0, "RS split encrypt failed: {stderr}");

    let part1 = out_dir.join("data.bin.vault.001");
    let part2 = out_dir.join("data.bin.vault.002");
    assert!(part1.is_file() && part2.is_file());

    // Flip 32 bytes inside part .002
    let mut bytes = fs::read(&part2).unwrap();
    for b in &mut bytes[500..532] {
        *b ^= 0xAA;
    }
    fs::write(&part2, &bytes).unwrap();

    // Repair in place via CLI
    let (code, stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "repair",
            part1.to_str().unwrap(),
            "--json",
        ],
        "",
    );
    assert_eq!(code, 0, "RS split repair failed: {stderr}");
    let rep: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(rep["repaired_bytes"], 32);

    // Decrypt repaired split volume
    let dec_out = dir.path().join("dec_rs");
    fs::create_dir(&dec_out).unwrap();
    let (code, _stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "decrypt",
            part1.to_str().unwrap(),
            "-o",
            dec_out.to_str().unwrap(),
            "--password-stdin",
        ],
        "RsSplitCli!1\n",
    );
    assert_eq!(code, 0, "RS split decrypt failed: {stderr}");
    assert_eq!(fs::read(dec_out.join("data.bin")).unwrap(), payload);
}

#[test]
fn cli_split_guards_pre_password_fail_fast_repair_checks_and_dedup() {
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("guard.bin");
    let payload = pseudo_random_bytes(1_200_000, 29);
    fs::write(&payload_path, &payload).unwrap();

    // 1) Upfront MAX_SPLIT_PARTS rejection BEFORE prompting password (empty stdin!).
    let (code, _stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "encrypt",
            payload_path.to_str().unwrap(),
            "--container-mb",
            "20000",
            "--split-mb",
            "1",
            "--password-stdin",
        ],
        "",
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("9999"), "stderr: {stderr}");

    // 2) Create a 2-part RS split vault
    let out_dir = dir.path().join("rs_guards");
    fs::create_dir(&out_dir).unwrap();
    let (code, _stdout, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "encrypt",
            payload_path.to_str().unwrap(),
            "--reed-solomon",
            "--no-compress",
            "--split-mb",
            "1",
            "-o",
            out_dir.to_str().unwrap(),
            "--password-stdin",
        ],
        "CliGuard!1\n",
    );
    assert_eq!(code, 0, "encrypt failed: {stderr}");
    let part1 = out_dir.join("guard.bin.vault.001");
    let part2 = out_dir.join("guard.bin.vault.002");
    assert!(part1.is_file() && part2.is_file());

    // 3) CLI `repair` rejects missing vault, directory as vault, `-o <existing_dir>`, and `-o <own_part>`
    let (code, _, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "repair",
            dir.path().join("missing.vault").to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("not found"), "stderr: {stderr}");

    let (code, _, _) = run(
        &["rpm-encrypter-cli", "repair", out_dir.to_str().unwrap()],
        "",
    );
    assert_eq!(code, 1);

    let (code, _, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "repair",
            part1.to_str().unwrap(),
            "-o",
            out_dir.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("directory"), "stderr: {stderr}");

    let (code, _, _) = run(
        &[
            "rpm-encrypter-cli",
            "repair",
            part1.to_str().unwrap(),
            "-o",
            part2.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(code, 1);

    // 4) Windows case-variant split part dedup in `decrypt --only`
    #[cfg(windows)]
    {
        let upper_p2 = out_dir.join("GUARD.BIN.VAULT.002");
        let dec_case = dir.path().join("dec_case");
        fs::create_dir(&dec_case).unwrap();
        let (code, _stdout, stderr) = run(
            &[
                "rpm-encrypter-cli",
                "decrypt",
                part1.to_str().unwrap(),
                upper_p2.to_str().unwrap(),
                "--only",
                "guard.bin",
                "-o",
                dec_case.to_str().unwrap(),
                "--password-stdin",
            ],
            "CliGuard!1\n",
        );
        assert_eq!(code, 0, "case-variant split dedup failed: {stderr}");
        assert_eq!(fs::read(dec_case.join("guard.bin")).unwrap(), payload);
    }

    // 5) Missing `.001` causes `inspect` and `rekey` to fail BEFORE reading password from stdin
    fs::remove_file(&part1).unwrap();
    let (code, _, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "inspect",
            part2.to_str().unwrap(),
            "--password-stdin",
        ],
        "",
    );
    assert_eq!(code, 1);
    assert!(
        stderr.contains("missing split volume part"),
        "inspect must fail on missing part before reading stdin; got: {stderr}"
    );

    let (code, _, stderr) = run(
        &[
            "rpm-encrypter-cli",
            "rekey",
            part2.to_str().unwrap(),
            "--password-stdin",
        ],
        "",
    );
    assert_eq!(code, 1);
    assert!(
        stderr.contains("missing split volume part"),
        "rekey must fail on missing part before reading stdin; got: {stderr}"
    );
}
