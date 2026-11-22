use rpm_core::KdfParams;
use serde_json::Value;
use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy, PartialEq, Eq)]
enum EnvelopeMode {
    Standard,
    Stealth,
    ReedSolomon,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ContainerLayout {
    Unpadded,
    Padded,
    Hidden,
}

fn run(args: &[&str], stdin_data: &str) -> (i32, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = rpm_cli::run_cli_args(
        std::iter::once("rpm-encrypter-cli").chain(args.iter().copied()),
        &mut Cursor::new(stdin_data),
        &mut out,
        &mut err,
        Some(KdfParams::fast_test()),
    );
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn ok(args: &[&str], stdin_data: &str) -> String {
    let (code, out, err) = run(args, stdin_data);
    assert_eq!(code, 0, "args={args:?}\nstderr={err}\nstdout={out}");
    out
}

fn flip_sector(bytes: &mut [u8], offset: usize, len: usize) {
    for (i, b) in bytes[offset..offset + len].iter_mut().enumerate() {
        *b ^= ((i % 251) + 1) as u8;
    }
}

fn build_fixture(root: &Path) -> (String, String, String, String, String) {
    let outer_dir = root.join("outer");
    fs::create_dir_all(outer_dir.join("sub")).unwrap();
    fs::write(outer_dir.join("shared.txt"), "shared-content").unwrap();
    fs::write(outer_dir.join("Iğdır-özel.txt"), "Dış Türkçe metin ğüşıöç").unwrap();
    fs::write(outer_dir.join("sub/nested.bin"), vec![0x42u8; 4096]).unwrap();

    let hidden_dir = root.join("hidden");
    fs::create_dir_all(hidden_dir.join("secret_sub")).unwrap();
    fs::write(
        hidden_dir.join("shared.txt"),
        "shared-content-modified-hidden",
    )
    .unwrap();
    fs::write(hidden_dir.join("secret.txt"), "Gizli bölme metni").unwrap();
    fs::write(
        hidden_dir.join("secret_sub/payload.bin"),
        vec![0x99u8; 2048],
    )
    .unwrap();

    let kf1 = root.join("kf1.key");
    let kf2 = root.join("kf2.key");
    let kf_h = root.join("kf_hidden.key");
    fs::write(&kf1, b"cli-keyfile-outer-1").unwrap();
    fs::write(&kf2, b"cli-keyfile-outer-2").unwrap();
    fs::write(&kf_h, b"cli-keyfile-hidden").unwrap();

    (
        outer_dir.to_str().unwrap().to_owned(),
        hidden_dir.to_str().unwrap().to_owned(),
        kf1.to_str().unwrap().to_owned(),
        kf2.to_str().unwrap().to_owned(),
        kf_h.to_str().unwrap().to_owned(),
    )
}

fn run_cli_24_configs(mode: EnvelopeMode) {
    let progress_modes = ["auto", "always", "never"];
    let mut configs_run = 0usize;
    let mut wipes_run = 0usize;

    for layout in [
        ContainerLayout::Unpadded,
        ContainerLayout::Padded,
        ContainerLayout::Hidden,
    ] {
        let hidden_variants: &[(bool, bool)] = match layout {
            ContainerLayout::Hidden => {
                &[(false, false), (false, true), (true, false), (true, true)]
            }
            ContainerLayout::Unpadded | ContainerLayout::Padded => &[(false, false)],
        };
        for &outer_compress in &[false, true] {
            for &outer_kf_on in &[false, true] {
                for &(hidden_compress, hidden_kf_on) in hidden_variants {
                    configs_run += 1;
                    let case = tempfile::tempdir().unwrap();
                    let src_root = case.path().join("src");
                    let out_dir = case.path().join("vault_out");
                    fs::create_dir_all(&src_root).unwrap();
                    fs::create_dir_all(&out_dir).unwrap();
                    let (outer_src, hidden_src, kf1, kf2, kf_h) = build_fixture(&src_root);

                    let out_dir_str = out_dir.to_str().unwrap().to_owned();
                    let rec_file = case.path().join("recovery.txt");
                    let rec_file_str = rec_file.to_str().unwrap().to_owned();
                    let progress = progress_modes[configs_run % progress_modes.len()];
                    let use_rec_out = configs_run.is_multiple_of(2);
                    let use_out_dir = !configs_run.is_multiple_of(3);
                    // Configs 4 (Unpadded), 8 (Padded), and 20 (Hidden) all write to `-o` so
                    // `--wipe` is genuinely exercised across all 3 container layouts.
                    let use_wipe = matches!(configs_run, 4 | 8 | 20) && use_out_dir;

                    let mut args = vec![
                        "encrypt",
                        &outer_src,
                        "--password-stdin",
                        "--progress",
                        progress,
                    ];
                    if mode == EnvelopeMode::Stealth {
                        args.push("--stealth");
                    } else if mode == EnvelopeMode::ReedSolomon {
                        args.push("--reed-solomon");
                    }
                    if layout != ContainerLayout::Unpadded {
                        args.extend(["--container-mb", "1"]);
                    }
                    if !outer_compress {
                        args.push("--no-compress");
                    }
                    if outer_kf_on {
                        args.extend(["--keyfile", &kf1]);
                    }
                    if use_out_dir {
                        args.extend(["-o", &out_dir_str]);
                    }
                    if use_rec_out {
                        args.extend(["--recovery-out", &rec_file_str]);
                    }
                    if use_wipe {
                        args.push("--wipe");
                    }

                    let secrets = if layout == ContainerLayout::Hidden {
                        args.extend(["--hidden", &hidden_src]);
                        if hidden_kf_on {
                            args.extend(["--hidden-keyfile", &kf_h]);
                        }
                        if !hidden_compress {
                            args.push("--hidden-no-compress");
                        }
                        "OuterCli!1\nHiddenCli!2\n"
                    } else {
                        "OuterCli!1\n"
                    };

                    let enc_stdout = ok(&args, secrets);
                    if use_wipe {
                        wipes_run += 1;
                        assert!(!Path::new(&outer_src).exists());
                        if layout == ContainerLayout::Hidden {
                            assert!(!Path::new(&hidden_src).exists());
                        }
                    }

                    let phrase = if use_rec_out {
                        fs::read_to_string(&rec_file).unwrap()
                    } else {
                        format!("{}\n", enc_stdout.lines().last().unwrap().trim())
                    };
                    assert_eq!(phrase.split_whitespace().count(), 24);

                    let default_vault = if use_out_dir {
                        out_dir.join("outer.vault")
                    } else {
                        src_root.join("outer.vault")
                    };
                    let vault_path = if mode == EnvelopeMode::Stealth {
                        let renamed =
                            default_vault.with_file_name(if configs_run.is_multiple_of(2) {
                                "stealth_vault.bin"
                            } else {
                                "opaque_vault"
                            });
                        fs::rename(&default_vault, &renamed).unwrap();
                        renamed
                    } else {
                        default_vault
                    };
                    let mut vault = vault_path.to_str().unwrap().to_owned();

                    // Reed-Solomon: corrupt 512 B, integrity check, transparent full decrypt, then repair (-o or in-place)
                    if mode == EnvelopeMode::ReedSolomon {
                        let clean = fs::read(&vault_path).unwrap();
                        let mut damaged = clean.clone();
                        let offset = if configs_run.is_multiple_of(2) {
                            0
                        } else {
                            48 + 300
                        };
                        flip_sector(&mut damaged, offset, 512);
                        fs::write(&vault_path, &damaged).unwrap();

                        let dmg_json: Value = serde_json::from_str(&ok(
                            &["inspect", &vault, "--integrity-only", "--json"],
                            "",
                        ))
                        .unwrap();
                        assert_eq!(dmg_json["ok"], true);
                        assert_eq!(dmg_json["has_reed_solomon"], true);
                        assert_eq!(dmg_json["rs_repaired_bytes"], 512);

                        let dmg_dec = case.path().join("dmg_dec");
                        fs::create_dir_all(&dmg_dec).unwrap();
                        let mut dec_dmg_args = vec![
                            "decrypt",
                            &vault,
                            "-o",
                            dmg_dec.to_str().unwrap(),
                            "--password-stdin",
                            "--progress",
                            progress,
                        ];
                        if outer_kf_on {
                            dec_dmg_args.extend(["--keyfile", &kf1]);
                        }
                        ok(&dec_dmg_args, "OuterCli!1\n");
                        assert_eq!(
                            fs::read_to_string(dmg_dec.join("outer/Iğdır-özel.txt")).unwrap(),
                            "Dış Türkçe metin ğüşıöç"
                        );
                        assert_eq!(
                            fs::read(dmg_dec.join("outer/sub/nested.bin")).unwrap(),
                            vec![0x42u8; 4096]
                        );

                        if configs_run.is_multiple_of(2) {
                            let copy = case.path().join("repaired_copy.vault");
                            let copy_str = copy.to_str().unwrap().to_owned();
                            let rep_json: Value = serde_json::from_str(&ok(
                                &["repair", &vault, "-o", &copy_str, "--json"],
                                "",
                            ))
                            .unwrap();
                            assert_eq!(rep_json["repaired_bytes"], 512);
                            assert_eq!(fs::read(&copy).unwrap(), clean);
                            assert_eq!(fs::read(&vault_path).unwrap(), damaged);
                            vault = copy_str;
                        } else {
                            ok(&["repair", &vault], "");
                            assert_eq!(fs::read(&vault_path).unwrap(), clean);
                        }
                    }

                    // Passwordless integrity on clean/repaired vault (JSON & plain)
                    let int_json: Value = serde_json::from_str(&ok(
                        &["inspect", &vault, "--integrity-only", "--json"],
                        "",
                    ))
                    .unwrap();
                    assert_eq!(int_json["ok"], true);
                    assert_eq!(int_json["sha256_only"], mode == EnvelopeMode::Stealth);
                    assert_eq!(
                        int_json["has_reed_solomon"],
                        mode == EnvelopeMode::ReedSolomon
                    );
                    assert_eq!(int_json["rs_repaired_bytes"], 0);
                    if configs_run.is_multiple_of(3) {
                        let plain_int = ok(&["inspect", &vault, "--integrity-only"], "");
                        assert!(!plain_int.trim().is_empty());
                    }

                    // Inspect unlocked metadata: password & recovery (JSON / plain)
                    let mut ins_args = vec!["inspect", &vault, "--password-stdin", "--json"];
                    if outer_kf_on {
                        ins_args.extend(["--keyfile", &kf1]);
                    }
                    let ins_pw: Value =
                        serde_json::from_str(&ok(&ins_args, "OuterCli!1\n")).unwrap();
                    assert_eq!(ins_pw["is_stealth"], mode == EnvelopeMode::Stealth);
                    assert_eq!(
                        ins_pw["has_reed_solomon"],
                        mode == EnvelopeMode::ReedSolomon
                    );
                    assert_eq!(ins_pw["is_hidden_compartment"], false);

                    let ins_rec_plain = ok(&["inspect", &vault, "--recovery-stdin"], &phrase);
                    assert!(ins_rec_plain.contains("Iğdır-özel.txt"));

                    // Full decrypt for Standard/Stealth (RS already ran full decrypt above on damaged envelope)
                    if mode != EnvelopeMode::ReedSolomon {
                        let full_outer = case.path().join("full_outer");
                        fs::create_dir_all(&full_outer).unwrap();
                        let mut dec_outer = vec![
                            "decrypt",
                            &vault,
                            "-o",
                            full_outer.to_str().unwrap(),
                            "--password-stdin",
                            "--progress",
                            progress,
                        ];
                        if outer_kf_on {
                            dec_outer.extend(["--keyfile", &kf1]);
                        }
                        ok(&dec_outer, "OuterCli!1\n");
                        assert_eq!(
                            fs::read_to_string(full_outer.join("outer/Iğdır-özel.txt")).unwrap(),
                            "Dış Türkçe metin ğüşıöç"
                        );
                        assert_eq!(
                            fs::read(full_outer.join("outer/sub/nested.bin")).unwrap(),
                            vec![0x42u8; 4096]
                        );
                    }

                    let sel_rec = case.path().join("sel_rec");
                    fs::create_dir_all(&sel_rec).unwrap();
                    ok(
                        &[
                            "decrypt",
                            &vault,
                            "-o",
                            sel_rec.to_str().unwrap(),
                            "--recovery-stdin",
                            "--only",
                            "outer/Iğdır-özel.txt",
                            "--only",
                            "outer/sub",
                        ],
                        &phrase,
                    );
                    assert!(sel_rec.join("outer/Iğdır-özel.txt").is_file());
                    assert!(sel_rec.join("outer/sub/nested.bin").is_file());
                    assert!(!sel_rec.join("outer/shared.txt").exists());

                    // Hidden inspect + selective decrypt + diff against outer
                    if layout == ContainerLayout::Hidden {
                        let mut h_ins = vec!["inspect", &vault, "--password-stdin", "--json"];
                        if hidden_kf_on {
                            h_ins.extend(["--keyfile", &kf_h]);
                        }
                        let h_info: Value =
                            serde_json::from_str(&ok(&h_ins, "HiddenCli!2\n")).unwrap();
                        assert_eq!(h_info["is_hidden_compartment"], true);

                        let sel_h = case.path().join("sel_hidden");
                        fs::create_dir_all(&sel_h).unwrap();
                        let mut dec_h = vec![
                            "decrypt",
                            &vault,
                            "-o",
                            sel_h.to_str().unwrap(),
                            "--password-stdin",
                            "--only",
                            "hidden/secret_sub",
                        ];
                        if hidden_kf_on {
                            dec_h.extend(["--keyfile", &kf_h]);
                        }
                        ok(&dec_h, "HiddenCli!2\n");
                        assert_eq!(
                            fs::read(sel_h.join("hidden/secret_sub/payload.bin")).unwrap(),
                            vec![0x99u8; 2048]
                        );
                        assert!(!sel_h.join("hidden/secret.txt").exists());

                        let mut diff_args = vec![
                            "diff",
                            &vault,
                            &vault,
                            "--recovery-a",
                            "--password-stdin",
                            "--json",
                        ];
                        if hidden_kf_on {
                            diff_args.extend(["--keyfile-b", &kf_h]);
                        }
                        let diff_json: Value = serde_json::from_str(&ok(
                            &diff_args,
                            &format!("{phrase}HiddenCli!2\n"),
                        ))
                        .unwrap();
                        assert_eq!(diff_json["added"].as_array().unwrap().len(), 3);
                        assert_eq!(diff_json["removed"].as_array().unwrap().len(), 3);
                    }

                    // Standard + Unpadded Re-Key transitions
                    if mode == EnvelopeMode::Standard && layout == ContainerLayout::Unpadded {
                        let mut current_pw = "OuterCli!1".to_string();
                        let mut current_kf = outer_kf_on.then_some(kf1.clone());
                        let transitions: Vec<Option<String>> = if outer_kf_on {
                            vec![Some(kf1.clone()), Some(kf2.clone()), None]
                        } else {
                            vec![None, Some(kf1.clone())]
                        };

                        for (step, target_kf) in transitions.into_iter().enumerate() {
                            let next_pw = format!("CliRekey!{configs_run}_{step}");
                            let mut rk_args = vec!["rekey", &vault, "--password-stdin"];
                            if let Some(ref okf) = current_kf {
                                rk_args.extend(["--keyfile", okf]);
                            }
                            match (&current_kf, &target_kf) {
                                (_, Some(ref nkf)) => rk_args.extend(["--new-keyfile", nkf]),
                                (Some(_), None) => rk_args.push("--clear-keyfile"),
                                (None, None) => {}
                            }
                            ok(&rk_args, &format!("{current_pw}\n{next_pw}\n"));
                            current_pw = next_pw;
                            current_kf = target_kf;

                            let out_rk = case.path().join(format!("dec_rk_{step}"));
                            fs::create_dir_all(&out_rk).unwrap();
                            let mut d_rk = vec![
                                "decrypt",
                                &vault,
                                "-o",
                                out_rk.to_str().unwrap(),
                                "--password-stdin",
                            ];
                            if let Some(ref ckf) = current_kf {
                                d_rk.extend(["--keyfile", ckf]);
                            }
                            ok(&d_rk, &format!("{current_pw}\n"));
                            assert!(out_rk.join("outer/Iğdır-özel.txt").is_file());
                        }
                        let rec_after = case.path().join("dec_rk_rec");
                        fs::create_dir_all(&rec_after).unwrap();
                        ok(
                            &[
                                "decrypt",
                                &vault,
                                "-o",
                                rec_after.to_str().unwrap(),
                                "--recovery-stdin",
                            ],
                            &phrase,
                        );
                        assert!(rec_after.join("outer/sub/nested.bin").is_file());
                    }
                }
            }
        }
    }

    assert_eq!(configs_run, 24);
    assert_eq!(wipes_run, 3);
}

#[test]
fn cli_vault_matrix_standard_24() {
    run_cli_24_configs(EnvelopeMode::Standard);
}

#[test]
fn cli_vault_matrix_stealth_24() {
    run_cli_24_configs(EnvelopeMode::Stealth);
}

#[test]
fn cli_vault_matrix_reed_solomon_24() {
    run_cli_24_configs(EnvelopeMode::ReedSolomon);
}

#[test]
fn cli_batch_decrypt_diff_password_and_shell_status_matrix() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let dir_a = root.join("vault_a");
    let dir_b = root.join("vault_b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    let unchanged_a = dir_a.join("unchanged.txt");
    let unchanged_b = dir_b.join("unchanged.txt");
    fs::write(&unchanged_a, b"same bytes").unwrap();
    fs::write(dir_a.join("changed.txt"), b"before").unwrap();
    fs::write(dir_a.join("removed.txt"), b"only in A").unwrap();

    fs::write(&unchanged_b, b"same bytes").unwrap();
    fs::write(dir_b.join("changed.txt"), b"after-expanded").unwrap();
    fs::write(dir_b.join("added.txt"), b"only in B").unwrap();

    // Pin identical mtime so a wall-clock second tick between the two writes
    // cannot reclassify `unchanged.txt` as `changed`.
    let pinned_mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    for path in [&unchanged_a, &unchanged_b] {
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(pinned_mtime)
            .unwrap();
    }

    let kf = root.join("diff.key");
    fs::write(&kf, b"diff-key-material").unwrap();
    let rec_a = root.join("rec_a.txt");
    let rec_b = root.join("rec_b.txt");
    let va_out = root.join("a_out");
    let vb_out = root.join("b_out");
    fs::create_dir_all(&va_out).unwrap();
    fs::create_dir_all(&vb_out).unwrap();

    ok(
        &[
            "encrypt",
            dir_a.join("unchanged.txt").to_str().unwrap(),
            dir_a.join("changed.txt").to_str().unwrap(),
            dir_a.join("removed.txt").to_str().unwrap(),
            "--keyfile",
            kf.to_str().unwrap(),
            "--recovery-out",
            rec_a.to_str().unwrap(),
            "-o",
            va_out.to_str().unwrap(),
            "--password-stdin",
        ],
        "BatchPw!1\n",
    );
    ok(
        &[
            "encrypt",
            dir_b.join("unchanged.txt").to_str().unwrap(),
            dir_b.join("changed.txt").to_str().unwrap(),
            dir_b.join("added.txt").to_str().unwrap(),
            "--recovery-out",
            rec_b.to_str().unwrap(),
            "-o",
            vb_out.to_str().unwrap(),
            "--password-stdin",
        ],
        "BatchPw!1\n",
    );

    let va = va_out.join("Archive.vault");
    let vb = vb_out.join("Archive.vault");
    let phrase_a = fs::read_to_string(&rec_a).unwrap();
    let phrase_b = fs::read_to_string(&rec_b).unwrap();

    // Recovery decrypt on va without keyfile
    let rec_va_out = root.join("rec_va");
    fs::create_dir_all(&rec_va_out).unwrap();
    let rec_dec = ok(
        &[
            "decrypt",
            va.to_str().unwrap(),
            "-o",
            rec_va_out.to_str().unwrap(),
            "--recovery-stdin",
        ],
        &phrase_a,
    );
    assert!(rec_dec.contains("Decrypted:"));

    // Multi-vault password batch decrypt on vb + vc (sharing password, keyless)
    let dir_c = root.join("vault_c");
    fs::create_dir_all(&dir_c).unwrap();
    fs::write(dir_c.join("batch.txt"), b"vault c batch item").unwrap();
    let vc_out = root.join("c_out");
    fs::create_dir_all(&vc_out).unwrap();
    ok(
        &[
            "encrypt",
            dir_c.join("batch.txt").to_str().unwrap(),
            "-o",
            vc_out.to_str().unwrap(),
            "--password-stdin",
        ],
        "BatchPw!1\n",
    );
    let vc = vc_out.join("batch.txt.vault");
    let batch_pw_out = root.join("batch_pw");
    fs::create_dir_all(&batch_pw_out).unwrap();
    let batch_out = ok(
        &[
            "decrypt",
            vb.to_str().unwrap(),
            vc.to_str().unwrap(),
            "-o",
            batch_pw_out.to_str().unwrap(),
            "--password-stdin",
        ],
        "BatchPw!1\n",
    );
    assert_eq!(batch_out.matches("Decrypted:").count(), 2);

    // Valid diff auth pairings: pw+kf / pw, rec / pw, pw+kf / rec, rec / rec
    let va_s = va.to_str().unwrap();
    let vb_s = vb.to_str().unwrap();
    let kf_s = kf.to_str().unwrap();
    let diff_cases: Vec<(Vec<&str>, String)> = vec![
        (
            vec![
                "diff",
                va_s,
                vb_s,
                "--keyfile-a",
                kf_s,
                "--password-stdin",
                "--json",
            ],
            "BatchPw!1\nBatchPw!1\n".into(),
        ),
        (
            vec![
                "diff",
                va_s,
                vb_s,
                "--recovery-a",
                "--password-stdin",
                "--json",
            ],
            format!("{phrase_a}BatchPw!1\n"),
        ),
        (
            vec![
                "diff",
                va_s,
                vb_s,
                "--keyfile-a",
                kf_s,
                "--recovery-b",
                "--password-stdin",
                "--json",
            ],
            format!("BatchPw!1\n{phrase_b}"),
        ),
        (
            vec![
                "diff",
                va_s,
                vb_s,
                "--recovery-a",
                "--recovery-b",
                "--password-stdin",
                "--json",
            ],
            format!("{phrase_a}{phrase_b}"),
        ),
        (
            vec!["diff", vb_s, va_s, "--keyfile-b", kf_s, "--password-stdin"],
            "BatchPw!1\nBatchPw!1\n".into(),
        ),
    ];
    for (idx, (args, input)) in diff_cases.iter().enumerate() {
        let out = ok(args, input);
        if idx < 4 {
            let v: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["added"][0]["path"], "added.txt");
            assert_eq!(v["removed"][0]["path"], "removed.txt");
            assert_eq!(v["changed"][0]["after"]["path"], "changed.txt");
            assert_eq!(v["unchanged"][0]["path"], "unchanged.txt");
        } else {
            assert!(out.contains("Added (1)") && out.contains("Removed (1)"));
        }
    }

    // Password generator matrix: lengths x no_symbols
    for len in [12usize, 16, 24, 32, 64] {
        for no_sym in [false, true] {
            let len_s = len.to_string();
            let mut args = vec!["password", "--length", &len_s];
            if no_sym {
                args.push("--no-symbols");
            }
            let out = ok(&args, "");
            let pw_line = out.lines().next().unwrap();
            assert_eq!(pw_line.len(), len);
            if no_sym {
                assert!(pw_line.bytes().all(|b| b.is_ascii_alphanumeric()));
            }
            assert!(out.contains("Strength score:"));
        }
    }

    // Read-only Windows/Linux shell-integration status exits 0 cleanly without mutating registry
    let st = ok(&["shell-integration", "status"], "");
    assert!(st.contains("supported="));
}
