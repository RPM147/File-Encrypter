use rpm_core::KdfParams;
use serde_json::Value;
use std::{fs, io::Cursor};

fn run(args: &[&str], secrets: &str) -> (i32, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = rpm_cli::run_cli_args(
        std::iter::once("cli").chain(args.iter().copied()),
        &mut Cursor::new(secrets),
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

fn success(args: &[&str], secrets: &str) -> String {
    let (code, out, err) = run(args, secrets);
    assert_eq!(code, 0, "{err}");
    out
}

#[test]
fn padded_outer_without_hidden_sources() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("note");
    fs::write(&source, "note").unwrap();
    success(
        &[
            "encrypt",
            source.to_str().unwrap(),
            "--container-mb",
            "1",
            "--password-stdin",
        ],
        "outer\n",
    );
    let vault = temp.path().join("note.vault");
    assert_eq!(fs::metadata(&vault).unwrap().len(), 1 << 20);
    let text = success(
        &["inspect", vault.to_str().unwrap(), "--password-stdin"],
        "outer\n",
    );
    assert!(text.contains("container_size: 1048576 bytes"));
    assert!(text.contains("is_hidden_compartment: false"));
}

#[test]
fn credentials_select_the_compartment_for_inspect_extract_and_diff() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let outer = dir.join("public");
    let secret = dir.join("private");
    let extra = dir.join("extra");
    let key = dir.join("secret.key");
    let recovery = dir.join("outer.phrase");
    for path in [&outer, &secret, &extra, &key] {
        fs::write(path, path.file_name().unwrap().to_str().unwrap()).unwrap();
    }
    success(
        &[
            "encrypt",
            outer.to_str().unwrap(),
            "--hidden",
            secret.to_str().unwrap(),
            extra.to_str().unwrap(),
            "--container-mb",
            "1",
            "--hidden-keyfile",
            key.to_str().unwrap(),
            "--hidden-no-compress",
            "--password-stdin",
            "--wipe",
            "--recovery-out",
            recovery.to_str().unwrap(),
        ],
        "decoy\nsecret\n",
    );
    assert!(!outer.exists() && !secret.exists() && !extra.exists());
    let vault = dir.join("public.vault");
    assert_eq!(fs::metadata(&vault).unwrap().len(), 1 << 20);
    let vault = vault.to_str().unwrap();
    let key = key.to_str().unwrap();
    let phrase = fs::read_to_string(recovery).unwrap();
    let outer_info: Value = serde_json::from_str(&success(
        &["inspect", vault, "--recovery-stdin", "--json"],
        &phrase,
    ))
    .unwrap();
    assert_eq!(outer_info["is_hidden_compartment"], false);
    assert_eq!(outer_info["metadata"]["files"][0]["path"], "public");
    assert_eq!(outer_info["metadata"]["compressed"], true);
    let info: Value = serde_json::from_str(&success(
        &[
            "inspect",
            vault,
            "--password-stdin",
            "--keyfile",
            key,
            "--json",
        ],
        "secret\n",
    ))
    .unwrap();
    assert_eq!(info["container_size"], 1 << 20);
    assert_eq!(info["is_hidden_compartment"], true);
    assert_eq!(info["has_keyfile"], true);
    assert_eq!(info["has_recovery"], false);
    assert_eq!(info["metadata"]["compressed"], false);
    assert_ne!(
        run(&["inspect", vault, "--password-stdin"], "secret\n").0,
        0
    );

    let dest = dir.join("restored");
    fs::create_dir(&dest).unwrap();
    success(
        &[
            "decrypt",
            vault,
            "--only",
            "private",
            "--keyfile",
            key,
            "--password-stdin",
            "-o",
            dest.to_str().unwrap(),
        ],
        "secret\n",
    );
    assert_eq!(fs::read(dest.join("private")).unwrap(), b"private");
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 1);
    let diff: Value = serde_json::from_str(&success(
        &[
            "diff",
            vault,
            vault,
            "--password-stdin",
            "--keyfile-b",
            key,
            "--json",
        ],
        "decoy\nsecret\n",
    ))
    .unwrap();
    assert_eq!(diff["added"][0]["path"], "extra");
    assert_eq!(diff["added"][1]["path"], "private");
    assert_eq!(diff["removed"][0]["path"], "public");
}

#[test]
fn invalid_hidden_options_leave_inputs_intact() {
    let dir = tempfile::tempdir().unwrap();
    let outer = dir.path().join("outer");
    let hidden = dir.path().join("inner");
    fs::write(&outer, "outer").unwrap();
    fs::write(&hidden, "inner").unwrap();
    let a = outer.to_str().unwrap();
    let b = hidden.to_str().unwrap();
    let missing = run(&["encrypt", a, "--hidden", b, "--password-stdin"], "");
    assert_ne!(missing.0, 0);
    assert!(missing.2.contains("--container-mb"));
    let args = [
        "encrypt",
        a,
        "--container-mb",
        "1",
        "--hidden",
        b,
        "--password-stdin",
        "--wipe",
    ];
    let equal = run(&args, "same\nsame\n");
    assert_ne!(equal.0, 0);
    assert!(equal.2.contains("different"));
    assert_ne!(run(&args, "outer only\n").0, 0);
    let overlap = run(
        &[
            "encrypt",
            dir.path().to_str().unwrap(),
            "--container-mb",
            "1",
            "--hidden",
            b,
            "--password-stdin",
        ],
        "outer\nsecret\n",
    );
    assert_ne!(overlap.0, 0);
    assert!(overlap.2.contains("overlap"));
    let mut wipe_key = args.to_vec();
    wipe_key.extend(["--hidden-keyfile", b]);
    let rejected = run(&wipe_key, "outer\nsecret\n");
    assert_ne!(rejected.0, 0);
    assert!(rejected.2.contains("--wipe"));
    for options in [
        &["--hidden"][..],
        &["--hidden-no-compress"],
        &["--hidden-keyfile", b],
        &["--container-mb", "18446744073709551615"],
    ] {
        let mut args = vec!["encrypt", a, "--password-stdin"];
        args.extend_from_slice(options);
        assert_eq!(run(&args, "outer\n").0, 2);
    }
    assert_eq!(fs::read(&outer).unwrap(), b"outer");
    assert_eq!(fs::read(&hidden).unwrap(), b"inner");
    assert!(!dir.path().join("outer.vault").exists());
}
