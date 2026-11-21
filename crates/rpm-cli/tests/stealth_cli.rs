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
fn stealth_commands_on_unpadded_padded_and_hidden_files() {
    for (padded, hidden) in [(false, false), (true, false), (true, true)] {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
        let a = path("decoy");
        let b = path("private");
        let recovery = path("recovery");
        let key = path("keyfile");
        fs::write(&a, b"public data").unwrap();
        fs::write(&b, b"private data").unwrap();
        fs::write(&key, b"secret key").unwrap();
        let mut args = vec![
            "encrypt",
            &a,
            "--stealth",
            "--recovery-out",
            &recovery,
            "--password-stdin",
        ];
        if padded {
            args.extend(["--container-mb", "1"]);
        }
        if hidden {
            args.extend(["--hidden", &b, "--hidden-keyfile", &key]);
        }
        success(&args, "outer\ninner\n");
        let vault = &path("random.dat");
        fs::rename(path("decoy.vault"), vault).unwrap();
        let bytes = fs::read(vault).unwrap();
        assert_ne!(&bytes[..4], b"RPMV");
        if padded {
            assert_eq!(bytes.len(), 1 << 20);
        }
        let integrity: Value = serde_json::from_str(&success(
            &["inspect", vault, "--integrity-only", "--json"],
            "",
        ))
        .unwrap();
        assert_eq!(integrity["sha256_only"], true);
        assert_eq!(integrity["ok"], true);
        let info: Value = serde_json::from_str(&success(
            &["inspect", vault, "--json", "--password-stdin"],
            "outer\n",
        ))
        .unwrap();
        assert_eq!(info["is_stealth"], true);
        assert!(success(&["inspect", vault, "--password-stdin"], "outer\n")
            .contains("is_stealth: true"));
        let phrase = fs::read_to_string(recovery).unwrap();
        let dest = path("restored");
        fs::create_dir(&dest).unwrap();
        success(
            &[
                "decrypt",
                vault,
                "--recovery-stdin",
                "--only",
                "decoy",
                "-o",
                &dest,
            ],
            &phrase,
        );
        assert_eq!(
            fs::read(dir.path().join("restored/decoy")).unwrap(),
            b"public data"
        );
        if hidden {
            let diff: Value = serde_json::from_str(&success(
                &[
                    "diff",
                    vault,
                    vault,
                    "--keyfile-b",
                    &key,
                    "--password-stdin",
                    "--json",
                ],
                "outer\ninner\n",
            ))
            .unwrap();
            assert_eq!(diff["added"][0]["path"], "private");
            assert_eq!(diff["removed"][0]["path"], "decoy");
            success(
                &[
                    "decrypt",
                    vault,
                    "--only",
                    "private",
                    "--keyfile",
                    &key,
                    "--password-stdin",
                    "-o",
                    &dest,
                ],
                "inner\n",
            );
            assert_eq!(
                fs::read(dir.path().join("restored/private")).unwrap(),
                b"private data"
            );
        }
        let (code, _, err) = run(&["rekey", vault, "--password-stdin"], "outer\nchange\n");
        assert_ne!(code, 0);
        assert!(err.contains("not available"));
        assert_eq!(fs::read(vault).unwrap(), bytes);
    }
}
