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
    child
        .stdin
        .take()
        .unwrap()
        .write_all(credentials.as_bytes())
        .unwrap();
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
