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
fn passwordless_repair_and_transparent_vault_commands() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name).to_str().unwrap().to_owned();
    let src = path("note");
    fs::write(&src, "example").unwrap();
    assert_eq!(
        run(&["encrypt", &src, "--stealth", "--reed-solomon"], "").0,
        2
    );
    success(
        &["encrypt", &src, "--reed-solomon", "--password-stdin"],
        "pw\n",
    );
    let vault = path("note.vault");
    let clean = fs::read(&vault).unwrap();
    let mut damaged = clean.clone();
    for b in &mut damaged[99..611] {
        *b ^= 37;
    }
    fs::write(&vault, &damaged).unwrap();
    let check: Value = serde_json::from_str(&success(
        &["inspect", &vault, "--integrity-only", "--json"],
        "",
    ))
    .unwrap();
    assert_eq!(check["has_reed_solomon"], true);
    assert_eq!(check["rs_repaired_bytes"], 512);
    let inspect: Value = serde_json::from_str(&success(
        &["inspect", &vault, "--password-stdin", "--json"],
        "pw\n",
    ))
    .unwrap();
    assert_eq!(inspect["has_reed_solomon"], true);
    let dirout = path("out");
    fs::create_dir(&dirout).unwrap();
    success(
        &["decrypt", &vault, "-o", &dirout, "--password-stdin"],
        "pw\n",
    );
    assert_eq!(fs::read(path("out/note")).unwrap(), b"example");
    let diff: Value = serde_json::from_str(&success(
        &["diff", &vault, &vault, "--password-stdin", "--json"],
        "pw\npw\n",
    ))
    .unwrap();
    assert_eq!(diff["unchanged"][0]["path"], "note");
    let fixed = path("copy.vault");
    let report: Value =
        serde_json::from_str(&success(&["repair", &vault, "--json", "-o", &fixed], "")).unwrap();
    assert_eq!(report["repaired_bytes"], 512);
    assert_eq!(fs::read(&fixed).unwrap(), clean);
    assert_eq!(fs::read(&vault).unwrap(), damaged);
    success(&["repair", &vault], "");
    assert_eq!(fs::read(&vault).unwrap(), clean);
    assert_eq!(run(&["repair", &src], "").0, 1);
}
