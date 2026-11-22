use rpm_core::{Auth, SecretKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub const NAMES: [&str; 8] = [
    "standard_uncompressed",
    "standard_compressed_keyfile",
    "padded_64k",
    "hidden_64k",
    "stealth_standard",
    "stealth_hidden_64k",
    "rs_standard",
    "rs_hidden_64k",
];
pub const OUTER: &[u8] = b"public fixture password";
pub const HIDDEN: &[u8] = b"hidden fixture password";
#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub recovery_phrase: String,
    pub vaults: BTreeMap<String, Case>,
}
#[derive(Serialize, Deserialize)]
pub struct Case {
    pub size: u64,
    pub sha256: String,
    pub recovery: bool,
    pub keyfile: bool,
    pub outer: BTreeMap<String, String>,
    pub hidden: BTreeMap<String, String>,
}
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../rpm-core/tests/fixtures/v4_4_0")
}
pub fn manifest() -> Manifest {
    let m: Manifest =
        serde_json::from_slice(&fs::read(root().join("fixtures_manifest.json")).unwrap()).unwrap();
    assert_eq!(m.vaults.len(), 8);
    for name in NAMES {
        assert!(m.vaults.contains_key(&format!("{name}.vault")));
    }
    m
}
pub fn key() -> SecretKey {
    let bytes = fs::read(root().join("golden.key")).unwrap();
    assert_eq!(bytes, (0u8..64).collect::<Vec<_>>());
    rpm_core::hash_keyfile_reader(&mut bytes.as_slice()).unwrap()
}
pub fn auth(hidden: bool, keyfile: Option<&SecretKey>) -> Auth<'_> {
    Auth::Password {
        password: if hidden { HIDDEN } else { OUTER },
        keyfile_hash: keyfile,
    }
}
