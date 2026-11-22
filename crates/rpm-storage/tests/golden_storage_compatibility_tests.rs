#[path = "../../rpm-core/tests/support/golden.rs"]
mod golden;
use golden::*;
use rpm_core::{
    diff_metadata, inspect_header_seekable, EncryptOptions, HiddenEncryptOptions, KdfParams,
    SecretKey,
};
use rpm_storage::*;
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::{atomic::AtomicBool, Arc},
};
fn digest(data: &[u8]) -> String {
    rpm_core::hash_keyfile_reader(&mut &*data)
        .unwrap()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn cancel() -> Arc<AtomicBool> {
    Arc::new(false.into())
}
fn content(name: &str) -> &'static [u8] {
    match name {
        "note.txt" => b"Frozen RPM v4.4.0\n",
        "tiny.bin" => b"\0\xff\x01\x03",
        "secret.txt" => b"Private museum compartment\n",
        _ => panic!("unexpected member {name}"),
    }
}
#[test]
#[ignore = "one-time fixture generator; refuses an existing directory"]
fn generate_v4_4_0() {
    let root = root();
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    fs::create_dir(&root).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let paths = ["note.txt", "tiny.bin", "secret.txt"].map(|n| {
        let p = tmp.path().join(n);
        fs::write(&p, content(n)).unwrap();
        p
    });
    fs::write(root.join("golden.key"), (0u8..64).collect::<Vec<_>>()).unwrap();
    let entropy = SecretKey::new([42; 32]);
    let mut manifest = Manifest {
        recovery_phrase: rpm_core::entropy_to_mnemonic(&entropy).unwrap().to_string(),
        vaults: BTreeMap::new(),
    };
    for name in NAMES {
        let file = format!("{name}.vault");
        let dest = root.join(&file);
        let hidden = name.contains("hidden");
        let stealth = name.starts_with("stealth");
        let rs = name.starts_with("rs_");
        let kf = name.contains("keyfile");
        let recovery = !hidden && !rs;
        let kdf = if stealth {
            rpm_core::STEALTH_KDF_PARAMS
        } else {
            KdfParams::fast_test()
        };
        let progress: Arc<dyn Fn(u64, u64) + Send + Sync> = Arc::new(|_, _| {});
        if hidden {
            encrypt_hidden_sources_v5(
                &paths[..2],
                &paths[2..],
                &dest,
                OUTER,
                HIDDEN,
                &HiddenEncryptOptions {
                    stealth,
                    reed_solomon: rs,
                    kdf,
                    container_size_bytes: 65536,
                    ..Default::default()
                },
                progress,
                cancel(),
                |_| {},
            )
            .unwrap();
        } else {
            encrypt_sources_v5(
                &paths[..2],
                &dest,
                OUTER,
                &EncryptOptions {
                    stealth,
                    reed_solomon: rs,
                    kdf,
                    container_size_bytes: name.contains("64k").then_some(65536),
                    compressed: !name.contains("uncompressed"),
                    keyfile_hash: kf.then(key),
                    recovery_key: recovery.then(|| entropy.clone()),
                    ..Default::default()
                },
                progress,
                cancel(),
                |_| {},
            )
            .unwrap();
        }
        let hashes = |names: &[&str]| {
            names
                .iter()
                .map(|&n| (n.to_owned(), digest(content(n))))
                .collect()
        };
        let raw = fs::read(dest).unwrap();
        manifest.vaults.insert(
            file,
            Case {
                size: raw.len() as u64,
                sha256: digest(&raw),
                outer: hashes(&["tiny.bin", "note.txt"]),
                hidden: if hidden {
                    hashes(&["secret.txt"])
                } else {
                    BTreeMap::new()
                },
                recovery,
                keyfile: kf,
            },
        );
    }
    fs::write(
        root.join("fixtures_manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}
#[test]
fn extract_preview_compare_and_repair_frozen_vaults() {
    let m = manifest();
    let entropy = rpm_core::mnemonic_to_entropy(&m.recovery_phrase).unwrap();
    let key = key();
    for (name, case) in m.vaults {
        let path = root().join(&name);
        let mut outer = None;
        for (hidden, expected) in [(false, case.outer), (true, case.hidden)] {
            if expected.is_empty() {
                continue;
            }
            let mut auth_modes = vec![auth(hidden, case.keyfile.then_some(&key))];
            if !hidden && case.recovery {
                auth_modes.push(rpm_core::Auth::RecoveryKey(&entropy));
            }
            for credentials in auth_modes {
                let info =
                    inspect_header_seekable(&mut fs::File::open(&path).unwrap(), credentials)
                        .unwrap();
                if matches!(credentials, rpm_core::Auth::Password { .. }) {
                    if let Some(a) = &outer {
                        let diff = diff_metadata(a, &info.metadata).unwrap();
                        assert_eq!((diff.added.len(), diff.removed.len()), (1, 2));
                    } else {
                        outer = Some(info.metadata);
                    }
                }
                let tmp = tempfile::tempdir().unwrap();
                let result = decrypt_vault_v5(
                    &path,
                    tmp.path(),
                    credentials,
                    Arc::new(|_, _| {}),
                    cancel(),
                )
                .unwrap();
                let tree = if result.output_path.is_dir() {
                    result.output_path.as_path()
                } else {
                    tmp.path()
                };
                assert_eq!(fs::read_dir(tree).unwrap().count(), expected.len());
                for (member, hash) in &expected {
                    let data = fs::read(tree.join(member)).unwrap();
                    assert_eq!(data, content(member));
                    assert_eq!(digest(&data), *hash);
                    let preview = extract_entry_to_memory_v5(
                        &path,
                        credentials,
                        member,
                        256,
                        Arc::new(|_, _| {}),
                        cancel(),
                    )
                    .unwrap();
                    assert_eq!(preview.as_slice(), data);
                }
            }
        }
        if name.starts_with("rs_") {
            repair_copy(&path);
        }
    }

    // Cross-vault header diff between distinct frozen v4.4.0 files.
    let std_info = inspect_header_seekable(
        &mut fs::File::open(root().join("standard_uncompressed.vault")).unwrap(),
        auth(false, None),
    )
    .unwrap();
    let std_kf_info = inspect_header_seekable(
        &mut fs::File::open(root().join("standard_compressed_keyfile.vault")).unwrap(),
        auth(false, Some(&key)),
    )
    .unwrap();
    let hidden_info = inspect_header_seekable(
        &mut fs::File::open(root().join("hidden_64k.vault")).unwrap(),
        auth(true, None),
    )
    .unwrap();
    let same_content = diff_metadata(&std_info.metadata, &std_kf_info.metadata).unwrap();
    assert!(
        same_content.added.is_empty()
            && same_content.removed.is_empty()
            && same_content.changed.is_empty()
    );
    let cross_diff = diff_metadata(&std_info.metadata, &hidden_info.metadata).unwrap();
    let added_paths: Vec<&str> = cross_diff.added.iter().map(|e| e.path.as_str()).collect();
    let removed_paths: Vec<&str> = cross_diff.removed.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(added_paths, vec!["secret.txt"]);
    assert_eq!(removed_paths, vec!["note.txt", "tiny.bin"]);
}
fn repair_copy(path: &Path) {
    let tmp = tempfile::tempdir().unwrap();
    let copy = tmp.path().join("damaged");
    let original = fs::read(path).unwrap();
    let mut bad = original.clone();
    for b in &mut bad[0..512] {
        *b ^= 0xfe;
    }
    fs::write(&copy, bad).unwrap();
    assert_eq!(
        repair_vault_v5(&copy, None, cancel())
            .unwrap()
            .repaired_bytes,
        512
    );
    assert_eq!(fs::read(copy).unwrap(), original);
}
