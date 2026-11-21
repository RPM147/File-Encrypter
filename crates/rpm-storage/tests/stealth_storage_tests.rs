use rpm_core::{Auth, EncryptOptions, HiddenEncryptOptions, KdfParams};
use rpm_storage::{
    decrypt_vault_v5_with_stealth_kdf, encrypt_hidden_sources_v5, encrypt_sources_v5,
    extract_entry_to_memory_v5_with_stealth_kdf,
};
use std::{
    fs,
    sync::{atomic::AtomicBool, Arc},
};

#[test]
fn stream_to_destination_and_restore_or_preview_either_compartment() {
    for hidden in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let a = dir.path().join("public");
        let b = dir.path().join("secret");
        fs::write(&a, b"outside").unwrap();
        fs::write(&b, b"inside").unwrap();
        let path = output.path().join("opaque.dat");
        let cancel = Arc::new(AtomicBool::new(false));
        let kdf = KdfParams::fast_test();
        let dst = path.clone();
        let progress: Arc<dyn Fn(u64, u64) + Send + Sync> = Arc::new(move |_, _| {
            // Check during encryption as well as after it, catching transient sibling files.
            let files: Vec<_> = fs::read_dir(dst.parent().unwrap())
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            assert_eq!(files, std::slice::from_ref(&dst));
        });
        if hidden {
            let opts = HiddenEncryptOptions {
                stealth: true,
                kdf,
                container_size_bytes: 256 * 1024,
                ..Default::default()
            };
            encrypt_hidden_sources_v5(
                &[a],
                &[b],
                &path,
                b"first",
                b"second",
                &opts,
                progress,
                cancel.clone(),
                |_| {},
            )
            .unwrap();
        } else {
            let opts = EncryptOptions {
                stealth: true,
                kdf,
                ..Default::default()
            };
            encrypt_sources_v5(
                &[a],
                &path,
                b"first",
                &opts,
                progress,
                cancel.clone(),
                |_| {},
            )
            .unwrap();
        }
        let mut members = vec![("public", "first", "outside")];
        if hidden {
            members.push(("secret", "second", "inside"));
        }
        for (name, pw, expected) in members {
            let auth = Auth::Password {
                password: pw.as_bytes(),
                keyfile_hash: None,
            };
            let preview = extract_entry_to_memory_v5_with_stealth_kdf(
                &path,
                auth,
                name,
                16,
                &kdf,
                Arc::new(|_, _| {}),
                cancel.clone(),
            )
            .unwrap();
            assert_eq!(preview.as_slice(), expected.as_bytes());
            assert_eq!(fs::read_dir(output.path()).unwrap().count(), 1);
            let selection = [name.to_owned()];
            for selected in [None, Some(selection.as_slice())] {
                let restore = tempfile::tempdir().unwrap();
                let summary = decrypt_vault_v5_with_stealth_kdf(
                    &path,
                    restore.path(),
                    auth,
                    selected,
                    &kdf,
                    Arc::new(|_, _| {}),
                    cancel.clone(),
                )
                .unwrap();
                assert_eq!(summary.files_extracted, 1);
                assert_eq!(
                    fs::read(restore.path().join(name)).unwrap(),
                    expected.as_bytes()
                );
            }
        }
    }
}

#[test]
fn failed_encryption_preserves_existing_files_and_cleans_fresh_destination() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::write(&source, b"test").unwrap();
    let target = dir.path().join("output");
    let opts = EncryptOptions {
        stealth: true,
        kdf: KdfParams::fast_test(),
        ..Default::default()
    };
    let attempt = || {
        encrypt_sources_v5(
            std::slice::from_ref(&source),
            &target,
            b"",
            &opts,
            Arc::new(|_, _| {}),
            Arc::new(AtomicBool::new(false)),
            |_| {},
        )
    };
    assert!(attempt().is_err());
    assert!(!target.exists());
    fs::write(&target, b"existing").unwrap();
    assert!(attempt().is_err());
    assert_eq!(fs::read(target).unwrap(), b"existing");
}
