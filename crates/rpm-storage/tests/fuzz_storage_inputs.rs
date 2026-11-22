#[path = "../../rpm-core/tests/support/fuzz.rs"]
mod fuzz;
use rpm_core::{
    encrypt_stream, inspect_header_seekable, Auth, EncryptOptions, KdfParams, VaultMetadata,
};
use rpm_storage::{
    decrypt_vault_selected_v5, decrypt_vault_v5, extract_entry_to_memory_v5, repair_vault_v5,
};
use std::{
    fs,
    path::Path,
    sync::{atomic::AtomicBool, Arc},
};

fn cancel() -> Arc<AtomicBool> {
    Arc::new(false.into())
}

fn auth() -> Auth<'static> {
    Auth::Password {
        password: b"test",
        keyfile_hash: None,
    }
}

fn reject_payload(file: &Path, root: &Path) {
    assert!(decrypt_vault_v5(file, root, auth(), Arc::new(|_, _| {}), cancel()).is_err());
    assert!(decrypt_vault_selected_v5(
        file,
        root,
        auth(),
        &["first".to_string()],
        Arc::new(|_, _| {}),
        cancel(),
    )
    .is_err());
    assert!(
        extract_entry_to_memory_v5(file, auth(), "first", 64, Arc::new(|_, _| {}), cancel())
            .is_err()
    );
    assert!(!root.exists());
}

#[test]
fn rejected_storage_inputs_leave_no_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("input");
    let output = dir.path().join("out");
    let repaired = dir.path().join("repaired");
    let fixture =
        include_bytes!("../../rpm-core/tests/fixtures/v4_4_0/standard_uncompressed.vault");
    let rs_fixture = include_bytes!("../../rpm-core/tests/fixtures/v4_4_0/rs_standard.vault");

    fuzz::corpus(|iter, rng| {
        let data = match iter % 4 {
            0 => {
                let mut buf = vec![0u8; rng.index(1025)];
                rng.fill(&mut buf);
                buf
            }
            1 => {
                let len = (fixture.len() / 8).max(1) + rng.index(fixture.len());
                let mut buf = fixture[..len.min(fixture.len())].to_vec();
                let orig = buf.clone();
                let flips = 1 + rng.index(8);
                for _ in 0..flips {
                    let pos = rng.index(buf.len());
                    buf[pos] ^= (1 + rng.index(255)) as u8;
                }
                if buf == orig {
                    buf[0] ^= 1;
                }
                buf
            }
            2 => {
                let len = 9 + rng.index(1016);
                let mut buf = vec![0u8; len];
                rng.fill(&mut buf);
                buf[..4].copy_from_slice(b"RPMV");
                buf[4] = 5;
                if rng.index(2) == 0 {
                    buf[5..9].fill(255);
                }
                buf
            }
            _ => {
                let mut buf = rs_fixture.to_vec();
                let start = 48 + rng.index(buf.len() - 48 - 1024);
                for b in &mut buf[start..start + 1024] {
                    *b ^= (1 + rng.index(255)) as u8;
                }
                buf
            }
        };
        fs::write(&file, &data).unwrap();
        assert!(inspect_header_seekable(&mut fs::File::open(&file).unwrap(), auth()).is_err());
        reject_payload(&file, &output);
        assert!(repair_vault_v5(&file, Some(&repaired), cancel()).is_err());
        assert!(!repaired.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(fs::read(&file).unwrap(), data);
    });
}

fn member(name: &[u8], kind: u8) -> Vec<u8> {
    let mut h = tar::Header::new_gnu();
    h.set_mode(0o600);
    h.set_size(0);
    h.set_entry_type(tar::EntryType::new(kind));
    if matches!(kind, b'1' | b'2') {
        h.set_link_name("../outside").unwrap();
    }
    h.as_mut_bytes()[..name.len()].copy_from_slice(name);
    h.set_cksum();
    h.as_bytes().to_vec()
}

#[test]
fn authenticated_malformed_archives_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = dir.path().join("sandbox");
    fs::create_dir(&sandbox).unwrap();
    let outside = dir.path().join("sentinel");
    fs::write(&outside, b"untouched").unwrap();
    let absolute = outside.to_string_lossy().replace('\\', "/");
    let mut cases: Vec<_> = [
        ("../escape.txt", b'0'),
        ("sub/../../escape.txt", b'0'),
        (r"sub\..\..\escape.txt", b'0'),
        (r"\escape.txt", b'0'),
        ("/tmp/escape.txt", b'0'),
        (r"C:\escape.txt", b'0'),
        (&absolute, b'0'),
        ("link", b'2'),
        ("link", b'1'),
    ]
    .iter()
    .map(|(p, t)| (member(p.as_bytes(), *t), false))
    .collect();
    cases.push((member(b"incomplete", b'0')[..100].to_vec(), false));
    cases.push((b"invalid gzip".to_vec(), true));

    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    use std::io::Write;
    gzip.write_all(&member(b"first", b'0')).unwrap();
    gzip.write_all(&[0; 1024]).unwrap();
    let mut encoded = gzip.finish().unwrap();
    let crc = encoded.len() - 8;
    encoded[crc] ^= 1;
    cases.push((encoded, true));

    for (tail, compressed) in cases {
        let mut archive = if compressed {
            Vec::new()
        } else {
            member(b"first", b'0')
        };
        archive.extend(tail);
        let options = EncryptOptions {
            kdf: KdfParams::fast_test(),
            compressed,
            ..Default::default()
        };
        let meta = VaultMetadata {
            filename: "test".into(),
            source_type: "file".into(),
            file_count: 2,
            original_size: 0,
            created_at: String::new(),
            compressed,
            files: vec![],
        };
        let file = sandbox.join("input");
        encrypt_stream(
            &mut archive.as_slice(),
            &mut fs::File::create(&file).unwrap(),
            &meta,
            b"test",
            &options,
            |_| {},
            None,
        )
        .unwrap();
        // Header inspection intentionally reads no tar bytes.
        assert_eq!(
            inspect_header_seekable(&mut fs::File::open(&file).unwrap(), auth())
                .unwrap()
                .metadata,
            meta
        );
        reject_payload(&file, &sandbox.join("out"));
        assert_eq!(fs::read_dir(&sandbox).unwrap().count(), 1);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    }
}
