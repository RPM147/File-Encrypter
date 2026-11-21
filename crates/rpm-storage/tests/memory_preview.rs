use rpm_core::{constants::MIN_CHUNK_SIZE, Auth, CryptoError, EncryptOptions, KdfParams};
use rpm_storage::{encrypt_sources_v5, extract_entry_to_memory_v5, StorageError};
use std::{
    fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[test]
fn preview_returns_only_after_final_authentication() {
    let tmp = tempfile::tempdir().unwrap();
    let inputs = tmp.path().join("sources");
    fs::create_dir(&inputs).unwrap();
    let first = inputs.join("first");
    let last = inputs.join("last");
    fs::write(&first, b"preview").unwrap();
    fs::write(&last, vec![3; 10 * MIN_CHUNK_SIZE as usize]).unwrap();
    let vault = tmp.path().join("test.vault");
    let cancel = Arc::new(AtomicBool::new(false));
    encrypt_sources_v5(
        &[first, last],
        &vault,
        b"pw",
        &EncryptOptions {
            kdf: KdfParams::fast_test(),
            compressed: false,
            chunk_size: MIN_CHUNK_SIZE,
            ..Default::default()
        },
        Arc::new(|_, _| {}),
        cancel.clone(),
        |_| {},
    )
    .unwrap();
    let auth = || Auth::Password {
        password: b"pw",
        keyfile_hash: None,
    };
    let preview = |path, max| {
        extract_entry_to_memory_v5(
            &vault,
            auth(),
            path,
            max,
            Arc::new(|_, _| {}),
            cancel.clone(),
        )
    };
    assert_eq!(&preview("./first", 7).unwrap()[..], b"preview");
    assert!(matches!(
        preview("first", 6),
        Err(StorageError::LimitExceeded(_))
    ));
    for path in ["missing", "../first", "/first"] {
        assert!(matches!(
            preview(path, 7),
            Err(StorageError::InvalidPath(_))
        ));
    }
    let stop = cancel.clone();
    assert!(extract_entry_to_memory_v5(
        &vault,
        auth(),
        "first",
        7,
        Arc::new(move |_, _| stop.store(true, Ordering::Relaxed)),
        cancel.clone()
    )
    .is_err());
    cancel.store(false, Ordering::Relaxed);
    let mut damaged = fs::read(&vault).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&vault, damaged).unwrap();
    assert!(matches!(
        preview("first", 7),
        Err(StorageError::Crypto(CryptoError::AuthenticationFailed))
    ));
    assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 2);
    assert_eq!(fs::read_dir(inputs).unwrap().count(), 2);
}
