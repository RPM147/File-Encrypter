#[path = "support/golden.rs"]
mod golden;
use golden::*;
use rpm_core::*;
use sha2::{Digest, Sha256};
use std::{fs, io::Cursor};
#[test]
fn frozen_v4_4_0_wire_compatibility() {
    let m = manifest();
    let entropy = mnemonic_to_entropy(&m.recovery_phrase).unwrap();
    assert_eq!(m.recovery_phrase.split_whitespace().count(), 24);
    let key = key();
    let total: u64 = fs::read_dir(root())
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .sum();
    assert!(total < 600 * 1024);
    for (name, case) in m.vaults {
        let path = root().join(&name);
        let raw = fs::read(&path).unwrap();
        assert_eq!(raw.len() as u64, case.size, "{name}");
        assert_eq!(format!("{:x}", Sha256::digest(&raw)), case.sha256, "{name}");
        let integrity = check_integrity(&path).unwrap();
        assert!(integrity.ok);
        assert_eq!(integrity.sha256_hex, case.sha256);
        assert_eq!(integrity.sha256_only, name.starts_with("stealth"));
        assert_eq!(integrity.has_reed_solomon, name.starts_with("rs_"));
        assert_eq!(integrity.rs_repaired_bytes, 0);
        let mut credentials = vec![(auth(false, case.keyfile.then_some(&key)), false)];
        if case.recovery {
            credentials.push((Auth::RecoveryKey(&entropy), false));
        }
        if !case.hidden.is_empty() {
            credentials.push((auth(true, None), true));
        }
        let mut outer = None;
        for (auth, hidden) in credentials {
            let mut reader = Cursor::new(&raw);
            let unlocked = unlock_seekable(&mut reader, auth).unwrap();
            let info = unlocked.vault_info();
            assert_eq!(info.is_hidden_compartment, hidden);
            assert_eq!(info.compressed, !name.contains("uncompressed"));
            assert_eq!(info.has_keyfile, case.keyfile);
            assert_eq!(info.has_recovery, case.recovery);
            assert_eq!(info.is_stealth, name.starts_with("stealth"));
            assert_eq!(info.container_size, name.contains("64k").then_some(65536));
            let kdf = if info.is_stealth {
                STEALTH_KDF_PARAMS
            } else {
                KdfParams::fast_test()
            };
            assert_eq!(
                (
                    info.argon_memory_kib,
                    info.argon_iterations,
                    info.argon_parallelism
                ),
                (kdf.memory_kib, kdf.iterations, kdf.parallelism)
            );
            let mut decoded = vec![];
            decrypt_unlocked_stream(&mut reader, &mut decoded, &unlocked, |_| {}, None).unwrap();
            assert!(!decoded.is_empty());
            if !hidden {
                if let Some(previous) = &outer {
                    assert_eq!(previous, &decoded);
                }
                outer = Some(decoded);
            }
        }
        if name.starts_with("rs_") {
            let mut bad = raw.clone();
            for b in &mut bad[127..639] {
                *b ^= 0xff;
            }
            let mut fixed = vec![];
            let r = repair_vault_stream(&mut Cursor::new(bad), &mut fixed, None).unwrap();
            assert_eq!(r.repaired_bytes, 512);
            assert_eq!(fixed, raw);
        }
    }
}
