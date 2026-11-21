use rand::{rngs::StdRng, RngCore, SeedableRng};
use rpm_core::constants::{DEFAULT_CHUNK_SIZE, MIN_CHUNK_SIZE};
use rpm_core::rs::{repair_vault_stream, RS_BLOCK_WIRE_SIZE};
use rpm_core::{
    check_integrity, decrypt_stream_seekable_with_kdf, decrypt_unlocked_stream, diff_metadata,
    encrypt_hidden_stream, encrypt_stream, entropy_to_mnemonic, generate_recovery_entropy,
    hash_keyfile_reader, inspect_header_seekable_with_kdf, mnemonic_to_entropy, rekey_stream,
    unlock_seekable, Auth, EncryptOptions, FileManifestEntry, HiddenEncryptOptions, KdfParams,
    RekeyOptions, SecretKey, VaultInfo, VaultMetadata, STEALTH_KDF_PARAMS, VAULT_MAGIC,
    VAULT_VERSION,
};
use sha2::{Digest, Sha256};
use std::io::Cursor;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnvelopeMode {
    Standard,
    Stealth,
    ReedSolomon,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContainerLayout {
    Unpadded,
    Padded,
    Hidden,
}

const PADDED_BYTES: u64 = 128 * 1024;
const HIDDEN_BYTES: u64 = 160 * 1024;
const TEST_CHUNK_SIZE: u32 = MIN_CHUNK_SIZE; // 16 KiB

fn pattern_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i % 251) as u8))
        .collect()
}

fn manifest_meta(name: &str, size: u64, compressed: bool, is_hidden: bool) -> VaultMetadata {
    let files = if is_hidden {
        vec![
            FileManifestEntry {
                path: "shared_same.txt".into(),
                size: 120,
                modified_unix: 1_700_000_000,
            },
            FileManifestEntry {
                path: "shared_changed.txt".into(),
                size: 512,
                modified_unix: 1_700_000_999,
            },
            FileManifestEntry {
                path: "hidden_only.txt".into(),
                size,
                modified_unix: 1_700_000_500,
            },
        ]
    } else {
        vec![
            FileManifestEntry {
                path: "shared_same.txt".into(),
                size: 120,
                modified_unix: 1_700_000_000,
            },
            FileManifestEntry {
                path: "shared_changed.txt".into(),
                size: 256,
                modified_unix: 1_700_000_100,
            },
            FileManifestEntry {
                path: "outer_only.txt".into(),
                size,
                modified_unix: 1_700_000_200,
            },
        ]
    };
    VaultMetadata {
        filename: name.into(),
        source_type: "file".into(),
        original_size: size,
        file_count: files.len() as u64,
        created_at: "2026-11-21T00:00:00Z".into(),
        compressed,
        files,
    }
}

fn keyfile_from_bytes(bytes: &[u8]) -> SecretKey {
    hash_keyfile_reader(&mut Cursor::new(bytes)).unwrap()
}

fn flip_sector(bytes: &mut [u8], offset: usize, len: usize) {
    for (i, b) in bytes[offset..offset + len].iter_mut().enumerate() {
        *b ^= ((i % 251) + 1) as u8;
    }
}

fn assert_info_matches(
    info: &VaultInfo,
    mode: EnvelopeMode,
    layout: ContainerLayout,
    is_hidden_compartment: bool,
    compressed: bool,
    has_keyfile: bool,
    kdf: KdfParams,
) {
    assert_eq!(info.version, VAULT_VERSION);
    assert_eq!(info.is_stealth, mode == EnvelopeMode::Stealth);
    assert_eq!(info.has_reed_solomon, mode == EnvelopeMode::ReedSolomon);
    assert_eq!(info.compressed, compressed);
    assert_eq!(info.has_keyfile, has_keyfile);
    assert_eq!(info.has_recovery, !is_hidden_compartment);
    assert_eq!(info.is_hidden_compartment, is_hidden_compartment);
    assert_eq!(info.argon_memory_kib, kdf.memory_kib);
    assert_eq!(info.argon_iterations, kdf.iterations);
    assert_eq!(info.argon_parallelism, kdf.parallelism);
    let expected_container = match layout {
        ContainerLayout::Unpadded => None,
        ContainerLayout::Padded => Some(PADDED_BYTES),
        ContainerLayout::Hidden => Some(HIDDEN_BYTES),
    };
    assert_eq!(info.container_size, expected_container);
}

fn run_24_configs(mode: EnvelopeMode) {
    let outer_payload = pattern_bytes(35_000, 0x11);
    let hidden_payload = pattern_bytes(20_000, 0xA7);
    let kf_outer_1 = keyfile_from_bytes(b"outer-keyfile-material-1");
    let kf_outer_2 = keyfile_from_bytes(b"outer-keyfile-material-2-rotated");
    let kf_hidden = keyfile_from_bytes(b"hidden-keyfile-material");
    let fast = KdfParams::fast_test();
    let dir = tempfile::tempdir().unwrap();
    let mut configs_run = 0usize;

    for layout in [
        ContainerLayout::Unpadded,
        ContainerLayout::Padded,
        ContainerLayout::Hidden,
    ] {
        let hidden_variants: &[(bool, bool)] = match layout {
            ContainerLayout::Hidden => {
                &[(false, false), (false, true), (true, false), (true, true)]
            }
            ContainerLayout::Unpadded | ContainerLayout::Padded => &[(false, false)],
        };
        for &outer_compress in &[false, true] {
            for &outer_kf_on in &[false, true] {
                for &(hidden_compress, hidden_kf_on) in hidden_variants {
                    configs_run += 1;

                    let entropy = generate_recovery_entropy();
                    let phrase = entropy_to_mnemonic(&entropy).unwrap();
                    let parsed_entropy = mnemonic_to_entropy(&phrase).unwrap();
                    assert_eq!(parsed_entropy.as_bytes(), entropy.as_bytes());

                    let outer_meta = manifest_meta(
                        "outer.bin",
                        outer_payload.len() as u64,
                        outer_compress,
                        false,
                    );
                    let hidden_meta = manifest_meta(
                        "hidden.bin",
                        hidden_payload.len() as u64,
                        hidden_compress,
                        true,
                    );
                    let outer_kf = outer_kf_on.then(|| kf_outer_1.clone());
                    let h_kf = (layout == ContainerLayout::Hidden && hidden_kf_on)
                        .then(|| kf_hidden.clone());

                    let mut wire = Vec::new();
                    if layout == ContainerLayout::Hidden {
                        let opts = HiddenEncryptOptions {
                            reed_solomon: mode == EnvelopeMode::ReedSolomon,
                            stealth: mode == EnvelopeMode::Stealth,
                            kdf: fast,
                            chunk_size: TEST_CHUNK_SIZE,
                            decoy_compressed: outer_compress,
                            hidden_compressed: hidden_compress,
                            decoy_recovery_key: Some(entropy.clone()),
                            decoy_keyfile_hash: outer_kf.clone(),
                            hidden_keyfile_hash: h_kf.clone(),
                            container_size_bytes: HIDDEN_BYTES,
                        };
                        encrypt_hidden_stream(
                            &mut outer_payload.as_slice(),
                            &mut hidden_payload.as_slice(),
                            &mut wire,
                            &outer_meta,
                            &hidden_meta,
                            b"OuterPass!1",
                            b"HiddenPass!2",
                            &opts,
                            |_| {},
                            |_| {},
                            None,
                        )
                        .unwrap();
                    } else {
                        let opts = EncryptOptions {
                            reed_solomon: mode == EnvelopeMode::ReedSolomon,
                            stealth: mode == EnvelopeMode::Stealth,
                            kdf: fast,
                            chunk_size: TEST_CHUNK_SIZE,
                            compressed: outer_compress,
                            recovery_key: Some(entropy.clone()),
                            keyfile_hash: outer_kf.clone(),
                            container_size_bytes: (layout == ContainerLayout::Padded)
                                .then_some(PADDED_BYTES),
                        };
                        encrypt_stream(
                            &mut outer_payload.as_slice(),
                            &mut wire,
                            &outer_meta,
                            b"OuterPass!1",
                            &opts,
                            |_| {},
                            None,
                        )
                        .unwrap();
                    }

                    // Wire header & container size invariants
                    match mode {
                        EnvelopeMode::Standard => {
                            assert_eq!(&wire[..4], &VAULT_MAGIC);
                            if layout == ContainerLayout::Padded {
                                assert_eq!(wire.len() as u64, PADDED_BYTES);
                            } else if layout == ContainerLayout::Hidden {
                                assert_eq!(wire.len() as u64, HIDDEN_BYTES);
                            }
                        }
                        EnvelopeMode::Stealth => {
                            assert_ne!(&wire[..4], &VAULT_MAGIC);
                            assert_ne!(&wire[..4], b"RPMR");
                            if layout == ContainerLayout::Padded {
                                assert_eq!(wire.len() as u64, PADDED_BYTES);
                            } else if layout == ContainerLayout::Hidden {
                                assert_eq!(wire.len() as u64, HIDDEN_BYTES);
                            }
                        }
                        EnvelopeMode::ReedSolomon => {
                            assert_eq!(&wire[..4], b"RPMR");
                            assert_eq!((wire.len() - 48) % RS_BLOCK_WIRE_SIZE, 0);
                        }
                    }

                    let vault_path = dir.path().join(format!("vault_{configs_run}.dat"));
                    std::fs::write(&vault_path, &wire).unwrap();
                    let integrity = check_integrity(&vault_path).unwrap();
                    assert!(integrity.ok, "integrity failed for config {configs_run}");
                    assert_eq!(integrity.sha256_only, mode == EnvelopeMode::Stealth);
                    assert_eq!(
                        integrity.has_reed_solomon,
                        mode == EnvelopeMode::ReedSolomon
                    );
                    assert_eq!(integrity.rs_repaired_bytes, 0);
                    assert_eq!(integrity.sha256_hex, format!("{:x}", Sha256::digest(&wire)));
                    if mode != EnvelopeMode::Stealth {
                        assert_eq!(integrity.has_keyfile, outer_kf_on);
                        assert!(integrity.has_recovery);
                    }

                    let outer_auth = Auth::Password {
                        password: b"OuterPass!1",
                        keyfile_hash: outer_kf.as_ref(),
                    };
                    let rec_auth = Auth::RecoveryKey(&parsed_entropy);

                    if mode == EnvelopeMode::ReedSolomon {
                        // Corrupt 512 contiguous bytes across header, payload, and trailing mini-header
                        let damage_offset = match configs_run % 3 {
                            0 => 0,
                            1 => 48 + RS_BLOCK_WIRE_SIZE + 128,
                            _ => wire.len() - 512,
                        };
                        let mut damaged = wire.clone();
                        flip_sector(&mut damaged, damage_offset, 512);
                        std::fs::write(&vault_path, &damaged).unwrap();

                        let dmg_report = check_integrity(&vault_path).unwrap();
                        assert!(dmg_report.ok);
                        assert!(dmg_report.has_reed_solomon);
                        assert_eq!(dmg_report.rs_repaired_bytes, 512);
                        assert_eq!(
                            dmg_report.sha256_hex,
                            format!("{:x}", Sha256::digest(&damaged))
                        );

                        for auth in [outer_auth, rec_auth] {
                            let info = inspect_header_seekable_with_kdf(
                                &mut Cursor::new(&damaged),
                                auth,
                                &fast,
                            )
                            .unwrap();
                            assert_info_matches(
                                &info,
                                mode,
                                layout,
                                false,
                                outer_compress,
                                outer_kf_on,
                                fast,
                            );
                            let mut out = Vec::new();
                            decrypt_stream_seekable_with_kdf(
                                &mut Cursor::new(&damaged),
                                &mut out,
                                auth,
                                &fast,
                                |_| {},
                                None,
                            )
                            .unwrap();
                            assert_eq!(out, outer_payload);
                        }

                        if layout == ContainerLayout::Hidden {
                            let hidden_auth = Auth::Password {
                                password: b"HiddenPass!2",
                                keyfile_hash: h_kf.as_ref(),
                            };
                            let h_info = inspect_header_seekable_with_kdf(
                                &mut Cursor::new(&damaged),
                                hidden_auth,
                                &fast,
                            )
                            .unwrap();
                            assert_info_matches(
                                &h_info,
                                mode,
                                layout,
                                true,
                                hidden_compress,
                                hidden_kf_on,
                                fast,
                            );
                            let mut h_out = Vec::new();
                            decrypt_stream_seekable_with_kdf(
                                &mut Cursor::new(&damaged),
                                &mut h_out,
                                hidden_auth,
                                &fast,
                                |_| {},
                                None,
                            )
                            .unwrap();
                            assert_eq!(h_out, hidden_payload);

                            let diff = diff_metadata(&outer_meta, &h_info.metadata).unwrap();
                            assert_eq!(diff.unchanged.len(), 1);
                            assert_eq!(diff.changed.len(), 1);
                            assert_eq!(diff.removed.len(), 1);
                            assert_eq!(diff.added.len(), 1);
                        }

                        let mut repaired = Vec::new();
                        let rep_report =
                            repair_vault_stream(&mut Cursor::new(&damaged), &mut repaired, None)
                                .unwrap();
                        assert_eq!(rep_report.repaired_bytes, 512);
                        assert_eq!(rep_report.header_repaired, damage_offset == 0);
                        assert_eq!(repaired, wire);
                    } else {
                        for auth in [outer_auth, rec_auth] {
                            let mut r = Cursor::new(&wire);
                            let info = inspect_header_seekable_with_kdf(&mut r, auth, &fast)
                                .expect("inspect outer");
                            assert_info_matches(
                                &info,
                                mode,
                                layout,
                                false,
                                outer_compress,
                                outer_kf_on,
                                fast,
                            );
                            assert_eq!(info.metadata.original_size, outer_payload.len() as u64);

                            let mut out = Vec::new();
                            decrypt_stream_seekable_with_kdf(
                                &mut Cursor::new(&wire),
                                &mut out,
                                auth,
                                &fast,
                                |_| {},
                                None,
                            )
                            .expect("decrypt outer");
                            assert_eq!(out, outer_payload);
                        }

                        if layout == ContainerLayout::Hidden {
                            let hidden_auth = Auth::Password {
                                password: b"HiddenPass!2",
                                keyfile_hash: h_kf.as_ref(),
                            };
                            let h_info = inspect_header_seekable_with_kdf(
                                &mut Cursor::new(&wire),
                                hidden_auth,
                                &fast,
                            )
                            .expect("inspect hidden");
                            assert_info_matches(
                                &h_info,
                                mode,
                                layout,
                                true,
                                hidden_compress,
                                hidden_kf_on,
                                fast,
                            );
                            let mut h_out = Vec::new();
                            decrypt_stream_seekable_with_kdf(
                                &mut Cursor::new(&wire),
                                &mut h_out,
                                hidden_auth,
                                &fast,
                                |_| {},
                                None,
                            )
                            .expect("decrypt hidden");
                            assert_eq!(h_out, hidden_payload);

                            let diff = diff_metadata(&outer_meta, &h_info.metadata).unwrap();
                            assert_eq!(diff.unchanged.len(), 1);
                            assert_eq!(diff.changed.len(), 1);
                            assert_eq!(diff.removed.len(), 1);
                            assert_eq!(diff.added.len(), 1);
                        }
                    }

                    // Standard + Unpadded O(1) Re-Key transitions + recovery preservation
                    if mode == EnvelopeMode::Standard && layout == ContainerLayout::Unpadded {
                        let transitions: Vec<Option<SecretKey>> = if outer_kf_on {
                            vec![Some(kf_outer_1.clone()), Some(kf_outer_2.clone()), None]
                        } else {
                            vec![None, Some(kf_outer_1.clone())]
                        };
                        for (step, target_kf) in transitions.into_iter().enumerate() {
                            let new_pw = format!("RotatedPass!{configs_run}_{step}");
                            let mut rekeyed = Vec::new();
                            rekey_stream(
                                &mut wire.as_slice(),
                                &mut rekeyed,
                                &RekeyOptions {
                                    old_password: b"OuterPass!1",
                                    new_password: new_pw.as_bytes(),
                                    old_keyfile_hash: outer_kf.as_ref(),
                                    new_keyfile_hash: target_kf.as_ref(),
                                    new_kdf: Some(fast),
                                },
                                None,
                            )
                            .unwrap();

                            let mut out_pw = Vec::new();
                            decrypt_stream_seekable_with_kdf(
                                &mut Cursor::new(&rekeyed),
                                &mut out_pw,
                                Auth::Password {
                                    password: new_pw.as_bytes(),
                                    keyfile_hash: target_kf.as_ref(),
                                },
                                &fast,
                                |_| {},
                                None,
                            )
                            .unwrap();
                            assert_eq!(out_pw, outer_payload);

                            let mut out_rec = Vec::new();
                            decrypt_stream_seekable_with_kdf(
                                &mut Cursor::new(&rekeyed),
                                &mut out_rec,
                                rec_auth,
                                &fast,
                                |_| {},
                                None,
                            )
                            .unwrap();
                            assert_eq!(out_rec, outer_payload);
                        }
                    }
                }
            }
        }
    }

    assert_eq!(configs_run, 24);
}

#[test]
fn core_vault_matrix_standard_24() {
    run_24_configs(EnvelopeMode::Standard);
}

#[test]
fn core_vault_matrix_stealth_24() {
    run_24_configs(EnvelopeMode::Stealth);
}

#[test]
fn core_vault_matrix_reed_solomon_24() {
    run_24_configs(EnvelopeMode::ReedSolomon);
}

#[test]
fn core_chunk_size_and_payload_boundary_matrix() {
    let fast = KdfParams::fast_test();
    let mut rng = StdRng::seed_from_u64(0xC400_512E);
    let mut count = 0usize;

    for mode in [
        EnvelopeMode::Standard,
        EnvelopeMode::Stealth,
        EnvelopeMode::ReedSolomon,
    ] {
        for chunk_size in [16 * 1024u32, 64 * 1024u32] {
            let cs = chunk_size as usize;
            for compressed in [false, true] {
                for len in [0usize, 1, cs - 1, cs, cs + 1, 2 * cs + 17] {
                    let mut payload = vec![0u8; len];
                    rng.fill_bytes(&mut payload);
                    let meta = manifest_meta("chunk.bin", len as u64, compressed, false);
                    let mut wire = Vec::new();
                    encrypt_stream(
                        &mut payload.as_slice(),
                        &mut wire,
                        &meta,
                        b"ChunkPass!1",
                        &EncryptOptions {
                            reed_solomon: mode == EnvelopeMode::ReedSolomon,
                            stealth: mode == EnvelopeMode::Stealth,
                            kdf: fast,
                            chunk_size,
                            compressed,
                            recovery_key: None,
                            keyfile_hash: None,
                            container_size_bytes: None,
                        },
                        |_| {},
                        None,
                    )
                    .unwrap();

                    let mut out = Vec::new();
                    decrypt_stream_seekable_with_kdf(
                        &mut Cursor::new(&wire),
                        &mut out,
                        Auth::Password {
                            password: b"ChunkPass!1",
                            keyfile_hash: None,
                        },
                        &fast,
                        |_| {},
                        None,
                    )
                    .unwrap();
                    assert_eq!(out, payload);
                    count += 1;
                }
            }
        }

        // Default 1 MiB chunk boundary check across all 3 envelope modes
        let big_len = (DEFAULT_CHUNK_SIZE as usize) + 13;
        let big_payload = pattern_bytes(big_len, 0x33);
        let meta = manifest_meta("one_mib.bin", big_len as u64, false, false);
        let mut wire = Vec::new();
        encrypt_stream(
            &mut big_payload.as_slice(),
            &mut wire,
            &meta,
            b"DefaultChunk!1",
            &EncryptOptions {
                reed_solomon: mode == EnvelopeMode::ReedSolomon,
                stealth: mode == EnvelopeMode::Stealth,
                kdf: fast,
                chunk_size: DEFAULT_CHUNK_SIZE,
                compressed: false,
                recovery_key: None,
                keyfile_hash: None,
                container_size_bytes: None,
            },
            |_| {},
            None,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream_seekable_with_kdf(
            &mut Cursor::new(&wire),
            &mut out,
            Auth::Password {
                password: b"DefaultChunk!1",
                keyfile_hash: None,
            },
            &fast,
            |_| {},
            None,
        )
        .unwrap();
        assert_eq!(out, big_payload);
        count += 1;
    }

    assert_eq!(count, 75);
}

#[test]
fn core_argon2id_kdf_profile_matrix() {
    let profiles = [
        KdfParams {
            memory_kib: 16_384,
            iterations: 1,
            parallelism: 1,
        },
        KdfParams {
            memory_kib: 16_384,
            iterations: 2,
            parallelism: 4,
        },
        KdfParams {
            memory_kib: 32_768,
            iterations: 2,
            parallelism: 2,
        },
        KdfParams::owasp_default(),
    ];

    let outer = b"argon2id outer matrix payload".to_vec();
    let hidden = b"argon2id hidden matrix payload".to_vec();

    for kdf in profiles {
        kdf.validate().unwrap();
        for variant in 0..4 {
            let mut wire = Vec::new();
            let (is_hidden, rs, container) = match variant {
                0 => (false, false, None),
                1 => (false, false, Some(PADDED_BYTES)),
                2 => (true, false, Some(HIDDEN_BYTES)),
                _ => (false, true, None),
            };
            if is_hidden {
                encrypt_hidden_stream(
                    &mut outer.as_slice(),
                    &mut hidden.as_slice(),
                    &mut wire,
                    &manifest_meta("o.bin", outer.len() as u64, false, false),
                    &manifest_meta("h.bin", hidden.len() as u64, false, true),
                    b"KdfOuter!1",
                    b"KdfHidden!2",
                    &HiddenEncryptOptions {
                        reed_solomon: rs,
                        stealth: false,
                        kdf,
                        chunk_size: TEST_CHUNK_SIZE,
                        container_size_bytes: container.unwrap(),
                        ..Default::default()
                    },
                    |_| {},
                    |_| {},
                    None,
                )
                .unwrap();
                let auth_h = Auth::Password {
                    password: b"KdfHidden!2",
                    keyfile_hash: None,
                };
                let mut r_h = Cursor::new(&wire);
                let unlocked_h = unlock_seekable(&mut r_h, auth_h).unwrap();
                let info_h = unlocked_h.vault_info();
                assert_eq!(info_h.argon_memory_kib, kdf.memory_kib);
                assert_eq!(info_h.argon_iterations, kdf.iterations);
                assert_eq!(info_h.argon_parallelism, kdf.parallelism);
            } else {
                encrypt_stream(
                    &mut outer.as_slice(),
                    &mut wire,
                    &manifest_meta("o.bin", outer.len() as u64, false, false),
                    b"KdfOuter!1",
                    &EncryptOptions {
                        reed_solomon: rs,
                        stealth: false,
                        kdf,
                        chunk_size: TEST_CHUNK_SIZE,
                        container_size_bytes: container,
                        ..Default::default()
                    },
                    |_| {},
                    None,
                )
                .unwrap();
            }

            let auth = Auth::Password {
                password: b"KdfOuter!1",
                keyfile_hash: None,
            };
            let mut r = Cursor::new(&wire);
            let unlocked = unlock_seekable(&mut r, auth).unwrap();
            let info = unlocked.vault_info();
            assert_eq!(info.argon_memory_kib, kdf.memory_kib);
            assert_eq!(info.argon_iterations, kdf.iterations);
            assert_eq!(info.argon_parallelism, kdf.parallelism);
            let mut out = Vec::new();
            decrypt_unlocked_stream(&mut r, &mut out, &unlocked, |_| {}, None).unwrap();
            assert_eq!(out, outer);
        }
    }

    // Production Stealth KDF profile (64 MiB / 3 / 4) across Unpadded, Padded, Hidden
    for layout in [
        ContainerLayout::Unpadded,
        ContainerLayout::Padded,
        ContainerLayout::Hidden,
    ] {
        let mut wire = Vec::new();
        if layout == ContainerLayout::Hidden {
            encrypt_hidden_stream(
                &mut outer.as_slice(),
                &mut hidden.as_slice(),
                &mut wire,
                &manifest_meta("o.bin", outer.len() as u64, false, false),
                &manifest_meta("h.bin", hidden.len() as u64, false, true),
                b"StealthOut!1",
                b"StealthHid!2",
                &HiddenEncryptOptions {
                    stealth: true,
                    kdf: STEALTH_KDF_PARAMS,
                    chunk_size: TEST_CHUNK_SIZE,
                    container_size_bytes: HIDDEN_BYTES,
                    ..Default::default()
                },
                |_| {},
                |_| {},
                None,
            )
            .unwrap();
            let mut r_h = Cursor::new(&wire);
            let unlocked_h = unlock_seekable(
                &mut r_h,
                Auth::Password {
                    password: b"StealthHid!2",
                    keyfile_hash: None,
                },
            )
            .unwrap();
            let mut h_out = Vec::new();
            decrypt_unlocked_stream(&mut r_h, &mut h_out, &unlocked_h, |_| {}, None).unwrap();
            assert_eq!(h_out, hidden);
        } else {
            encrypt_stream(
                &mut outer.as_slice(),
                &mut wire,
                &manifest_meta("o.bin", outer.len() as u64, false, false),
                b"StealthOut!1",
                &EncryptOptions {
                    stealth: true,
                    kdf: STEALTH_KDF_PARAMS,
                    chunk_size: TEST_CHUNK_SIZE,
                    container_size_bytes: (layout == ContainerLayout::Padded)
                        .then_some(PADDED_BYTES),
                    ..Default::default()
                },
                |_| {},
                None,
            )
            .unwrap();
        }
        let mut r = Cursor::new(&wire);
        let unlocked = unlock_seekable(
            &mut r,
            Auth::Password {
                password: b"StealthOut!1",
                keyfile_hash: None,
            },
        )
        .unwrap();
        let info = unlocked.vault_info();
        assert_eq!(info.argon_memory_kib, STEALTH_KDF_PARAMS.memory_kib);
        assert_eq!(info.argon_iterations, STEALTH_KDF_PARAMS.iterations);
        assert_eq!(info.argon_parallelism, STEALTH_KDF_PARAMS.parallelism);
        let mut out = Vec::new();
        decrypt_unlocked_stream(&mut r, &mut out, &unlocked, |_| {}, None).unwrap();
        assert_eq!(out, outer);
    }
}

#[test]
fn core_diff_full_state_matrix() {
    let entry = |path: &str, size: u64, modified_unix: u64| FileManifestEntry {
        path: path.into(),
        size,
        modified_unix,
    };
    let meta = |files: Vec<FileManifestEntry>| VaultMetadata {
        filename: "m".into(),
        source_type: "folder".into(),
        original_size: files.iter().map(|f| f.size).sum(),
        file_count: files.len() as u64,
        created_at: String::new(),
        compressed: false,
        files,
    };

    let empty = meta(vec![]);
    let full = meta(vec![
        entry("same.txt", 10, 100),
        entry("size_changed.txt", 10, 200),
        entry("mtime_changed.txt", 10, 300),
        entry("both_changed.txt", 10, 400),
        entry("removed_only.txt", 50, 500),
    ]);
    let next = meta(vec![
        entry("same.txt", 10, 100),
        entry("size_changed.txt", 25, 200),
        entry("mtime_changed.txt", 10, 301),
        entry("both_changed.txt", 99, 499),
        entry("added_only.txt", 75, 600),
    ]);

    // Empty vs empty
    let d0 = diff_metadata(&empty, &empty).unwrap();
    assert!(
        d0.added.is_empty()
            && d0.removed.is_empty()
            && d0.changed.is_empty()
            && d0.unchanged.is_empty()
    );

    // Empty <-> nonempty symmetry
    let d_add = diff_metadata(&empty, &full).unwrap();
    assert_eq!(d_add.added.len(), 5);
    assert!(d_add.removed.is_empty() && d_add.changed.is_empty() && d_add.unchanged.is_empty());
    let d_rem = diff_metadata(&full, &empty).unwrap();
    assert_eq!(d_rem.removed.len(), 5);
    assert!(d_rem.added.is_empty() && d_rem.changed.is_empty() && d_rem.unchanged.is_empty());

    // Identical
    let d_same = diff_metadata(&full, &full).unwrap();
    assert_eq!(d_same.unchanged.len(), 5);
    assert!(d_same.added.is_empty() && d_same.removed.is_empty() && d_same.changed.is_empty());

    // Forward A -> B and reverse B -> A
    let fwd = diff_metadata(&full, &next).unwrap();
    let rev = diff_metadata(&next, &full).unwrap();
    assert_eq!(fwd.added, vec![entry("added_only.txt", 75, 600)]);
    assert_eq!(fwd.removed, vec![entry("removed_only.txt", 50, 500)]);
    assert_eq!(fwd.unchanged, vec![entry("same.txt", 10, 100)]);
    assert_eq!(
        fwd.changed
            .iter()
            .map(|c| c.after.path.as_str())
            .collect::<Vec<_>>(),
        vec!["both_changed.txt", "mtime_changed.txt", "size_changed.txt"]
    );
    assert_eq!(rev.added, fwd.removed);
    assert_eq!(rev.removed, fwd.added);
    assert_eq!(rev.unchanged, fwd.unchanged);
    assert_eq!(rev.changed.len(), fwd.changed.len());
}
