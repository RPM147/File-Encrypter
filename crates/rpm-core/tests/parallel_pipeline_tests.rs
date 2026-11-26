use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use rpm_core::constants::{AES_TAG_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use rpm_core::header::read_header_and_meta;
use rpm_core::rs::{RS_BLOCK_DATA_CAP, RS_BLOCK_WIRE_SIZE};
use rpm_core::{
    check_integrity_reader_with_threads, decrypt_stream_seekable_with_kdf_and_threads,
    decrypt_stream_seekable_with_threads, decrypt_stream_with_threads, default_pipeline_threads,
    encrypt_hidden_stream_with_threads, encrypt_stream_with_threads,
    inspect_header_seekable_with_kdf_and_threads, repair_vault_stream_with_threads,
    resolve_pipeline_threads, Auth, CryptoError, EncryptOptions, FileManifestEntry,
    HiddenEncryptOptions, KdfParams, RsEncoderWriter, RsSeekableReader, VaultMetadata,
    MAX_PIPELINE_THREADS,
};
use sha2::{Digest, Sha256};

fn meta(name: &str, size: usize) -> VaultMetadata {
    VaultMetadata {
        filename: name.into(),
        source_type: "file".into(),
        original_size: size as u64,
        file_count: 1,
        created_at: "2026-11-26T00:00:00Z".into(),
        compressed: false,
        files: vec![],
    }
}

fn auth(pw: &[u8]) -> Auth<'_> {
    Auth::Password {
        password: pw,
        keyfile_hash: None,
    }
}

fn damage(bytes: &mut [u8], start: usize, len: usize) {
    for (i, b) in bytes[start..start + len].iter_mut().enumerate() {
        *b ^= ((i % 251) + 1) as u8;
    }
}

#[test]
fn resolve_thread_count_bounds_and_defaults() {
    assert!((1..=MAX_PIPELINE_THREADS).contains(&default_pipeline_threads()));
    assert_eq!(resolve_pipeline_threads(0), default_pipeline_threads());
    assert_eq!(resolve_pipeline_threads(1), 1);
    assert_eq!(resolve_pipeline_threads(4), 4);
    assert_eq!(
        resolve_pipeline_threads(MAX_PIPELINE_THREADS),
        MAX_PIPELINE_THREADS
    );
    assert_eq!(
        resolve_pipeline_threads(MAX_PIPELINE_THREADS + 500),
        MAX_PIPELINE_THREADS
    );
}

#[test]
fn rs_encoder_is_bit_exact_across_all_thread_counts_and_fragmented_writes() {
    let mut rng = StdRng::seed_from_u64(0xB17_E4AC);
    // ~2.5 MiB -> ~170 RS blocks, spanning multiple 64-block parallel batches + partial tail.
    let mut payload = vec![0u8; RS_BLOCK_DATA_CAP * 170 + 731];
    rng.fill_bytes(&mut payload);

    let encode_with = |threads: usize, write_sizes: &[usize]| -> Vec<u8> {
        let mut enc = RsEncoderWriter::with_threads(Vec::new(), threads).unwrap();
        let mut pos = 0usize;
        let mut step = 0usize;
        while pos < payload.len() {
            let take = write_sizes[step % write_sizes.len()].min(payload.len() - pos);
            enc.write_all(&payload[pos..pos + take]).unwrap();
            if step.is_multiple_of(19) {
                enc.flush().unwrap();
            }
            pos += take;
            step += 1;
        }
        enc.finish().unwrap()
    };

    let baseline = encode_with(1, &[RS_BLOCK_DATA_CAP]);
    for threads in [0, 2, 4, 8, 16] {
        let fragmented = encode_with(threads, &[1, 17, 4096, RS_BLOCK_DATA_CAP - 1, 50_000]);
        assert_eq!(
            fragmented, baseline,
            "RS wire bytes must be bit-identical for threads={threads}"
        );
    }

    // Empty and exact-block boundary streams are also bit-identical across thread counts.
    for size in [0, 1, RS_BLOCK_DATA_CAP, RS_BLOCK_DATA_CAP * 2] {
        let slice = &payload[..size];
        let mut w1 = RsEncoderWriter::with_threads(Vec::new(), 1).unwrap();
        w1.write_all(slice).unwrap();
        let wire1 = w1.finish().unwrap();

        let mut w8 = RsEncoderWriter::with_threads(Vec::new(), 8).unwrap();
        w8.write_all(slice).unwrap();
        let wire8 = w8.finish().unwrap();
        assert_eq!(wire8, wire1, "boundary size={size}");

        for threads in [1, 2, 8, 0] {
            let mut r = RsSeekableReader::with_threads(Cursor::new(&wire8), threads).unwrap();
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            assert_eq!(out, slice, "decode boundary size={size} threads={threads}");
            assert_eq!(r.repaired_bytes(), 0);
        }
    }
}

#[test]
fn cross_thread_interoperability_across_all_vault_modes() {
    let mut rng = StdRng::seed_from_u64(0xC055_743D);
    let mut outer_data = vec![0u8; MIN_CHUNK_SIZE as usize * 18 + 333];
    let mut hidden_data = vec![0u8; MIN_CHUNK_SIZE as usize * 10 + 123];
    rng.fill_bytes(&mut outer_data);
    rng.fill_bytes(&mut hidden_data);

    let thread_counts = [1usize, 2, 4, 8, 0];

    // 1. Standard, Padded, Stealth, and RS vaults across thread counts.
    for (label, stealth, reed_solomon, container_size) in [
        ("standard", false, false, None),
        ("padded", false, false, Some(512 * 1024)),
        ("stealth", true, false, None),
        ("stealth_padded", true, false, Some(512 * 1024)),
        ("rs", false, true, None),
    ] {
        for &enc_t in &[1usize, 4, 8] {
            let opts = EncryptOptions {
                stealth,
                reed_solomon,
                kdf: KdfParams::fast_test(),
                chunk_size: MIN_CHUNK_SIZE,
                compressed: false,
                container_size_bytes: container_size,
                ..Default::default()
            };
            let mut vault = Vec::new();
            let summary = encrypt_stream_with_threads(
                &mut Cursor::new(&outer_data),
                &mut vault,
                &meta(label, outer_data.len()),
                b"CrossPw!1",
                &opts,
                enc_t,
                |_| {},
                None,
            )
            .unwrap();
            assert_eq!(summary.bytes_encrypted, outer_data.len() as u64);
            assert_eq!(summary.chunks_written, 19);

            for &dec_t in &thread_counts {
                let mut out = Vec::new();
                decrypt_stream_seekable_with_kdf_and_threads(
                    &mut Cursor::new(&vault),
                    &mut out,
                    auth(b"CrossPw!1"),
                    &KdfParams::fast_test(),
                    dec_t,
                    |_| {},
                    None,
                )
                .unwrap();
                assert_eq!(out, outer_data, "mode={label} enc_t={enc_t} dec_t={dec_t}");
            }
        }
    }

    // 2. Hidden compartments (standard, stealth, RS) across thread counts.
    for (label, stealth, reed_solomon) in [
        ("hidden_std", false, false),
        ("hidden_stealth", true, false),
        ("hidden_rs", false, true),
    ] {
        let opts = HiddenEncryptOptions {
            stealth,
            reed_solomon,
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            container_size_bytes: 768 * 1024,
            decoy_compressed: false,
            hidden_compressed: false,
            ..Default::default()
        };
        let mut container = Vec::new();
        let summary = encrypt_hidden_stream_with_threads(
            &mut Cursor::new(&outer_data),
            &mut Cursor::new(&hidden_data),
            &mut container,
            &meta("decoy.bin", outer_data.len()),
            &meta("hidden.bin", hidden_data.len()),
            b"DecoyPw!1",
            b"HiddenPw!2",
            &opts,
            8,
            |_| {},
            |_| {},
            None,
        )
        .unwrap();
        assert_eq!(summary.decoy.bytes_encrypted, outer_data.len() as u64);
        assert_eq!(summary.hidden_bytes_encrypted, hidden_data.len() as u64);

        for &dec_t in &[1usize, 4, 8] {
            let mut dec_outer = Vec::new();
            decrypt_stream_seekable_with_kdf_and_threads(
                &mut Cursor::new(&container),
                &mut dec_outer,
                auth(b"DecoyPw!1"),
                &KdfParams::fast_test(),
                dec_t,
                |_| {},
                None,
            )
            .unwrap();
            assert_eq!(dec_outer, outer_data, "{label} outer dec_t={dec_t}");

            let mut dec_hidden = Vec::new();
            decrypt_stream_seekable_with_kdf_and_threads(
                &mut Cursor::new(&container),
                &mut dec_hidden,
                auth(b"HiddenPw!2"),
                &KdfParams::fast_test(),
                dec_t,
                |_| {},
                None,
            )
            .unwrap();
            assert_eq!(dec_hidden, hidden_data, "{label} hidden dec_t={dec_t}");
        }
    }
}

#[test]
fn multi_batch_rs_repair_integrity_and_uncorrectable_block_isolation() {
    let mut rng = StdRng::seed_from_u64(0x5EED_B47C);
    // ~2.4 MiB -> >160 RS blocks spanning multiple 64-block parallel batches.
    let mut plain = vec![0u8; 2_400_000];
    rng.fill_bytes(&mut plain);

    let opts = EncryptOptions {
        reed_solomon: true,
        kdf: KdfParams::fast_test(),
        chunk_size: 64 * 1024,
        compressed: false,
        ..Default::default()
    };
    let mut clean = Vec::new();
    encrypt_stream_with_threads(
        &mut Cursor::new(&plain),
        &mut clean,
        &meta("multi_batch.bin", plain.len()),
        b"RsMulti!1",
        &opts,
        8,
        |_| {},
        None,
    )
    .unwrap();

    let total_blocks = (clean.len() - 48) / RS_BLOCK_WIRE_SIZE;
    assert!(
        total_blocks > 140,
        "expected >140 RS blocks across multiple batches, got {total_blocks}"
    );

    // Inject 512-byte sector corruption across prefix + batch boundaries (blocks 0, 63, 64, 65, 127, 128, last).
    let mut damaged = clean.clone();
    // Corrupt 3 bytes in RPMR header (1 in each copy at different offsets -> still majority-voted).
    damaged[1] ^= 0x55;
    damaged[16 + 2] ^= 0xAA;
    damaged[32 + 3] ^= 0x33;
    let damaged_blocks = [0usize, 63, 64, 65, 127, 128, total_blocks - 1];
    for &b in &damaged_blocks {
        damage(&mut damaged, 48 + b * RS_BLOCK_WIRE_SIZE + 17, 512);
    }
    let expected_repaired = 3 + (damaged_blocks.len() as u64) * 512;
    let damaged_sha: String = Sha256::digest(&damaged)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    for threads in [1usize, 2, 4, 8, 0] {
        let rep = check_integrity_reader_with_threads(&mut Cursor::new(&damaged), threads).unwrap();
        assert!(
            rep.ok,
            "integrity failed for threads={threads}: {}",
            rep.message
        );
        assert!(rep.has_reed_solomon);
        assert_eq!(rep.rs_repaired_bytes, expected_repaired);
        assert_eq!(rep.sha256_hex, damaged_sha);

        let mut repaired = Vec::new();
        let rrep = repair_vault_stream_with_threads(
            &mut Cursor::new(&damaged),
            &mut repaired,
            None,
            threads,
        )
        .unwrap();
        assert!(rrep.header_repaired);
        assert_eq!(rrep.blocks_checked, total_blocks as u64);
        assert_eq!(rrep.repaired_bytes, expected_repaired);
        assert_eq!(
            repaired, clean,
            "repaired output mismatch for threads={threads}"
        );

        let mut dec = Vec::new();
        decrypt_stream_seekable_with_threads(
            &mut Cursor::new(&damaged),
            &mut dec,
            auth(b"RsMulti!1"),
            threads,
            |_| {},
            None,
        )
        .unwrap();
        assert_eq!(dec, plain, "decrypt mismatch for threads={threads}");
    }

    // Uncorrectable 1024-byte damage in block 10 (inside first 64-block batch) and block 70 (second batch):
    // Blocks 0..10 must still read cleanly via RsSeekableReader; block 10 must fail; seeking to block 11..70 must succeed!
    let mut uncorrectable = clean.clone();
    damage(&mut uncorrectable, 48 + 10 * RS_BLOCK_WIRE_SIZE, 1024);
    damage(&mut uncorrectable, 48 + 70 * RS_BLOCK_WIRE_SIZE, 1024);
    // Also add 512B repairable damage in block 80 to confirm check_integrity keeps scanning after block 10 & 70.
    damage(&mut uncorrectable, 48 + 80 * RS_BLOCK_WIRE_SIZE + 5, 512);

    let mut clean_inner = Vec::new();
    RsSeekableReader::with_threads(Cursor::new(&clean), 8)
        .unwrap()
        .read_to_end(&mut clean_inner)
        .unwrap();

    for threads in [1usize, 4, 8] {
        let mut r = RsSeekableReader::with_threads(Cursor::new(&uncorrectable), threads).unwrap();
        let mut prefix = vec![0u8; 10 * RS_BLOCK_DATA_CAP];
        r.read_exact(&mut prefix).unwrap();
        assert_eq!(prefix, clean_inner[..prefix.len()]);

        // Block 10 fails cleanly.
        let mut one = [0u8; 16];
        let err = r.read(&mut one).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        // Seeking past block 10 to block 11..20 succeeds cleanly.
        let seek_pos = 11 * RS_BLOCK_DATA_CAP as u64;
        r.seek(SeekFrom::Start(seek_pos)).unwrap();
        let mut mid = vec![0u8; 9 * RS_BLOCK_DATA_CAP];
        r.read_exact(&mut mid).unwrap();
        assert_eq!(
            mid,
            clean_inner[seek_pos as usize..seek_pos as usize + mid.len()]
        );

        // Integrity check reports ok == false while scanning through EOF and counting block 80's 512 repairs.
        let irep =
            check_integrity_reader_with_threads(&mut Cursor::new(&uncorrectable), threads).unwrap();
        assert!(!irep.ok);
        assert_eq!(irep.rs_repaired_bytes, 512);
        let expected_hex: String = Sha256::digest(&uncorrectable)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(irep.sha256_hex, expected_hex);

        // Repair rejects uncorrectable vault cleanly.
        assert!(repair_vault_stream_with_threads(
            &mut Cursor::new(&uncorrectable),
            &mut Vec::new(),
            None,
            threads
        )
        .is_err());
    }
}

#[test]
fn parallel_decrypt_never_releases_unverified_chunks_and_preserves_exact_order() {
    let chunk = MIN_CHUNK_SIZE as usize;
    let total_chunks = 24usize;
    let data: Vec<u8> = (0..chunk * total_chunks + 77)
        .map(|i| ((i * 31 + 7) % 251) as u8)
        .collect();

    let opts = EncryptOptions {
        kdf: KdfParams::fast_test(),
        chunk_size: MIN_CHUNK_SIZE,
        compressed: false,
        ..Default::default()
    };
    let mut vault = Vec::new();
    encrypt_stream_with_threads(
        &mut Cursor::new(&data),
        &mut vault,
        &meta("ordered.bin", data.len()),
        b"OrderPw!1",
        &opts,
        8,
        |_| {},
        None,
    )
    .unwrap();

    let (_, _, payload_offset) = read_header_and_meta(&mut Cursor::new(&vault)).unwrap();
    let frame_wire = 5 + chunk + AES_TAG_SIZE;

    for &corrupt_idx in &[0usize, 1, 7, 8, 15, total_chunks] {
        let frame_start = payload_offset as usize + corrupt_idx * frame_wire;
        let expected_written = corrupt_idx * chunk;

        // 1. Ciphertext/tag corruption (worker fails AEAD while later chunks are valid & in flight).
        let mut tag_bad = vault.clone();
        let body_off = frame_start + 5 + if corrupt_idx == total_chunks { 10 } else { 100 };
        tag_bad[body_off] ^= 0x80;

        // 2. Frame header corruption (reader fails while earlier chunks `0..corrupt_idx` are in flight).
        let mut hdr_bad = vault.clone();
        hdr_bad[frame_start + 4] = 2; // invalid final_flag

        // 3. Truncation mid-chunk.
        let truncated = &vault[..frame_start + 8];

        for threads in [1usize, 2, 4, 8, 16] {
            for variant in [&tag_bad[..], &hdr_bad[..], truncated] {
                let mut out = Vec::new();
                let mut progress = Vec::new();
                let res = decrypt_stream_with_threads(
                    &mut Cursor::new(variant),
                    &mut out,
                    auth(b"OrderPw!1"),
                    threads,
                    |n| progress.push(n as usize),
                    None,
                );
                assert!(
                    res.is_err(),
                    "corrupt chunk {corrupt_idx} must fail (threads={threads})"
                );
                assert_eq!(
                    out.len(),
                    expected_written,
                    "chunk {corrupt_idx} threads={threads}: released wrong byte count"
                );
                assert_eq!(out, data[..expected_written]);
                let expected_progress: Vec<usize> = (1..=corrupt_idx).map(|k| k * chunk).collect();
                assert_eq!(
                    progress, expected_progress,
                    "chunk {corrupt_idx} threads={threads}: non-monotonic progress"
                );
            }
        }
    }
}

#[test]
fn parallel_pipeline_mid_stream_cancellation_and_large_chunk_fallback() {
    let chunk = MIN_CHUNK_SIZE as usize;
    let data = vec![0x5Au8; chunk * 20 + 99];

    // 1. Mid-stream cancel on parallel encrypt (Standard + RS).
    for rs in [false, true] {
        let cancel = AtomicBool::new(false);
        let opts = EncryptOptions {
            reed_solomon: rs,
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        };
        let res = encrypt_stream_with_threads(
            &mut Cursor::new(&data),
            &mut Vec::new(),
            &meta("cancel.bin", data.len()),
            b"CancelPw!1",
            &opts,
            8,
            |done| {
                if done >= (chunk * 3) as u64 {
                    cancel.store(true, Ordering::Relaxed);
                }
            },
            Some(&cancel),
        );
        assert!(
            matches!(res, Err(CryptoError::Cancelled)),
            "expected Cancelled for rs={rs}, got {res:?}"
        );
    }

    // 2. Mid-stream cancel on parallel decrypt.
    let mut vault = Vec::new();
    encrypt_stream_with_threads(
        &mut Cursor::new(&data),
        &mut vault,
        &meta("cancel.bin", data.len()),
        b"CancelPw!1",
        &EncryptOptions {
            reed_solomon: true,
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        8,
        |_| {},
        None,
    )
    .unwrap();

    let dec_cancel = AtomicBool::new(false);
    let dec_res = decrypt_stream_seekable_with_threads(
        &mut Cursor::new(&vault),
        &mut Vec::new(),
        auth(b"CancelPw!1"),
        8,
        |done| {
            if done >= (chunk * 2) as u64 {
                dec_cancel.store(true, Ordering::Relaxed);
            }
        },
        Some(&dec_cancel),
    );
    assert!(matches!(dec_res, Err(CryptoError::Cancelled)));

    // 3. Mid-stream cancel during parallel RS repair (reader flips cancel flag partway through).
    struct CancellingReader<'a> {
        inner: Cursor<&'a [u8]>,
        cancel: &'a AtomicBool,
        reads: usize,
    }
    impl Read for CancellingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            if self.reads >= 5 {
                self.cancel.store(true, Ordering::Relaxed);
            }
            self.inner.read(buf)
        }
    }
    impl Seek for CancellingReader<'_> {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    let rep_cancel = AtomicBool::new(false);
    let mut creader = CancellingReader {
        inner: Cursor::new(&vault),
        cancel: &rep_cancel,
        reads: 0,
    };
    let rep_res =
        repair_vault_stream_with_threads(&mut creader, &mut Vec::new(), Some(&rep_cancel), 8);
    assert!(matches!(rep_res, Err(CryptoError::Cancelled)));

    // 4. MAX_CHUNK_SIZE (16 MiB) with threads=8 falls back cleanly within memory budget.
    let small_payload = b"max-chunk-size bounded fallback payload".repeat(128);
    let mut max_chunk_vault = Vec::new();
    encrypt_stream_with_threads(
        &mut Cursor::new(&small_payload),
        &mut max_chunk_vault,
        &meta("maxchunk.bin", small_payload.len()),
        b"MaxChunk!1",
        &EncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: MAX_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        8,
        |_| {},
        None,
    )
    .unwrap();
    let mut max_out = Vec::new();
    decrypt_stream_with_threads(
        &mut Cursor::new(&max_chunk_vault),
        &mut max_out,
        auth(b"MaxChunk!1"),
        8,
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(max_out, small_payload);
}

#[test]
fn rs_seekable_reader_adversarial_random_seeks_and_boundary_reads() {
    let mut rng = StdRng::seed_from_u64(0x5EE4_AD7E);
    // 145 blocks + partial tail -> crosses multiple 32/64-block parallel windows.
    let mut payload = vec![0u8; RS_BLOCK_DATA_CAP * 145 + 913];
    rng.fill_bytes(&mut payload);

    let mut enc = RsEncoderWriter::with_threads(Vec::new(), 8).unwrap();
    enc.write_all(&payload).unwrap();
    let clean_wire = enc.finish().unwrap();
    let total_blocks = (clean_wire.len() - 48) / RS_BLOCK_WIRE_SIZE;
    assert_eq!(total_blocks, 146);

    // Inject 512-byte repairable damage across window boundaries + last block.
    let mut damaged_wire = clean_wire.clone();
    let damaged_blocks = [0usize, 1, 31, 32, 63, 64, 65, 127, 128, total_blocks - 1];
    for &b in &damaged_blocks {
        damage(&mut damaged_wire, 48 + b * RS_BLOCK_WIRE_SIZE + 9, 512);
    }
    let expected_sequential_repairs = (damaged_blocks.len() as u64) * 512;

    for threads in [1usize, 2, 4, 8, MAX_PIPELINE_THREADS] {
        // 1. Sequential read using varied buffer sizes (0, 1, 7, CAP-1, CAP, 3*CAP+17) counts last block once.
        let mut r = RsSeekableReader::with_threads(Cursor::new(&damaged_wire), threads).unwrap();
        let mut out = Vec::with_capacity(payload.len());
        let sizes = [
            0usize,
            1,
            7,
            RS_BLOCK_DATA_CAP - 1,
            RS_BLOCK_DATA_CAP,
            RS_BLOCK_DATA_CAP * 3 + 17,
        ];
        let mut step = 0usize;
        let mut eof = false;
        while !eof {
            let sz = sizes[step % sizes.len()];
            step += 1;
            let mut buf = vec![0u8; sz];
            let n = r.read(&mut buf).unwrap();
            if sz == 0 {
                assert_eq!(n, 0);
                continue;
            }
            if n == 0 {
                eof = true;
            } else {
                out.extend_from_slice(&buf[..n]);
            }
        }
        assert_eq!(
            out, payload,
            "sequential varied read mismatch threads={threads}"
        );
        assert_eq!(
            r.repaired_bytes(),
            expected_sequential_repairs,
            "repaired_bytes drift for threads={threads}"
        );

        // 2. Random forward & backward seeks across partially populated batches and End/Current offsets.
        let mut r2 = RsSeekableReader::with_threads(Cursor::new(&damaged_wire), threads).unwrap();
        let probe_positions: &[(SeekFrom, usize)] = &[
            (SeekFrom::End(-913), 913),
            (SeekFrom::Start(0), 1),
            (SeekFrom::Start((64 * RS_BLOCK_DATA_CAP - 10) as u64), 32),
            (SeekFrom::Current(-25), 40),
            (
                SeekFrom::Start((32 * RS_BLOCK_DATA_CAP) as u64),
                RS_BLOCK_DATA_CAP * 2 + 5,
            ),
            (
                SeekFrom::Start((127 * RS_BLOCK_DATA_CAP + 100) as u64),
                RS_BLOCK_DATA_CAP * 3,
            ),
            (SeekFrom::Start((RS_BLOCK_DATA_CAP - 3) as u64), 10),
            (SeekFrom::End(-1), 1),
            (SeekFrom::End(0), 16),
        ];
        for &(from, req_len) in probe_positions {
            let pos = r2.seek(from).unwrap() as usize;
            let expected_len = req_len.min(payload.len().saturating_sub(pos));
            let mut got = vec![0u8; expected_len];
            if expected_len == 0 {
                let mut extra = [0u8; 4];
                assert_eq!(r2.read(&mut extra).unwrap(), 0);
            } else {
                r2.read_exact(&mut got).unwrap();
                assert_eq!(
                    got,
                    payload[pos..pos + expected_len],
                    "seek probe {from:?} len={req_len} threads={threads}"
                );
            }
        }
    }
}

#[test]
fn extreme_threads_chunk_sizes_and_large_manifest_unlock() {
    let mut rng = StdRng::seed_from_u64(0xE77E_6416);

    // 1. 4 MiB chunk_size (2-slot window) + RS + threads=64 on multi-chunk (9 MiB) payload.
    let mut nine_mib = vec![0u8; 9 * 1024 * 1024 + 123];
    rng.fill_bytes(&mut nine_mib);
    let mut v4m = Vec::new();
    let opts4m = EncryptOptions {
        reed_solomon: true,
        kdf: KdfParams::fast_test(),
        chunk_size: 4 * 1024 * 1024,
        compressed: false,
        ..Default::default()
    };
    let s4m = encrypt_stream_with_threads(
        &mut Cursor::new(&nine_mib),
        &mut v4m,
        &meta("nine_mib.bin", nine_mib.len()),
        b"Chunk4M!1",
        &opts4m,
        MAX_PIPELINE_THREADS,
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(s4m.chunks_written, 3);
    let mut out4m = Vec::new();
    decrypt_stream_seekable_with_threads(
        &mut Cursor::new(&v4m),
        &mut out4m,
        auth(b"Chunk4M!1"),
        MAX_PIPELINE_THREADS,
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(out4m, nine_mib);

    // 2. MAX_CHUNK_SIZE (16 MiB -> 1-slot bounded fallback) on a MULTI-CHUNK (17 MiB) stream!
    let seventeen_mib: Vec<u8> = (0..(17 * 1024 * 1024 + 55))
        .map(|i| ((i * 13 + 3) % 251) as u8)
        .collect();
    let mut v16m = Vec::new();
    let s16m = encrypt_stream_with_threads(
        &mut Cursor::new(&seventeen_mib),
        &mut v16m,
        &meta("seventeen_mib.bin", seventeen_mib.len()),
        b"Chunk16M!1",
        &EncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: MAX_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        8,
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(s16m.chunks_written, 2);
    let mut out16m = Vec::new();
    decrypt_stream_with_threads(
        &mut Cursor::new(&v16m),
        &mut out16m,
        auth(b"Chunk16M!1"),
        8,
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(out16m, seventeen_mib);

    // 3. MIN_CHUNK_SIZE (16 KiB) with threads=64 + large manifest (> 40 KiB across multiple RS blocks).
    let files: Vec<FileManifestEntry> = (0..600)
        .map(|i| FileManifestEntry {
            path: format!("nested/dir_{:02}/item_{i:04}.dat", i % 20),
            size: (i as u64) * 17,
            modified_unix: 1_700_000_000 + i as u64,
        })
        .collect();
    let big_meta = VaultMetadata {
        filename: "large_manifest".into(),
        source_type: "directory".into(),
        original_size: 128 * 1024,
        file_count: files.len() as u64,
        created_at: "2026-11-26T00:00:00Z".into(),
        compressed: false,
        files,
    };
    let mut small_data = vec![0u8; 128 * 1024 + 77];
    rng.fill_bytes(&mut small_data);
    let mut rs_big_manifest = Vec::new();
    encrypt_stream_with_threads(
        &mut Cursor::new(&small_data),
        &mut rs_big_manifest,
        &big_meta,
        b"ManifestPw!1",
        &EncryptOptions {
            reed_solomon: true,
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        MAX_PIPELINE_THREADS,
        |_| {},
        None,
    )
    .unwrap();

    for threads in [1usize, 4, MAX_PIPELINE_THREADS] {
        let info = inspect_header_seekable_with_kdf_and_threads(
            &mut Cursor::new(&rs_big_manifest),
            auth(b"ManifestPw!1"),
            &KdfParams::fast_test(),
            threads,
        )
        .unwrap();
        assert_eq!(info.metadata.files.len(), 600);
        assert!(info.has_reed_solomon);

        let mut dec = Vec::new();
        decrypt_stream_seekable_with_kdf_and_threads(
            &mut Cursor::new(&rs_big_manifest),
            &mut dec,
            auth(b"ManifestPw!1"),
            &KdfParams::fast_test(),
            threads,
            |_| {},
            None,
        )
        .unwrap();
        assert_eq!(dec, small_data);
    }
}
