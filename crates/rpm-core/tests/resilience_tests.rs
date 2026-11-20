use std::io::{self, Read, Write};

use rand::{rngs::StdRng, RngCore, SeedableRng};
use rpm_core::constants::{AES_TAG_SIZE, MAX_HEADER_SIZE, MIN_CHUNK_SIZE, VAULT_MAGIC};
use rpm_core::header::read_header_and_meta;
use rpm_core::{
    decrypt_stream, encrypt_stream, inspect_header, Auth, EncryptOptions, KdfParams, SecretKey,
    VaultMetadata, VAULT_VERSION,
};

const CHUNK: usize = MIN_CHUNK_SIZE as usize;
const RECOVERY: [u8; 32] = [0x36; 32];

struct Fragmented<'a> {
    bytes: &'a [u8],
    step: usize,
}

impl Read for Fragmented<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let sizes = [1, 13, 512, 3, 1021];
        let limit = out.len().min(sizes[self.step % sizes.len()]);
        self.step += 1;
        self.bytes.read(&mut out[..limit])
    }
}

#[derive(Default)]
struct ShortWriter(Vec<u8>);

impl Write for ShortWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len().min(31);
        self.0.extend_from_slice(&buf[..len]);
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn vault(bytes: &[u8]) -> Vec<u8> {
    let metadata = VaultMetadata {
        filename: "stream.bin".into(),
        source_type: "file".into(),
        original_size: bytes.len() as u64,
        file_count: 1,
        created_at: "2026-01-01T00:00:00Z".into(),
        compressed: false,
        files: vec![],
    };
    let options = EncryptOptions {
        chunk_size: MIN_CHUNK_SIZE,
        kdf: KdfParams::fast_test(),
        recovery_key: Some(SecretKey::new(RECOVERY)),
        compressed: false,
        ..Default::default()
    };
    let mut output = ShortWriter::default();
    let summary = encrypt_stream(
        &mut Fragmented { bytes, step: 0 },
        &mut output,
        &metadata,
        b"test password",
        &options,
        |_| {},
        None,
    )
    .unwrap();
    assert_eq!(summary.bytes_encrypted, bytes.len() as u64);
    assert_eq!(
        summary.chunks_written as usize,
        bytes.len().div_ceil(CHUNK).max(1)
    );
    output.0
}

#[test]
fn short_reads_and_writes_preserve_chunk_boundaries() {
    let bytes: Vec<u8> = (0..=2 * CHUNK).map(|i| (i % 251) as u8).collect();
    for len in [
        0,
        1,
        CHUNK - 1,
        CHUNK,
        CHUNK + 1,
        2 * CHUNK - 1,
        2 * CHUNK,
        2 * CHUNK + 1,
    ] {
        let encrypted = vault(&bytes[..len]);
        let mut output = ShortWriter::default();
        let mut progress = Vec::new();
        decrypt_stream(
            &mut Fragmented {
                bytes: &encrypted,
                step: 0,
            },
            &mut output,
            Auth::RecoveryKey(&SecretKey::new(RECOVERY)),
            |n| progress.push(n as usize),
            None,
        )
        .unwrap();
        assert_eq!(output.0, bytes[..len]);
        let mut expected: Vec<usize> = (CHUNK..len).step_by(CHUNK).collect();
        expected.push(len);
        assert_eq!(progress, expected);
    }
}

#[test]
fn damaged_frames_release_only_previously_authenticated_chunks() {
    let bytes: Vec<u8> = (0..2 * CHUNK + 7).map(|i| (i % 251) as u8).collect();
    let encrypted = vault(&bytes);
    let (_, _, offset) = read_header_and_meta(&mut encrypted.as_slice()).unwrap();
    let recovery = SecretKey::new(RECOVERY);
    let reject = |mut damaged: &[u8], verified: usize| {
        let mut output = Vec::new();
        assert!(decrypt_stream(
            &mut damaged,
            &mut output,
            Auth::RecoveryKey(&recovery),
            |_| {},
            None
        )
        .is_err());
        assert_eq!(output.len(), verified);
        assert_eq!(output, bytes[..verified]);
    };

    for cut in [0, 4, 5, 8, offset as usize - 1] {
        reject(&encrypted[..cut], 0);
    }
    let mut start = offset as usize;
    for (i, chunk) in bytes.chunks(CHUNK).enumerate() {
        let end = start + 5 + chunk.len() + AES_TAG_SIZE;
        // Length, final flag, first ciphertext byte, and last authentication tag byte.
        for position in [start, start + 4, start + 5, end - 1] {
            let mut damaged = encrypted.clone();
            damaged[position] ^= 1;
            reject(&damaged, i * CHUNK);
            reject(&encrypted[..position], i * CHUNK);
        }
        start = end;
    }
    assert_eq!(start, encrypted.len());
}

#[test]
fn deterministic_oversized_and_mutated_headers_never_panic() {
    let payload = b"deterministic header resilience payload";
    let encrypted = vault(payload);
    let (_, _, offset) = read_header_and_meta(&mut encrypted.as_slice()).unwrap();
    let offset = offset as usize;
    let recovery = SecretKey::new(RECOVERY);

    // 1. Oversized header length prefix must fail without OOM or panic.
    for hdr_len in [0u32, (MAX_HEADER_SIZE as u32) + 1, u32::MAX] {
        let mut bad = Vec::from(VAULT_MAGIC);
        bad.push(VAULT_VERSION);
        bad.extend_from_slice(&hdr_len.to_be_bytes());
        bad.extend_from_slice(b"{}");
        assert!(inspect_header(&mut bad.as_slice(), Auth::RecoveryKey(&recovery)).is_err());
        assert!(decrypt_stream(
            &mut bad.as_slice(),
            &mut Vec::new(),
            Auth::RecoveryKey(&recovery),
            |_| {},
            None,
        )
        .is_err());
    }

    // 2. 64 seeded byte mutations/truncations across header & frame must never panic.
    let mut rng = StdRng::seed_from_u64(0x5EED_CAFE);
    for idx in 0..64 {
        let mut mutated = encrypted.clone();
        match idx % 4 {
            0 => {
                // Corrupt header length prefix directly.
                let pos = 5 + (rng.next_u32() as usize % 4);
                mutated[pos] ^= (rng.next_u32() as u8) | 1;
            }
            1 => {
                // Flip a byte inside magic / version / header JSON / enc_meta.
                let pos = rng.next_u32() as usize % offset;
                mutated[pos] ^= (rng.next_u32() as u8) | 1;
            }
            2 => {
                // Truncate inside the header/frame boundary.
                let cut = rng.next_u32() as usize % mutated.len();
                mutated.truncate(cut);
            }
            _ => {
                // Flip a byte in the encrypted metadata tag or payload frame.
                let start = offset.saturating_sub(AES_TAG_SIZE);
                let pos = start + (rng.next_u32() as usize % (mutated.len() - start));
                mutated[pos] ^= (rng.next_u32() as u8) | 1;
            }
        }

        let _ = inspect_header(&mut mutated.as_slice(), Auth::RecoveryKey(&recovery));
        let mut out = Vec::new();
        if decrypt_stream(
            &mut mutated.as_slice(),
            &mut out,
            Auth::RecoveryKey(&recovery),
            |_| {},
            None,
        )
        .is_ok()
        {
            // An unauthenticated metadata field (e.g. created_at byte) doesn't affect payload,
            // so any Ok decryption must still reproduce the exact authenticated plaintext.
            assert_eq!(out, payload);
        }
    }
}
