//! Bounded-memory multi-core parallel AEAD chunk pipeline for Vault Format v5.
//!
//! Design invariants preserved:
//! - Zero wire-format changes (`INV-01`): identical chunk nonces, AADs, and frame masks.
//! - Zero unverified plaintext release (`INV-02`): decrypted chunks are emitted strictly in
//!   chunk order `0, 1, 2, ...` and stop immediately at the first failing chunk; any
//!   speculatively decrypted later chunks are zeroized and dropped without touching `writer`.
//! - Bounded O(1) memory (`INV-03`): in-flight chunk buffers are pooled and strictly capped
//!   by `AEAD_PIPELINE_MEMORY_BUDGET`, with zero thread spawning for single-chunk or
//!   single-threaded streams.
//! - Deterministic zeroization (`INV-07`): all chunk buffers are wrapped in `Zeroizing` and
//!   scrubbed before reuse and on error/cancellation.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::Duration;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use zeroize::{Zeroize, Zeroizing};

use crate::constants::AES_TAG_SIZE;
use crate::error::CryptoError;
use crate::kdf::derive_hidden_frame_mask;
use crate::mem::SecretKey;
use crate::vault::{chunk_aad, chunk_nonce, is_cancelled, read_chunk_with_eof};

/// Upper bound on user-configurable pipeline worker threads.
pub const MAX_PIPELINE_THREADS: usize = 64;

/// Strict heap budget for pooled in-flight AEAD chunk buffers (8 MiB).
/// Keeps default 1 MiB chunk streams within `perf_and_memory_guard` limits while
/// saturating up to 8 parallel AEAD workers on multi-core CPUs.
pub(crate) const AEAD_PIPELINE_MEMORY_BUDGET: usize = 8 * 1024 * 1024;

const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Resolve a requested pipeline thread count (`0` = auto-detect logical CPUs),
/// clamped to `1..=MAX_PIPELINE_THREADS`.
pub fn resolve_pipeline_threads(requested: usize) -> usize {
    if requested == 0 {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, MAX_PIPELINE_THREADS)
    } else {
        requested.clamp(1, MAX_PIPELINE_THREADS)
    }
}

/// Default auto-detected pipeline thread count on this machine.
pub fn default_pipeline_threads() -> usize {
    resolve_pipeline_threads(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameMaskMode {
    None,
    Stealth,
    Hidden,
}

fn apply_frame_mask(
    frame: &mut [u8; 5],
    mode: FrameMaskMode,
    dek: &SecretKey,
    ctx: &[u8; 32],
    chunk_idx: u32,
) -> Result<(), CryptoError> {
    match mode {
        FrameMaskMode::None => Ok(()),
        FrameMaskMode::Stealth => crate::stealth::mask_frame(frame, dek, ctx, chunk_idx),
        FrameMaskMode::Hidden => {
            let mask = derive_hidden_frame_mask(dek, ctx, chunk_idx)?;
            for (b, m) in frame.iter_mut().zip(mask) {
                *b ^= m;
            }
            Ok(())
        }
    }
}

/// Compute `(workers, max_slots)` within `AEAD_PIPELINE_MEMORY_BUDGET`.
fn aead_geometry(chunk_size: u32, requested_threads: usize) -> (usize, usize) {
    let threads = resolve_pipeline_threads(requested_threads);
    if threads <= 1 {
        return (1, 1);
    }
    let max_by_mem = (AEAD_PIPELINE_MEMORY_BUDGET / (chunk_size as usize).max(1)).max(1);
    if max_by_mem <= 1 {
        return (1, 1);
    }
    let workers = threads.min(max_by_mem);
    let max_slots = (workers * 2).min(max_by_mem).max(workers);
    (workers, max_slots)
}

#[allow(clippy::too_many_arguments)]
fn encrypt_chunk_in_place(
    cipher: &Aes256Gcm,
    dek: &SecretKey,
    payload_ctx: &[u8; 32],
    prefix: &[u8; 7],
    mask_mode: FrameMaskMode,
    chunk_idx: u32,
    plain_len: usize,
    is_final: bool,
    buf: &mut [u8],
) -> Result<(), CryptoError> {
    let final_flag = u8::from(is_final);
    let plain_len_u32 = plain_len as u32;
    let nonce_bytes = chunk_nonce(prefix, chunk_idx, final_flag);
    let aad = chunk_aad(payload_ctx, chunk_idx, final_flag, plain_len_u32);

    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&nonce_bytes),
            &aad,
            &mut buf[5..5 + plain_len],
        )
        .map_err(|_| CryptoError::CryptoFailure)?;

    let mut frame = [0u8; 5];
    frame[..4].copy_from_slice(&plain_len_u32.to_be_bytes());
    frame[4] = final_flag;
    apply_frame_mask(&mut frame, mask_mode, dek, payload_ctx, chunk_idx)?;

    buf[..5].copy_from_slice(&frame);
    buf[5 + plain_len..5 + plain_len + AES_TAG_SIZE].copy_from_slice(tag.as_slice());
    Ok(())
}

fn decrypt_chunk_in_place(
    cipher: &Aes256Gcm,
    payload_ctx: &[u8; 32],
    prefix: &[u8; 7],
    chunk_idx: u32,
    plain_len: usize,
    final_flag: u8,
    buf: &mut [u8],
) -> Result<(), CryptoError> {
    let nonce_bytes = chunk_nonce(prefix, chunk_idx, final_flag);
    let aad = chunk_aad(payload_ctx, chunk_idx, final_flag, plain_len as u32);
    let (body, tag_slice) = buf[..plain_len + AES_TAG_SIZE].split_at_mut(plain_len);
    let tag = *Tag::from_slice(tag_slice);
    if cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &aad, body, &tag)
        .is_err()
    {
        buf[..plain_len + AES_TAG_SIZE].zeroize();
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(())
}

struct SharedState<W, D> {
    queue: VecDeque<W>,
    ready: Vec<Option<D>>,
    shutdown: bool,
    worker_failed: bool,
    active_workers: usize,
}

impl<W, D> SharedState<W, D> {
    fn new(max_slots: usize, workers: usize) -> Self {
        let mut ready = Vec::with_capacity(max_slots);
        ready.resize_with(max_slots, || None);
        Self {
            queue: VecDeque::with_capacity(max_slots),
            ready,
            shutdown: false,
            worker_failed: false,
            active_workers: workers,
        }
    }
}

/// Ensures workers are signalled to exit and queued/buffered secrets are dropped
/// promptly on every return or unwind path.
struct ShutdownGuard<'a, W, D> {
    shared: &'a Mutex<SharedState<W, D>>,
    work_cv: &'a Condvar,
    abort: &'a AtomicBool,
}

impl<W, D> Drop for ShutdownGuard<'_, W, D> {
    fn drop(&mut self) {
        self.abort.store(true, Ordering::Release);
        let mut st = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        st.shutdown = true;
        st.queue.clear();
        for slot in &mut st.ready {
            slot.take();
        }
        drop(st);
        self.work_cv.notify_all();
    }
}

/// Ensures the coordinator can never deadlock if any worker exits unexpectedly.
struct WorkerExitGuard<'a, W, D> {
    shared: &'a Mutex<SharedState<W, D>>,
    done_cv: &'a Condvar,
}

impl<W, D> Drop for WorkerExitGuard<'_, W, D> {
    fn drop(&mut self) {
        let mut st = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        st.active_workers = st.active_workers.saturating_sub(1);
        if !st.shutdown {
            st.worker_failed = true;
        }
        drop(st);
        self.done_cv.notify_all();
    }
}

fn wait_for_slot<W, D>(
    shared: &Mutex<SharedState<W, D>>,
    done_cv: &Condvar,
    slot: usize,
    cancel: Option<&AtomicBool>,
) -> Result<D, CryptoError> {
    let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if is_cancelled(cancel) {
            return Err(CryptoError::Cancelled);
        }
        if let Some(done) = st.ready[slot].take() {
            return Ok(done);
        }
        if st.worker_failed || st.active_workers == 0 {
            return Err(CryptoError::CryptoFailure);
        }
        st = if cancel.is_some() {
            let (guard, _) = done_cv
                .wait_timeout(st, CANCEL_POLL_INTERVAL)
                .unwrap_or_else(|e| e.into_inner());
            guard
        } else {
            done_cv.wait(st).unwrap_or_else(|e| e.into_inner())
        };
    }
}

struct EncryptWork {
    seq: u64,
    chunk_idx: u32,
    plain_len: usize,
    is_final: bool,
    buf: Zeroizing<Vec<u8>>,
}

struct EncryptDone {
    plain_len: usize,
    is_final: bool,
    result: Result<Zeroizing<Vec<u8>>, CryptoError>,
}

#[allow(clippy::too_many_arguments)]
fn encrypt_chunks_sequential(
    reader: &mut impl Read,
    writer: &mut impl Write,
    cipher: &Aes256Gcm,
    dek: &SecretKey,
    payload_ctx: &[u8; 32],
    prefix: &[u8; 7],
    chunk_cap: usize,
    mask_mode: FrameMaskMode,
    hidden_capacity: Option<(u64, u64)>,
    pending: &mut Option<u8>,
    mut projected_wire: u64,
    mut buf: Zeroizing<Vec<u8>>,
    mut len: usize,
    mut is_final: bool,
    mut progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<(u64, u32), CryptoError> {
    let mut total_bytes: u64 = 0;
    let mut chunk_idx: u32 = 0;

    loop {
        encrypt_chunk_in_place(
            cipher,
            dek,
            payload_ctx,
            prefix,
            mask_mode,
            chunk_idx,
            len,
            is_final,
            &mut buf,
        )?;
        let wire_len = 5 + len + AES_TAG_SIZE;
        writer.write_all(&buf[..wire_len])?;
        total_bytes += len as u64;
        progress_cb(total_bytes);

        chunk_idx = chunk_idx
            .checked_add(1)
            .ok_or_else(|| CryptoError::InvalidFormat("chunk counter overflow".into()))?;
        if is_final {
            return Ok((total_bytes, chunk_idx));
        }

        if is_cancelled(cancel) {
            return Err(CryptoError::Cancelled);
        }
        let next = read_chunk_with_eof(reader, &mut buf[5..5 + chunk_cap], pending)?;
        len = next.0;
        is_final = next.1;
        let wire_len_u64 = 5u64 + (len as u64) + (AES_TAG_SIZE as u64);
        if let Some((limit, container_size)) = hidden_capacity {
            if projected_wire.saturating_add(wire_len_u64) > limit {
                return Err(CryptoError::InvalidFormat(format!(
                    "decoy + hidden compartments exceed {container_size} byte container capacity"
                )));
            }
            projected_wire += wire_len_u64;
        }
    }
}

/// Encrypt all payload chunks from `reader` to `writer` using a memory-bounded
/// multi-core sliding-window AEAD pipeline.
///
/// `hidden_capacity`: optional `(max_wire_bytes, container_size_bytes)` enforcing
/// hidden-compartment space bounds before emitting chunks.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_chunks_pipeline(
    reader: &mut impl Read,
    writer: &mut impl Write,
    dek: &SecretKey,
    payload_ctx: &[u8; 32],
    prefix: &[u8; 7],
    chunk_size: u32,
    mask_mode: FrameMaskMode,
    hidden_capacity: Option<(u64, u64)>,
    threads: usize,
    mut progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<(u64, u32), CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(dek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;
    let (workers, max_slots) = aead_geometry(chunk_size, threads);
    let chunk_cap = chunk_size as usize;
    let buf_cap = 5 + chunk_cap + AES_TAG_SIZE;

    let mut pending: Option<u8> = None;
    let mut projected_wire: u64 = 0;

    if is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }

    // Read chunk 0 first: single-chunk and single-thread streams skip thread spawning entirely.
    let mut first_buf = Zeroizing::new(vec![0u8; buf_cap]);
    let (first_len, first_final) =
        read_chunk_with_eof(reader, &mut first_buf[5..5 + chunk_cap], &mut pending)?;
    let first_wire_len = 5u64 + (first_len as u64) + (AES_TAG_SIZE as u64);
    if let Some((limit, container_size)) = hidden_capacity {
        if projected_wire.saturating_add(first_wire_len) > limit {
            return Err(CryptoError::InvalidFormat(format!(
                "decoy + hidden compartments exceed {container_size} byte container capacity"
            )));
        }
        projected_wire += first_wire_len;
    }

    if first_final || workers <= 1 {
        return encrypt_chunks_sequential(
            reader,
            writer,
            &cipher,
            dek,
            payload_ctx,
            prefix,
            chunk_cap,
            mask_mode,
            hidden_capacity,
            &mut pending,
            projected_wire,
            first_buf,
            first_len,
            first_final,
            progress_cb,
            cancel,
        );
    }

    // Multi-chunk parallel sliding-window pipeline.
    let shared = Mutex::new(SharedState::<EncryptWork, EncryptDone>::new(
        max_slots, workers,
    ));
    let work_cv = Condvar::new();
    let done_cv = Condvar::new();
    let abort = AtomicBool::new(false);

    thread::scope(|scope| {
        // Construct ShutdownGuard BEFORE spawning workers so any unexpected unwind during
        // setup still signals already-spawned workers to exit cleanly without deadlocking.
        let _shutdown = ShutdownGuard {
            shared: &shared,
            work_cv: &work_cv,
            abort: &abort,
        };

        let mut spawned = 0usize;
        for _ in 0..workers {
            let shared = &shared;
            let work_cv = &work_cv;
            let done_cv = &done_cv;
            let abort = &abort;
            let cipher = &cipher;

            if thread::Builder::new()
                .spawn_scoped(scope, move || {
                    let _exit = WorkerExitGuard { shared, done_cv };
                    loop {
                        let job = {
                            let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                            loop {
                                if st.shutdown {
                                    return;
                                }
                                if let Some(item) = st.queue.pop_front() {
                                    break item;
                                }
                                st = work_cv.wait(st).unwrap_or_else(|e| e.into_inner());
                            }
                        };

                        let EncryptWork {
                            seq,
                            chunk_idx,
                            plain_len,
                            is_final,
                            mut buf,
                        } = job;

                        let result = if abort.load(Ordering::Acquire) || is_cancelled(cancel) {
                            Err(CryptoError::Cancelled)
                        } else {
                            encrypt_chunk_in_place(
                                cipher,
                                dek,
                                payload_ctx,
                                prefix,
                                mask_mode,
                                chunk_idx,
                                plain_len,
                                is_final,
                                &mut buf,
                            )
                            .map(|()| buf)
                        };

                        let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                        if st.shutdown {
                            return;
                        }
                        st.ready[(seq as usize) % max_slots] = Some(EncryptDone {
                            plain_len,
                            is_final,
                            result,
                        });
                        drop(st);
                        done_cv.notify_one();
                    }
                })
                .is_ok()
            {
                spawned += 1;
            } else {
                break;
            }
        }

        let failed_spawns = workers - spawned;
        if failed_spawns > 0 {
            let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
            st.active_workers = st.active_workers.saturating_sub(failed_spawns);
        }
        if spawned == 0 {
            return encrypt_chunks_sequential(
                reader,
                writer,
                &cipher,
                dek,
                payload_ctx,
                prefix,
                chunk_cap,
                mask_mode,
                hidden_capacity,
                &mut pending,
                projected_wire,
                first_buf,
                first_len,
                first_final,
                progress_cb,
                cancel,
            );
        }

        let mut free_bufs: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(max_slots);
        let mut next_submit: u64 = 1;
        let mut next_write: u64 = 0;
        let mut next_chunk_idx: Option<u32> = Some(1);
        let mut read_done = false;
        let mut total_bytes: u64 = 0;

        // Enqueue chunk 0 immediately so Worker 0 begins encrypting while we read chunk 1.
        {
            let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
            st.queue.push_back(EncryptWork {
                seq: 0,
                chunk_idx: 0,
                plain_len: first_len,
                is_final: false,
                buf: first_buf,
            });
        }
        work_cv.notify_one();

        loop {
            // 1. Drain all contiguous completed chunks starting at `next_write`.
            loop {
                if is_cancelled(cancel) {
                    return Err(CryptoError::Cancelled);
                }
                let maybe_done = {
                    let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                    st.ready[(next_write as usize) % max_slots].take()
                };
                let Some(done) = maybe_done else {
                    break;
                };
                let buf = done.result?;
                let wire_len = 5 + done.plain_len + AES_TAG_SIZE;
                writer.write_all(&buf[..wire_len])?;
                total_bytes += done.plain_len as u64;
                progress_cb(total_bytes);
                next_write += 1;
                if done.is_final {
                    let chunks_written = u32::try_from(next_write)
                        .map_err(|_| CryptoError::InvalidFormat("chunk counter overflow".into()))?;
                    return Ok((total_bytes, chunks_written));
                }
                free_bufs.push(buf);
            }

            if is_cancelled(cancel) {
                return Err(CryptoError::Cancelled);
            }

            // 2. Keep workers saturated by reading one chunk whenever the window has room.
            if !read_done && (next_submit - next_write) < (max_slots as u64) {
                let chunk_idx = next_chunk_idx
                    .ok_or_else(|| CryptoError::InvalidFormat("chunk counter overflow".into()))?;
                let mut buf = free_bufs
                    .pop()
                    .unwrap_or_else(|| Zeroizing::new(vec![0u8; buf_cap]));
                let (len, is_final) =
                    read_chunk_with_eof(reader, &mut buf[5..5 + chunk_cap], &mut pending)?;
                let wire_len = 5u64 + (len as u64) + (AES_TAG_SIZE as u64);
                if let Some((limit, container_size)) = hidden_capacity {
                    if projected_wire.saturating_add(wire_len) > limit {
                        return Err(CryptoError::InvalidFormat(format!(
                            "decoy + hidden compartments exceed {container_size} byte container capacity"
                        )));
                    }
                    projected_wire += wire_len;
                }
                if is_final {
                    read_done = true;
                } else {
                    next_chunk_idx = chunk_idx.checked_add(1);
                }
                {
                    let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                    st.queue.push_back(EncryptWork {
                        seq: next_submit,
                        chunk_idx,
                        plain_len: len,
                        is_final,
                        buf,
                    });
                }
                work_cv.notify_one();
                next_submit += 1;
                continue;
            }

            // 3. Window is full or EOF reached; wait for the next ordered chunk to finish.
            let done = wait_for_slot(&shared, &done_cv, (next_write as usize) % max_slots, cancel)?;
            let buf = done.result?;
            let wire_len = 5 + done.plain_len + AES_TAG_SIZE;
            writer.write_all(&buf[..wire_len])?;
            total_bytes += done.plain_len as u64;
            progress_cb(total_bytes);
            next_write += 1;
            if done.is_final {
                let chunks_written = u32::try_from(next_write)
                    .map_err(|_| CryptoError::InvalidFormat("chunk counter overflow".into()))?;
                return Ok((total_bytes, chunks_written));
            }
            free_bufs.push(buf);
        }
    })
}

struct ReadFrameResult {
    plain_len: usize,
    final_flag: u8,
    wire_bytes: u64,
}

#[allow(clippy::too_many_arguments)]
fn read_encrypted_frame(
    reader: &mut impl Read,
    dek: &SecretKey,
    payload_ctx: &[u8; 32],
    mask_mode: FrameMaskMode,
    chunk_size: u32,
    chunk_idx: u32,
    payload_bytes_read: u64,
    exact_payload_len: Option<u64>,
    buf: &mut Zeroizing<Vec<u8>>,
) -> Result<ReadFrameResult, CryptoError> {
    if let Some(limit) = exact_payload_len {
        if payload_bytes_read.saturating_add(5) > limit {
            return Err(CryptoError::AuthenticationFailed);
        }
    }

    let mut frame = [0u8; 5];
    reader
        .read_exact(&mut frame)
        .map_err(crate::stealth::map_eof)?;
    apply_frame_mask(&mut frame, mask_mode, dek, payload_ctx, chunk_idx)?;

    let plain_len = u32::from_be_bytes(frame[..4].try_into().unwrap());
    let final_flag = frame[4];

    if mask_mode == FrameMaskMode::Hidden {
        if plain_len > chunk_size || final_flag > 1 || (plain_len == 0 && final_flag == 0) {
            return Err(CryptoError::AuthenticationFailed);
        }
    } else {
        if plain_len > chunk_size {
            return Err(CryptoError::InvalidFormat(format!(
                "chunk length {plain_len} exceeds header chunk_size {chunk_size}"
            )));
        }
        if final_flag > 1 {
            return Err(CryptoError::InvalidFormat(format!(
                "invalid chunk final flag {final_flag}"
            )));
        }
        if plain_len == 0 && final_flag == 0 {
            return Err(CryptoError::InvalidFormat(
                "empty non-final chunk frame".into(),
            ));
        }
    }

    let ct_len = (plain_len as usize) + AES_TAG_SIZE;
    let frame_total = 5u64
        .checked_add(ct_len as u64)
        .ok_or(CryptoError::AuthenticationFailed)?;
    let new_total = payload_bytes_read
        .checked_add(frame_total)
        .ok_or(CryptoError::AuthenticationFailed)?;

    if let Some(limit) = exact_payload_len {
        if new_total > limit || (final_flag == 1 && new_total != limit) {
            return Err(CryptoError::AuthenticationFailed);
        }
    }

    if buf.len() < ct_len {
        buf.resize(ct_len, 0);
    }
    reader.read_exact(&mut buf[..ct_len]).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            CryptoError::AuthenticationFailed
        } else {
            CryptoError::Io(e)
        }
    })?;

    Ok(ReadFrameResult {
        plain_len: plain_len as usize,
        final_flag,
        wire_bytes: frame_total,
    })
}

struct DecryptWork {
    seq: u64,
    chunk_idx: u32,
    plain_len: usize,
    final_flag: u8,
    buf: Zeroizing<Vec<u8>>,
}

struct DecryptDone {
    plain_len: usize,
    final_flag: u8,
    result: Result<Zeroizing<Vec<u8>>, CryptoError>,
}

#[allow(clippy::too_many_arguments)]
fn decrypt_chunks_sequential(
    reader: &mut impl Read,
    writer: &mut impl Write,
    cipher: &Aes256Gcm,
    dek: &SecretKey,
    payload_ctx: &[u8; 32],
    prefix: &[u8; 7],
    chunk_size: u32,
    mask_mode: FrameMaskMode,
    exact_payload_len: Option<u64>,
    mut buf: Zeroizing<Vec<u8>>,
    mut frame: ReadFrameResult,
    mut payload_bytes_read: u64,
    mut progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<(u64, u64), CryptoError> {
    let mut total_bytes: u64 = 0;
    let mut chunk_idx: u32 = 0;

    loop {
        decrypt_chunk_in_place(
            cipher,
            payload_ctx,
            prefix,
            chunk_idx,
            frame.plain_len,
            frame.final_flag,
            &mut buf,
        )?;

        if frame.final_flag == 1 {
            if let Some(expected) = exact_payload_len {
                if payload_bytes_read != expected {
                    buf[..frame.plain_len].zeroize();
                    return Err(CryptoError::AuthenticationFailed);
                }
            }
        }

        if frame.plain_len > 0 {
            writer.write_all(&buf[..frame.plain_len])?;
            buf[..frame.plain_len].zeroize();
        }
        total_bytes += frame.plain_len as u64;
        progress_cb(total_bytes);

        if frame.final_flag == 1 {
            return Ok((total_bytes, payload_bytes_read));
        }

        chunk_idx = chunk_idx
            .checked_add(1)
            .ok_or_else(|| CryptoError::InvalidFormat("chunk counter overflow".into()))?;
        if is_cancelled(cancel) {
            return Err(CryptoError::Cancelled);
        }
        frame = read_encrypted_frame(
            reader,
            dek,
            payload_ctx,
            mask_mode,
            chunk_size,
            chunk_idx,
            payload_bytes_read,
            exact_payload_len,
            &mut buf,
        )?;
        payload_bytes_read = payload_bytes_read
            .checked_add(frame.wire_bytes)
            .ok_or(CryptoError::AuthenticationFailed)?;
    }
}

/// Decrypt all payload chunks from `reader` to `writer` using a memory-bounded
/// multi-core sliding-window AEAD pipeline.
///
/// Guarantees:
/// - Chunks are written strictly in order `0, 1, 2, ...` only after AEAD verification.
/// - On error at chunk `k` (frame/EOF/IO or AEAD tag failure), every verified chunk
///   `0..k` is flushed in order and zero bytes of chunk `k` or later are written.
/// - Every decrypted plaintext buffer is deterministically zeroized immediately after
///   writing or on error/cancellation.
///
/// Returns `(total_plaintext_bytes, payload_wire_bytes_read)`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn decrypt_chunks_pipeline(
    reader: &mut impl Read,
    writer: &mut impl Write,
    dek: &SecretKey,
    payload_ctx: &[u8; 32],
    prefix: &[u8; 7],
    chunk_size: u32,
    mask_mode: FrameMaskMode,
    exact_payload_len: Option<u64>,
    threads: usize,
    mut progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<(u64, u64), CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(dek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;
    let (workers, max_slots) = aead_geometry(chunk_size, threads);
    let ct_cap = (chunk_size as usize) + AES_TAG_SIZE;

    if is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }

    // Read chunk 0 first: single-chunk and single-thread streams skip thread spawning entirely.
    let mut first_buf = Zeroizing::new(Vec::new());
    let first_frame = read_encrypted_frame(
        reader,
        dek,
        payload_ctx,
        mask_mode,
        chunk_size,
        0,
        0,
        exact_payload_len,
        &mut first_buf,
    )?;
    let mut payload_bytes_read = first_frame.wire_bytes;

    if first_frame.final_flag == 1 || workers <= 1 {
        return decrypt_chunks_sequential(
            reader,
            writer,
            &cipher,
            dek,
            payload_ctx,
            prefix,
            chunk_size,
            mask_mode,
            exact_payload_len,
            first_buf,
            first_frame,
            payload_bytes_read,
            progress_cb,
            cancel,
        );
    }

    // Multi-chunk parallel sliding-window decrypt pipeline.
    let shared = Mutex::new(SharedState::<DecryptWork, DecryptDone>::new(
        max_slots, workers,
    ));
    let work_cv = Condvar::new();
    let done_cv = Condvar::new();
    let abort = AtomicBool::new(false);

    thread::scope(|scope| {
        // Construct ShutdownGuard BEFORE spawning workers so any unexpected unwind during
        // setup still signals already-spawned workers to exit cleanly without deadlocking.
        let _shutdown = ShutdownGuard {
            shared: &shared,
            work_cv: &work_cv,
            abort: &abort,
        };

        let mut spawned = 0usize;
        for _ in 0..workers {
            let shared = &shared;
            let work_cv = &work_cv;
            let done_cv = &done_cv;
            let abort = &abort;
            let cipher = &cipher;

            if thread::Builder::new()
                .spawn_scoped(scope, move || {
                    let _exit = WorkerExitGuard { shared, done_cv };
                    loop {
                        let job = {
                            let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                            loop {
                                if st.shutdown {
                                    return;
                                }
                                if let Some(item) = st.queue.pop_front() {
                                    break item;
                                }
                                st = work_cv.wait(st).unwrap_or_else(|e| e.into_inner());
                            }
                        };

                        let DecryptWork {
                            seq,
                            chunk_idx,
                            plain_len,
                            final_flag,
                            mut buf,
                        } = job;

                        let result = if abort.load(Ordering::Acquire) || is_cancelled(cancel) {
                            Err(CryptoError::Cancelled)
                        } else {
                            decrypt_chunk_in_place(
                                cipher,
                                payload_ctx,
                                prefix,
                                chunk_idx,
                                plain_len,
                                final_flag,
                                &mut buf,
                            )
                            .map(|()| buf)
                        };

                        let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                        if st.shutdown {
                            return;
                        }
                        st.ready[(seq as usize) % max_slots] = Some(DecryptDone {
                            plain_len,
                            final_flag,
                            result,
                        });
                        drop(st);
                        done_cv.notify_one();
                    }
                })
                .is_ok()
            {
                spawned += 1;
            } else {
                break;
            }
        }

        let failed_spawns = workers - spawned;
        if failed_spawns > 0 {
            let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
            st.active_workers = st.active_workers.saturating_sub(failed_spawns);
        }
        if spawned == 0 {
            return decrypt_chunks_sequential(
                reader,
                writer,
                &cipher,
                dek,
                payload_ctx,
                prefix,
                chunk_size,
                mask_mode,
                exact_payload_len,
                first_buf,
                first_frame,
                payload_bytes_read,
                progress_cb,
                cancel,
            );
        }

        let mut free_bufs: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(max_slots);
        let mut next_submit: u64 = 1;
        let mut next_write: u64 = 0;
        let mut next_chunk_idx: Option<u32> = Some(1);
        let mut read_done = false;
        let mut read_error: Option<(u64, CryptoError)> = None;
        let mut total_bytes: u64 = 0;

        // Enqueue chunk 0 immediately so Worker 0 begins decrypting while we read chunk 1.
        {
            let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
            st.queue.push_back(DecryptWork {
                seq: 0,
                chunk_idx: 0,
                plain_len: first_frame.plain_len,
                final_flag: first_frame.final_flag,
                buf: first_buf,
            });
        }
        work_cv.notify_one();

        let emit_done = |done: DecryptDone,
                         bytes_read_so_far: u64,
                         writer: &mut dyn Write,
                         total_bytes: &mut u64,
                         progress_cb: &mut dyn FnMut(u64),
                         free_bufs: &mut Vec<Zeroizing<Vec<u8>>>|
         -> Result<bool, CryptoError> {
            let mut buf = done.result?;
            if done.final_flag == 1 {
                if let Some(expected) = exact_payload_len {
                    if bytes_read_so_far != expected {
                        buf[..done.plain_len].zeroize();
                        return Err(CryptoError::AuthenticationFailed);
                    }
                }
            }
            if done.plain_len > 0 {
                writer.write_all(&buf[..done.plain_len])?;
                buf[..done.plain_len].zeroize();
            }
            *total_bytes += done.plain_len as u64;
            progress_cb(*total_bytes);
            if done.final_flag == 1 {
                return Ok(true);
            }
            free_bufs.push(buf);
            Ok(false)
        };

        loop {
            // 1. Drain all contiguous verified chunks starting at `next_write`.
            loop {
                if is_cancelled(cancel) {
                    return Err(CryptoError::Cancelled);
                }
                if let Some((err_seq, _)) = &read_error {
                    if next_write == *err_seq {
                        return Err(read_error.take().unwrap().1);
                    }
                }
                let maybe_done = {
                    let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                    st.ready[(next_write as usize) % max_slots].take()
                };
                let Some(done) = maybe_done else {
                    break;
                };
                let finished = emit_done(
                    done,
                    payload_bytes_read,
                    writer,
                    &mut total_bytes,
                    &mut progress_cb,
                    &mut free_bufs,
                )?;
                next_write += 1;
                if finished {
                    return Ok((total_bytes, payload_bytes_read));
                }
            }

            if is_cancelled(cancel) {
                return Err(CryptoError::Cancelled);
            }
            if let Some((err_seq, _)) = &read_error {
                if next_write == *err_seq {
                    return Err(read_error.take().unwrap().1);
                }
            }

            // 2. Read and dispatch the next encrypted frame if window has room.
            if !read_done && (next_submit - next_write) < (max_slots as u64) {
                let chunk_idx = match next_chunk_idx {
                    Some(idx) => idx,
                    None => {
                        read_error = Some((
                            next_submit,
                            CryptoError::InvalidFormat("chunk counter overflow".into()),
                        ));
                        read_done = true;
                        continue;
                    }
                };
                let mut buf = free_bufs
                    .pop()
                    .unwrap_or_else(|| Zeroizing::new(Vec::with_capacity(ct_cap)));
                match read_encrypted_frame(
                    reader,
                    dek,
                    payload_ctx,
                    mask_mode,
                    chunk_size,
                    chunk_idx,
                    payload_bytes_read,
                    exact_payload_len,
                    &mut buf,
                ) {
                    Ok(frame) => {
                        payload_bytes_read = match payload_bytes_read.checked_add(frame.wire_bytes)
                        {
                            Some(v) => v,
                            None => {
                                read_error = Some((next_submit, CryptoError::AuthenticationFailed));
                                read_done = true;
                                continue;
                            }
                        };
                        if frame.final_flag == 1 {
                            read_done = true;
                        } else {
                            next_chunk_idx = chunk_idx.checked_add(1);
                        }
                        {
                            let mut st = shared.lock().unwrap_or_else(|e| e.into_inner());
                            st.queue.push_back(DecryptWork {
                                seq: next_submit,
                                chunk_idx,
                                plain_len: frame.plain_len,
                                final_flag: frame.final_flag,
                                buf,
                            });
                        }
                        work_cv.notify_one();
                        next_submit += 1;
                    }
                    Err(err) => {
                        // Preserve ordered delivery of already-submitted chunks `0..next_submit`
                        // before surfacing this frame/EOF/IO error at `next_submit`.
                        read_error = Some((next_submit, err));
                        read_done = true;
                    }
                }
                continue;
            }

            // 3. Wait for chunk `next_write` to finish verifying.
            let done = wait_for_slot(&shared, &done_cv, (next_write as usize) % max_slots, cancel)?;
            let finished = emit_done(
                done,
                payload_bytes_read,
                writer,
                &mut total_bytes,
                &mut progress_cb,
                &mut free_bufs,
            )?;
            next_write += 1;
            if finished {
                return Ok((total_bytes, payload_bytes_read));
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MIN_CHUNK_SIZE;
    use std::io::Cursor;

    #[test]
    fn exact_payload_len_mismatch_never_writes_final_chunk_bytes() {
        let dek = SecretKey::new([0x42u8; 32]);
        let ctx = [0x19u8; 32];
        let prefix = [0x77u8; 7];
        let chunk = MIN_CHUNK_SIZE;

        // Test both 1-chunk (single-thread fast path) and 4-chunk (parallel sliding-window path).
        for (plain, expected_prior_written) in [
            (vec![0xABu8; 2048], 0usize),
            (
                (0..(chunk as usize * 3 + 777))
                    .map(|i| (i % 251) as u8)
                    .collect::<Vec<_>>(),
                chunk as usize * 3,
            ),
        ] {
            let mut wire = Vec::new();
            encrypt_chunks_pipeline(
                &mut Cursor::new(&plain),
                &mut wire,
                &dek,
                &ctx,
                &prefix,
                chunk,
                FrameMaskMode::Hidden,
                None,
                4,
                |_| {},
                None,
            )
            .unwrap();
            let actual_wire_len = wire.len() as u64;

            for threads in [1usize, 2, 4, 8] {
                // Case A: declared exact_payload_len is LARGER than actual wire length (valid final chunk ends early).
                let mut out = Vec::new();
                let mut progress = Vec::new();
                let res = decrypt_chunks_pipeline(
                    &mut Cursor::new(&wire),
                    &mut out,
                    &dek,
                    &ctx,
                    &prefix,
                    chunk,
                    FrameMaskMode::Hidden,
                    Some(actual_wire_len + 64),
                    threads,
                    |n| progress.push(n as usize),
                    None,
                );
                assert!(matches!(res, Err(CryptoError::AuthenticationFailed)));
                assert_eq!(
                    out.len(),
                    expected_prior_written,
                    "final chunk leaked on longer exact_payload_len (threads={threads})"
                );
                assert_eq!(out, plain[..expected_prior_written]);
                assert!(
                    progress.last().copied().unwrap_or(0) == expected_prior_written,
                    "progress advanced past verified prior chunks (threads={threads})"
                );

                // Case B: declared exact_payload_len is SHORTER than actual wire length.
                let mut out_short = Vec::new();
                let res_short = decrypt_chunks_pipeline(
                    &mut Cursor::new(&wire),
                    &mut out_short,
                    &dek,
                    &ctx,
                    &prefix,
                    chunk,
                    FrameMaskMode::Hidden,
                    Some(actual_wire_len - 1),
                    threads,
                    |_| {},
                    None,
                );
                assert!(matches!(res_short, Err(CryptoError::AuthenticationFailed)));
                assert_eq!(out_short.len(), expected_prior_written);

                // Case C: exact match succeeds cleanly.
                let mut out_ok = Vec::new();
                let (dec_bytes, wire_read) = decrypt_chunks_pipeline(
                    &mut Cursor::new(&wire),
                    &mut out_ok,
                    &dek,
                    &ctx,
                    &prefix,
                    chunk,
                    FrameMaskMode::Hidden,
                    Some(actual_wire_len),
                    threads,
                    |_| {},
                    None,
                )
                .unwrap();
                assert_eq!(dec_bytes, plain.len() as u64);
                assert_eq!(wire_read, actual_wire_len);
                assert_eq!(out_ok, plain);
            }
        }
    }

    #[test]
    fn wait_for_slot_unblocks_when_single_worker_exits_unexpectedly() {
        // Simulate 4 active workers where only 1 worker exits unexpectedly before publishing slot 1,
        // leaving 3 workers still active (previously caused a permanent deadlock because
        // wait_for_slot only checked `active_workers == 0`).
        let shared = Mutex::new(SharedState::<(), u32>::new(4, 4));
        let done_cv = Condvar::new();
        {
            let mut st = shared.lock().unwrap();
            st.ready[0] = Some(123);
        }

        thread::scope(|s| {
            let shared_ref = &shared;
            let done_cv_ref = &done_cv;
            s.spawn(move || {
                let _exit = WorkerExitGuard {
                    shared: shared_ref,
                    done_cv: done_cv_ref,
                };
                // Exit without publishing slot 1 while shutdown == false.
            });

            // Slot 0 was already completed and must still be retrievable.
            assert_eq!(wait_for_slot(&shared, &done_cv, 0, None).unwrap(), 123);

            // Slot 1 must promptly return CryptoFailure despite 3 remaining active workers.
            let err = wait_for_slot(&shared, &done_cv, 1, None).unwrap_err();
            assert!(matches!(err, CryptoError::CryptoFailure));
        });

        let st = shared.lock().unwrap();
        assert_eq!(st.active_workers, 3);
        assert!(st.worker_failed);
    }
}
