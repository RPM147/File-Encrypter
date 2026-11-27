//! Systematic shortened RS(255,239), first consecutive root 0, primitive element 2.
//! The envelope protects ciphertext against accidental damage; only the inner AEAD authenticates it.
#![forbid(unsafe_code)]

use crate::pipeline::resolve_pipeline_threads;
use crate::{CryptoError, VAULT_MAGIC};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

pub const NSYM: usize = 16;
const WORD: usize = 255;
const DATA: usize = WORD - NSYM;
const LANES: usize = 64;
pub const RS_BLOCK_DATA_CAP: usize = LANES * DATA - 4;
pub const RS_BLOCK_WIRE_SIZE: usize = LANES * WORD;
const HEADER: usize = 48;

/// Maximum RS wire blocks decoded or encoded in a single parallel batch.
/// `64 * 16,320 B = 1,044,480 B` (~1.00 MiB), keeping heap strictly O(1) bounded.
const MAX_RS_BATCH_BLOCKS: usize = 64;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or uncorrectable Reed-Solomon block",
    )
}

const fn tables() -> ([u8; 510], [usize; 256]) {
    let mut exp = [0; 510];
    let mut log = [0; 256];
    let mut x = 1u16;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        exp[i + 255] = x as u8;
        log[x as usize] = i;
        x <<= 1;
        if x & 256 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    (exp, log)
}
const GF: ([u8; 510], [usize; 256]) = tables();
const fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        GF.0[GF.1[a as usize] + GF.1[b as usize]]
    }
}
fn inv(a: u8) -> u8 {
    debug_assert_ne!(a, 0);
    GF.0[255 - GF.1[a as usize]]
}
const fn generator() -> [u8; NSYM + 1] {
    let mut g = [0; NSYM + 1];
    g[0] = 1;
    let mut r = 0;
    while r < NSYM {
        let mut j = r + 1;
        while j > 0 {
            g[j] ^= mul(g[j - 1], GF.0[r]);
            j -= 1;
        }
        r += 1;
    }
    g
}
const GENERATOR: [u8; NSYM + 1] = generator();

const fn mul_table_for(c: u8) -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        t[x] = mul(x as u8, c);
        x += 1;
    }
    t
}

/// Precomputed GF(2^8) multiply tables for `GENERATOR[1..=NSYM]` (4 KiB, L1-resident).
const GEN_MUL: [[u8; 256]; NSYM] = {
    let mut out = [[0u8; 256]; NSYM];
    let mut i = 0;
    while i < NSYM {
        out[i] = mul_table_for(GENERATOR[i + 1]);
        i += 1;
    }
    out
};

/// Precomputed GF(2^8) multiply tables for syndrome roots `GF.0[0..NSYM]` (4 KiB, L1-resident).
const ROOT_MUL: [[u8; 256]; NSYM] = {
    let mut out = [[0u8; 256]; NSYM];
    let mut i = 0;
    while i < NSYM {
        out[i] = mul_table_for(GF.0[i]);
        i += 1;
    }
    out
};

/// Append systematic parity in the last 16 bytes (leading zero symbols may be shortened).
pub fn encode_codeword(word: &mut [u8]) -> io::Result<()> {
    if !(NSYM..=WORD).contains(&word.len()) {
        return Err(invalid());
    }
    let (data, parity) = word.split_at_mut(word.len() - NSYM);
    parity.fill(0);
    for &symbol in data.iter() {
        let lead = (symbol ^ parity[0]) as usize;
        for i in 0..NSYM - 1 {
            parity[i] = parity[i + 1] ^ GEN_MUL[i][lead];
        }
        parity[NSYM - 1] = GEN_MUL[NSYM - 1][lead];
    }
    Ok(())
}

fn syndromes(word: &[u8]) -> [u8; NSYM] {
    let mut out = [0u8; NSYM];
    out[0] = word.iter().fold(0, |acc, &b| acc ^ b);
    for i in 1..NSYM {
        let tbl = &ROOT_MUL[i];
        out[i] = word.iter().fold(0, |acc, &b| tbl[acc as usize] ^ b);
    }
    out
}

// Locator/evaluator coefficients are stored in ascending powers.
fn evaluate(poly: &[u8], x: u8) -> u8 {
    poly.iter().rev().fold(0, |acc, &c| mul(acc, x) ^ c)
}

fn correct_codeword_with_syndromes(word: &mut [u8], s: [u8; NSYM]) -> io::Result<usize> {
    if s == [0; NSYM] {
        return Ok(0);
    }
    // Berlekamp–Massey: update the locator when a discrepancy breaks the recurrence.
    let mut locator = [0; NSYM + 1];
    locator[0] = 1;
    let mut previous = locator;
    let mut degree = 0;
    let mut shift = 1;
    let mut last = 1;
    for n in 0..NSYM {
        let mut discrepancy = s[n];
        for i in 1..=degree {
            discrepancy ^= mul(locator[i], s[n - i]);
        }
        if discrepancy == 0 {
            shift += 1;
            continue;
        }
        let saved = locator;
        let factor = mul(discrepancy, inv(last));
        for i in shift..=NSYM {
            locator[i] ^= mul(factor, previous[i - shift]);
        }
        if 2 * degree <= n {
            degree = n + 1 - degree;
            previous = saved;
            last = discrepancy;
            shift = 1;
        } else {
            shift += 1;
        }
    }
    if degree == 0 || degree > NSYM / 2 {
        return Err(invalid());
    }
    // Omega = (S * locator) mod x^NSYM. In characteristic two only odd
    // coefficients survive the formal derivative of the locator.
    let mut omega = [0; NSYM];
    let mut derivative = [0; NSYM];
    for i in 0..=degree {
        for j in i..NSYM {
            omega[j] ^= mul(locator[i], s[j - i]);
        }
        if i % 2 == 1 {
            derivative[i - 1] = locator[i];
        }
    }
    let mut candidate = [0; WORD];
    candidate[..word.len()].copy_from_slice(word);
    let mut roots = 0;
    for (pos, symbol) in candidate[..word.len()].iter_mut().enumerate() {
        let x = GF.0[word.len() - 1 - pos];
        let z = inv(x);
        if evaluate(&locator[..=degree], z) != 0 {
            continue;
        }
        let denom = evaluate(&derivative[..degree], z);
        if denom == 0 {
            return Err(invalid());
        }
        // Forney magnitude for first root zero: X * Omega(1/X) / locator'(1/X).
        *symbol ^= mul(x, mul(evaluate(&omega, z), inv(denom)));
        roots += 1;
    }
    if roots != degree || syndromes(&candidate[..word.len()]) != [0; NSYM] {
        return Err(invalid());
    }
    word.copy_from_slice(&candidate[..word.len()]);
    Ok(roots)
}

/// Locate and correct unknown symbol errors. A failed word is left untouched.
pub fn correct_codeword(word: &mut [u8]) -> io::Result<usize> {
    if !(NSYM..=WORD).contains(&word.len()) {
        return Err(invalid());
    }
    let s = syndromes(word);
    correct_codeword_with_syndromes(word, s)
}

const fn crc32(bytes: &[u8], len: usize) -> u32 {
    let mut crc = !0u32;
    let mut i = 0;
    while i < len {
        crc ^= bytes[i] as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
            bit += 1;
        }
        i += 1;
    }
    !crc
}

const fn header() -> [u8; HEADER] {
    let mut copy = *b"RPMR\x01\x10\x40\0\0\0\0\0\0\0\0\0";
    let sum = crc32(&copy, 12).to_be_bytes();
    let mut i;
    let mut out = [0; HEADER];
    i = 0;
    while i < 4 {
        copy[12 + i] = sum[i];
        i += 1;
    }
    i = 0;
    while i < HEADER {
        out[i] = copy[i % 16];
        i += 1;
    }
    out
}
const PREFIX: [u8; HEADER] = header();
fn recognized(h: &[u8]) -> bool {
    if h.as_chunks::<16>().0.iter().any(|c| c == &PREFIX[..16]) {
        return true;
    }
    h.len() == HEADER
        && (0..16).all(|i| {
            let (a, b, c) = (h[i], h[i + 16], h[i + 32]);
            (a == b || a == c) && a == PREFIX[i] || b == c && b == PREFIX[i]
        })
}
fn has_unsupported_profile(h: &[u8]) -> bool {
    !recognized(h)
        && h.as_chunks::<16>()
            .0
            .iter()
            .any(|copy| copy.starts_with(b"RPMR") && copy[12..] == crc32(copy, 12).to_be_bytes())
}
fn check_profile(h: &[u8]) -> io::Result<()> {
    if has_unsupported_profile(h) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported Reed-Solomon envelope profile",
        ));
    }
    Ok(())
}
fn differences(h: &[u8]) -> u64 {
    h.iter().zip(PREFIX).filter(|(a, b)| **a != *b).count() as u64
}
fn block_count(size: u64) -> io::Result<u64> {
    let bytes = size.checked_sub(HEADER as u64).ok_or_else(invalid)?;
    if bytes == 0 || bytes % RS_BLOCK_WIRE_SIZE as u64 != 0 {
        return Err(invalid());
    }
    Ok(bytes / RS_BLOCK_WIRE_SIZE as u64)
}

#[inline]
fn block_offset(inner: usize) -> usize {
    (inner % DATA) * LANES + inner / DATA
}

fn copy_out_slice(block: &[u8], at: usize, out: &mut [u8]) {
    let mut row = at % DATA;
    let mut lane = at / DATA;
    for b in out.iter_mut() {
        *b = block[row * LANES + lane];
        row += 1;
        if row == DATA {
            row = 0;
            lane += 1;
        }
    }
}

/// Transpose linear block data (`4`-byte length prefix + payload + zero tail = `DATA * LANES`)
/// into the `239 x 64` interleaved wire layout and append `16 x 64` systematic RS parity.
fn encode_linear_block_in_place(block: &mut [u8]) {
    debug_assert_eq!(block.len(), RS_BLOCK_WIRE_SIZE);
    let mut linear = [0u8; DATA * LANES];
    linear.copy_from_slice(&block[..DATA * LANES]);
    for lane in 0..LANES {
        let src = &linear[lane * DATA..(lane + 1) * DATA];
        for (row, &byte) in src.iter().enumerate() {
            block[row * LANES + lane] = byte;
        }
    }
    encode_block_slice(block);
}

/// De-interleave the authenticated inner payload bytes (`len` bytes starting at inner offset 4)
/// into contiguous linear layout at `block[..len]` so readers can serve via linear `memcpy`.
fn linearize_decoded_block_in_place(block: &mut [u8], len: usize) {
    debug_assert!(len <= RS_BLOCK_DATA_CAP);
    if len == 0 {
        return;
    }
    let mut linear = [0u8; DATA * LANES];
    let needed_lanes = (4 + len).div_ceil(DATA);
    for (row, wire_row) in block[..DATA * LANES]
        .as_chunks::<LANES>()
        .0
        .iter()
        .enumerate()
    {
        for (lane, &byte) in wire_row[..needed_lanes].iter().enumerate() {
            linear[lane * DATA + row] = byte;
        }
    }
    block[..len].copy_from_slice(&linear[4..4 + len]);
}

/// Row-interleaved 64-lane systematic RS(255,239) encoder operating directly on
/// one `RS_BLOCK_WIRE_SIZE` wire block. Produces bit-identical parity to per-lane
/// [`encode_codeword`] while keeping all 64 lanes contiguous and branchless.
fn encode_block_slice(block: &mut [u8]) {
    debug_assert_eq!(block.len(), RS_BLOCK_WIRE_SIZE);
    let mut parity = [[0u8; LANES]; NSYM];
    let mut lead = [0u8; LANES];

    for r in 0..DATA {
        let row = &block[r * LANES..(r + 1) * LANES];
        for l in 0..LANES {
            lead[l] = row[l] ^ parity[0][l];
        }
        for i in 0..NSYM - 1 {
            let tbl = &GEN_MUL[i];
            let (left, right) = parity.split_at_mut(i + 1);
            let dst = &mut left[i];
            let src = &right[0];
            for l in 0..LANES {
                dst[l] = src[l] ^ tbl[lead[l] as usize];
            }
        }
        let tbl = &GEN_MUL[NSYM - 1];
        for l in 0..LANES {
            parity[NSYM - 1][l] = tbl[lead[l] as usize];
        }
    }

    for (i, p_row) in parity.iter().enumerate() {
        let off = (DATA + i) * LANES;
        block[off..off + LANES].copy_from_slice(p_row);
    }
}

/// Row-interleaved 64-lane syndrome evaluation + selective lane correction on
/// one `RS_BLOCK_WIRE_SIZE` wire block. Zero-error blocks avoid all strided
/// de-interleaving and Berlekamp-Massey work.
fn decode_block_words(block: &mut [u8]) -> io::Result<u64> {
    debug_assert_eq!(block.len(), RS_BLOCK_WIRE_SIZE);
    let mut syn = [[0u8; LANES]; NSYM];

    // Root 0 is GF.0[0] == 1, so syndrome 0 is pure row-wise XOR across all 64 lanes.
    for r in 0..WORD {
        let row = &block[r * LANES..(r + 1) * LANES];
        for l in 0..LANES {
            syn[0][l] ^= row[l];
        }
    }
    for i in 1..NSYM {
        let tbl = &ROOT_MUL[i];
        let s_row = &mut syn[i];
        for r in 0..WORD {
            let row = &block[r * LANES..(r + 1) * LANES];
            for l in 0..LANES {
                s_row[l] = tbl[s_row[l] as usize] ^ row[l];
            }
        }
    }

    let mut any_err = [0u8; LANES];
    for s_row in &syn {
        for l in 0..LANES {
            any_err[l] |= s_row[l];
        }
    }
    if any_err == [0u8; LANES] {
        return Ok(0);
    }

    let mut repaired = 0u64;
    for (lane, &err_mask) in any_err.iter().enumerate() {
        if err_mask == 0 {
            continue;
        }
        let mut word: [u8; WORD] = std::array::from_fn(|i| block[i * LANES + lane]);
        let lane_syn: [u8; NSYM] = std::array::from_fn(|i| syn[i][lane]);
        let n = correct_codeword_with_syndromes(&mut word, lane_syn)?;
        repaired += n as u64;
        for (i, b) in word.into_iter().enumerate() {
            block[i * LANES + lane] = b;
        }
    }
    Ok(repaired)
}

/// Decode, repair, and validate inner length & zero padding for a single wire block.
fn decode_and_validate_block(
    block: &mut [u8],
    is_last: bool,
    reject_empty_multi: bool,
) -> io::Result<(usize, u64)> {
    let repaired = decode_block_words(block)?;
    let mut raw = [0u8; 4];
    copy_out_slice(block, 0, &mut raw);
    let len = u32::from_be_bytes(raw) as usize;
    if len > RS_BLOCK_DATA_CAP
        || (!is_last && len != RS_BLOCK_DATA_CAP)
        || (reject_empty_multi && len == 0)
        || (len + 4..DATA * LANES).any(|i| block[block_offset(i)] != 0)
    {
        return Err(invalid());
    }
    Ok((len, repaired))
}

// Keep a single block helper for lightweight one-off probing.
struct Block(Vec<u8>);
impl Block {
    fn new() -> Self {
        Self(vec![0; RS_BLOCK_WIRE_SIZE])
    }
    fn copy_out(&self, at: usize, out: &mut [u8]) {
        copy_out_slice(&self.0, at, out);
    }
    fn read(&mut self, r: &mut impl Read, last: bool) -> io::Result<(usize, u64)> {
        r.read_exact(&mut self.0)?;
        decode_and_validate_block(&mut self.0, last, false)
    }
}

fn rs_batch_cap(threads: usize) -> usize {
    if threads <= 1 {
        1
    } else {
        (threads * 4).clamp(8, MAX_RS_BATCH_BLOCKS)
    }
}

/// Balanced partition of `total` blocks across `buckets` (`buckets >= 1`):
/// the first `total % buckets` buckets get `total / buckets + 1` blocks and the
/// remaining buckets get `total / buckets` blocks, ensuring every worker in
/// `0..buckets.min(total)` receives work (fixing idle helpers for `threads = 17..=63`).
#[inline]
fn balanced_slab_size(total: usize, buckets: usize, idx: usize) -> usize {
    debug_assert!(buckets >= 1 && idx < buckets);
    let base = total / buckets;
    let rem = total % buckets;
    base + usize::from(idx < rem)
}

enum SlabTask {
    Encode {
        bytes: Vec<u8>,
    },
    Decode {
        bytes: Vec<u8>,
        first_block_idx: u64,
        total_blocks: u64,
        linearize: bool,
    },
}

enum SlabResult {
    Encoded(Vec<u8>),
    Decoded {
        bytes: Vec<u8>,
        outcomes: Vec<Result<(usize, u64), ()>>,
    },
}

fn execute_slab_task(task: SlabTask) -> SlabResult {
    match task {
        SlabTask::Encode { mut bytes } => {
            for blk in bytes.as_chunks_mut::<RS_BLOCK_WIRE_SIZE>().0 {
                encode_linear_block_in_place(blk);
            }
            SlabResult::Encoded(bytes)
        }
        SlabTask::Decode {
            mut bytes,
            first_block_idx,
            total_blocks,
            linearize,
        } => {
            let n = bytes.len() / RS_BLOCK_WIRE_SIZE;
            let mut outcomes = Vec::with_capacity(n);
            let reject_empty_multi = total_blocks != 1;
            for (i, blk) in bytes
                .as_chunks_mut::<RS_BLOCK_WIRE_SIZE>()
                .0
                .iter_mut()
                .enumerate()
            {
                let is_last = first_block_idx + (i as u64) + 1 == total_blocks;
                match decode_and_validate_block(blk, is_last, reject_empty_multi) {
                    Ok((len, repaired)) => {
                        if linearize {
                            linearize_decoded_block_in_place(blk, len);
                        }
                        outcomes.push(Ok((len, repaired)));
                    }
                    Err(_) => outcomes.push(Err(())),
                }
            }
            SlabResult::Decoded { bytes, outcomes }
        }
    }
}

struct HelperSlot {
    task: Option<SlabTask>,
    result: Option<SlabResult>,
    shutdown: bool,
    panicked: bool,
}

struct HelperExitGuard {
    state: Arc<(Mutex<HelperSlot>, Condvar)>,
}

impl Drop for HelperExitGuard {
    fn drop(&mut self) {
        if thread::panicking() {
            let (lock, cv) = &*self.state;
            let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
            slot.panicked = true;
            slot.shutdown = true;
            drop(slot);
            cv.notify_all();
        }
    }
}

struct HelperWorker {
    state: Arc<(Mutex<HelperSlot>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

/// Reusable, lazily-initialized, `#![forbid(unsafe_code)]` worker pool owned by a
/// single RS encoder/reader/scanner instance. Avoids per-batch OS thread creation
/// while keeping zero global state and joining cleanly on drop.
struct RsWorkerPool {
    helpers: Vec<HelperWorker>,
    #[cfg(test)]
    helper_tasks_executed: Arc<std::sync::atomic::AtomicUsize>,
}

impl RsWorkerPool {
    fn new(threads: usize) -> Self {
        let mut pool = Self {
            helpers: Vec::new(),
            #[cfg(test)]
            helper_tasks_executed: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        pool.ensure_threads(threads);
        pool
    }

    /// Grow the helper pool on demand up to `threads - 1` (capped at `MAX_RS_BATCH_BLOCKS - 1`),
    /// avoiding over-spawning idle OS threads on small multi-block reads or flushes.
    fn ensure_threads(&mut self, threads: usize) {
        let target_helpers = threads.min(MAX_RS_BATCH_BLOCKS).saturating_sub(1);
        if self.helpers.len() >= target_helpers {
            return;
        }
        self.helpers.reserve(target_helpers - self.helpers.len());
        for _ in self.helpers.len()..target_helpers {
            let state = Arc::new((
                Mutex::new(HelperSlot {
                    task: None,
                    result: None,
                    shutdown: false,
                    panicked: false,
                }),
                Condvar::new(),
            ));
            let worker_state = Arc::clone(&state);
            #[cfg(test)]
            let task_counter = Arc::clone(&self.helper_tasks_executed);
            let Ok(handle) = thread::Builder::new().spawn(move || {
                let _guard = HelperExitGuard {
                    state: Arc::clone(&worker_state),
                };
                let (lock, cv) = &*worker_state;
                loop {
                    let task = {
                        let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
                        loop {
                            if slot.shutdown {
                                slot.task.take();
                                return;
                            }
                            if let Some(t) = slot.task.take() {
                                break t;
                            }
                            slot = cv.wait(slot).unwrap_or_else(|e| e.into_inner());
                        }
                    };
                    let res = execute_slab_task(task);
                    #[cfg(test)]
                    task_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
                    slot.result = Some(res);
                    drop(slot);
                    cv.notify_one();
                }
            }) else {
                // Gracefully degrade to the helpers already spawned (or inline execution)
                // if the OS refuses additional threads.
                break;
            };
            self.helpers.push(HelperWorker {
                state,
                handle: Some(handle),
            });
        }
    }

    fn run_encode_slabs(&mut self, slabs: &mut [Vec<u8>]) -> io::Result<()> {
        if slabs.is_empty() {
            return Ok(());
        }
        if slabs.len() == 1 || self.helpers.is_empty() {
            for slab in slabs {
                for blk in slab.as_chunks_mut::<RS_BLOCK_WIRE_SIZE>().0 {
                    encode_linear_block_in_place(blk);
                }
            }
            return Ok(());
        }

        let active_helpers = (slabs.len() - 1).min(self.helpers.len());
        // Pre-check all active helpers before taking or dispatching any slab so a
        // previously panicked helper never causes partial in-place mutation of slab 1..k.
        for helper in &self.helpers[..active_helpers] {
            let (lock, _) = &*helper.state;
            let slot = lock.lock().unwrap_or_else(|e| e.into_inner());
            if slot.panicked || slot.shutdown {
                return Err(io::Error::other("Reed-Solomon worker thread failed"));
            }
        }

        let mut dispatched = 0usize;
        let mut first_err: Option<io::Error> = None;
        for i in 0..active_helpers {
            let (lock, cv) = &*self.helpers[i].state;
            let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
            if slot.panicked || slot.shutdown {
                first_err = Some(io::Error::other("Reed-Solomon worker thread failed"));
                break;
            }
            let bytes = std::mem::take(&mut slabs[i + 1]);
            slot.task = Some(SlabTask::Encode { bytes });
            drop(slot);
            cv.notify_one();
            dispatched += 1;
        }

        if first_err.is_none() {
            // Calling thread encodes slab 0 (and any overflow slabs beyond helper_count) directly.
            for blk in slabs[0].as_chunks_mut::<RS_BLOCK_WIRE_SIZE>().0 {
                encode_linear_block_in_place(blk);
            }
            for slab in &mut slabs[(active_helpers + 1)..] {
                for blk in slab.as_chunks_mut::<RS_BLOCK_WIRE_SIZE>().0 {
                    encode_linear_block_in_place(blk);
                }
            }
        }

        // Always collect every dispatched helper so slabs are restored and no stale result lingers.
        for i in 0..dispatched {
            let (lock, cv) = &*self.helpers[i].state;
            let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                match slot.result.take() {
                    Some(SlabResult::Encoded(bytes)) => {
                        slabs[i + 1] = bytes;
                        break;
                    }
                    Some(_) => {
                        if first_err.is_none() {
                            first_err = Some(io::Error::other(
                                "unexpected Reed-Solomon worker result variant",
                            ));
                        }
                        break;
                    }
                    None => {}
                }
                if slot.panicked || slot.shutdown {
                    if first_err.is_none() {
                        first_err = Some(io::Error::other("Reed-Solomon worker thread failed"));
                    }
                    break;
                }
                slot = cv.wait(slot).unwrap_or_else(|e| e.into_inner());
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        Ok(())
    }

    fn run_decode_slabs(
        &mut self,
        slabs: &mut [Vec<u8>],
        first_block_idx: u64,
        total_blocks: u64,
        linearize: bool,
    ) -> io::Result<Vec<Result<(usize, u64), ()>>> {
        let total_in_batch: usize = slabs.iter().map(|s| s.len() / RS_BLOCK_WIRE_SIZE).sum();
        let mut all_outcomes = Vec::with_capacity(total_in_batch);
        if total_in_batch == 0 {
            return Ok(all_outcomes);
        }

        if slabs.len() == 1 || self.helpers.is_empty() {
            let mut cursor = first_block_idx;
            for slab in slabs {
                let bytes = std::mem::take(slab);
                let n = bytes.len() / RS_BLOCK_WIRE_SIZE;
                let SlabResult::Decoded { bytes, outcomes } = execute_slab_task(SlabTask::Decode {
                    bytes,
                    first_block_idx: cursor,
                    total_blocks,
                    linearize,
                }) else {
                    unreachable!()
                };
                *slab = bytes;
                all_outcomes.extend(outcomes);
                cursor += n as u64;
            }
            return Ok(all_outcomes);
        }

        let active_helpers = (slabs.len() - 1).min(self.helpers.len());
        // Pre-check all active helpers before taking or dispatching any slab so a
        // previously panicked helper never causes partial in-place mutation of slab 1..k.
        for helper in &self.helpers[..active_helpers] {
            let (lock, _) = &*helper.state;
            let slot = lock.lock().unwrap_or_else(|e| e.into_inner());
            if slot.panicked || slot.shutdown {
                return Err(io::Error::other("Reed-Solomon worker thread failed"));
            }
        }

        let mut slab_starts = Vec::with_capacity(slabs.len());
        let mut cursor = first_block_idx;
        for slab in slabs.iter() {
            slab_starts.push(cursor);
            cursor += (slab.len() / RS_BLOCK_WIRE_SIZE) as u64;
        }

        let mut dispatched = 0usize;
        let mut first_err: Option<io::Error> = None;
        for i in 0..active_helpers {
            let (lock, cv) = &*self.helpers[i].state;
            let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
            if slot.panicked || slot.shutdown {
                first_err = Some(io::Error::other("Reed-Solomon worker thread failed"));
                break;
            }
            let bytes = std::mem::take(&mut slabs[i + 1]);
            slot.task = Some(SlabTask::Decode {
                bytes,
                first_block_idx: slab_starts[i + 1],
                total_blocks,
                linearize,
            });
            drop(slot);
            cv.notify_one();
            dispatched += 1;
        }

        if first_err.is_none() {
            // Calling thread decodes slab 0 directly.
            let bytes0 = std::mem::take(&mut slabs[0]);
            let SlabResult::Decoded {
                bytes: decoded0,
                outcomes: outcomes0,
            } = execute_slab_task(SlabTask::Decode {
                bytes: bytes0,
                first_block_idx: slab_starts[0],
                total_blocks,
                linearize,
            })
            else {
                unreachable!()
            };
            slabs[0] = decoded0;
            all_outcomes.extend(outcomes0);
        }

        // Always collect every dispatched helper so slabs are restored and no stale result lingers.
        for i in 0..dispatched {
            let (lock, cv) = &*self.helpers[i].state;
            let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                match slot.result.take() {
                    Some(SlabResult::Decoded { bytes, outcomes }) => {
                        slabs[i + 1] = bytes;
                        if first_err.is_none() {
                            all_outcomes.extend(outcomes);
                        }
                        break;
                    }
                    Some(_) => {
                        if first_err.is_none() {
                            first_err = Some(io::Error::other(
                                "unexpected Reed-Solomon worker result variant",
                            ));
                        }
                        break;
                    }
                    None => {}
                }
                if slot.panicked || slot.shutdown {
                    if first_err.is_none() {
                        first_err = Some(io::Error::other("Reed-Solomon worker thread failed"));
                    }
                    break;
                }
                slot = cv.wait(slot).unwrap_or_else(|e| e.into_inner());
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }

        for (idx, slab) in slabs.iter_mut().enumerate().skip(active_helpers + 1) {
            let bytes = std::mem::take(slab);
            let SlabResult::Decoded { bytes, outcomes } = execute_slab_task(SlabTask::Decode {
                bytes,
                first_block_idx: slab_starts[idx],
                total_blocks,
                linearize,
            }) else {
                unreachable!()
            };
            *slab = bytes;
            all_outcomes.extend(outcomes);
        }

        Ok(all_outcomes)
    }
}

impl Drop for RsWorkerPool {
    fn drop(&mut self) {
        for helper in &self.helpers {
            let (lock, cv) = &*helper.state;
            let mut slot = lock.lock().unwrap_or_else(|e| e.into_inner());
            slot.shutdown = true;
            drop(slot);
            cv.notify_all();
        }
        for helper in &mut self.helpers {
            if let Some(handle) = helper.handle.take() {
                let _ = handle.join();
            }
        }
    }
}

/// Recognize redundant headers even when the first magic is damaged. A sector
/// overwrite may destroy all three: corroborate the exact physical geometry
/// with a decodable first block carrying the inner v5 magic.
pub fn probe_rs_header(r: &mut (impl Read + Seek)) -> io::Result<bool> {
    let size = r.seek(SeekFrom::End(0))?;
    r.rewind()?;
    let mut h = [0; HEADER];
    let n = size.min(HEADER as u64) as usize;
    r.read_exact(&mut h[..n])?;
    if recognized(&h[..n]) || has_unsupported_profile(&h[..n]) {
        return Ok(true);
    }
    if let Ok(count) = block_count(size) {
        let mut block = Block::new();
        match block.read(r, count == 1) {
            Ok((len, _)) => {
                let mut magic = [0; 4];
                block.copy_out(4, &mut magic);
                if len >= 4 && magic == VAULT_MAGIC {
                    return Ok(true);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidData && count > 1 => {
                // With a destroyed prefix AND an uncorrectable first block,
                // an intact, populated RS block can still identify the envelope.
                match block.read(r, count == 2) {
                    Ok((len, _)) if len > 0 => return Ok(true),
                    Err(e) if e.kind() != io::ErrorKind::InvalidData => return Err(e),
                    _ => {}
                }
            }
            Err(e) if e.kind() != io::ErrorKind::InvalidData => return Err(e),
            Err(_) => {}
        }
    }
    Ok(h.starts_with(b"RPMR")
        && (n < HEADER
            || h[16..]
                .as_chunks::<16>()
                .0
                .iter()
                .any(|c| c.starts_with(b"RPMR"))))
}

pub struct RsEncoderWriter<W> {
    inner: W,
    /// Disjoint byte slabs holding up to `batch_cap` blocks (~1 MiB max), reused across flushes.
    slabs: Vec<Vec<u8>>,
    /// Number of completely populated (unencoded) blocks across `slabs`.
    filled_blocks: usize,
    /// Bytes written into the current in-progress block (`0..RS_BLOCK_DATA_CAP`).
    used: usize,
    wrote: bool,
    /// Sticky failure guard preventing double-encoding or unbounded slab growth after
    /// an encoding or partial `write_all` failure in `flush_filled_blocks`.
    poisoned: bool,
    threads: usize,
    batch_cap: usize,
    slab_count: usize,
    pool: Option<RsWorkerPool>,
}

impl<W: Write> RsEncoderWriter<W> {
    pub fn new(inner: W) -> io::Result<Self> {
        Self::with_threads(inner, 0)
    }

    pub fn with_threads(mut inner: W, requested_threads: usize) -> io::Result<Self> {
        inner.write_all(&PREFIX)?;
        let threads = resolve_pipeline_threads(requested_threads);
        let batch_cap = rs_batch_cap(threads);
        let slab_count = threads.min(batch_cap).max(1);
        Ok(Self {
            inner,
            slabs: Vec::new(),
            filled_blocks: 0,
            used: 0,
            wrote: false,
            poisoned: false,
            threads,
            batch_cap,
            slab_count,
            pool: None,
        })
    }

    fn check_not_poisoned(&self) -> io::Result<()> {
        if self.poisoned {
            Err(io::Error::other(
                "Reed-Solomon encoder is poisoned after a prior write or worker error",
            ))
        } else {
            Ok(())
        }
    }

    fn poison_and_clear(&mut self) {
        self.poisoned = true;
        self.filled_blocks = 0;
        self.used = 0;
        for slab in &mut self.slabs {
            slab.clear();
        }
    }

    fn locate_block(&self, block_idx: usize) -> (usize, usize) {
        let base = self.batch_cap / self.slab_count;
        let rem = self.batch_cap % self.slab_count;
        let big = base + 1;
        let boundary = rem * big;
        if block_idx < boundary {
            (block_idx / big, block_idx % big)
        } else {
            let rest = block_idx - boundary;
            (rem + rest / base, rest % base)
        }
    }

    fn current_block_mut(&mut self) -> &mut [u8] {
        let (slab_idx, in_slab) = self.locate_block(self.filled_blocks);
        while self.slabs.len() <= slab_idx {
            self.slabs.push(Vec::new());
        }
        let needed_len = (in_slab + 1) * RS_BLOCK_WIRE_SIZE;
        let slab = &mut self.slabs[slab_idx];
        if slab.len() < needed_len {
            slab.resize(needed_len, 0);
        }
        let start = in_slab * RS_BLOCK_WIRE_SIZE;
        &mut slab[start..start + RS_BLOCK_WIRE_SIZE]
    }

    fn flush_filled_blocks(&mut self) -> io::Result<()> {
        self.check_not_poisoned()?;
        if self.filled_blocks == 0 {
            return Ok(());
        }
        // Trim each active slab's logical length to the exact number of filled blocks it holds
        // under balanced partitioning without shrinking capacity so allocations are reused.
        let mut remaining = self.filled_blocks;
        let mut active_slabs = 0usize;
        for s_idx in 0..self.slab_count {
            if remaining == 0 {
                break;
            }
            let cap = balanced_slab_size(self.batch_cap, self.slab_count, s_idx);
            let take = remaining.min(cap);
            self.slabs[s_idx].truncate(take * RS_BLOCK_WIRE_SIZE);
            remaining -= take;
            active_slabs += 1;
        }

        if active_slabs >= 2 && self.threads >= 2 {
            let needed_threads = active_slabs.min(self.threads);
            let pool = self
                .pool
                .get_or_insert_with(|| RsWorkerPool::new(needed_threads));
            pool.ensure_threads(needed_threads);
            if let Err(err) = pool.run_encode_slabs(&mut self.slabs[..active_slabs]) {
                self.poison_and_clear();
                return Err(err);
            }
        } else {
            for slab in self.slabs.iter_mut().take(active_slabs) {
                for blk in slab.as_chunks_mut::<RS_BLOCK_WIRE_SIZE>().0 {
                    encode_linear_block_in_place(blk);
                }
            }
        }

        for s_idx in 0..active_slabs {
            if let Err(err) = self.inner.write_all(&self.slabs[s_idx]) {
                self.poison_and_clear();
                return Err(err);
            }
        }
        for slab in self.slabs.iter_mut().take(active_slabs) {
            slab.clear();
        }
        self.filled_blocks = 0;
        self.wrote = true;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.check_not_poisoned()?;
        if self.used > 0 || (self.filled_blocks == 0 && !self.wrote) {
            let used = self.used;
            let blk = self.current_block_mut();
            blk[..4].copy_from_slice(&(used as u32).to_be_bytes());
            // Zero any unused data tail in the final partial block so stale bytes never leak.
            blk[4 + used..DATA * LANES].fill(0);
            self.filled_blocks += 1;
            self.used = 0;
        }
        self.flush_filled_blocks()?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for RsEncoderWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.check_not_poisoned()?;
        if data.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        while written < data.len() {
            let n = (data.len() - written).min(RS_BLOCK_DATA_CAP - self.used);
            let used = self.used;
            let new_used = used + n;
            let blk = self.current_block_mut();
            blk[4 + used..4 + new_used].copy_from_slice(&data[written..written + n]);
            if new_used == RS_BLOCK_DATA_CAP {
                blk[..4].copy_from_slice(&(RS_BLOCK_DATA_CAP as u32).to_be_bytes());
            }
            written += n;
            if new_used == RS_BLOCK_DATA_CAP {
                self.filled_blocks += 1;
                self.used = 0;
                if self.filled_blocks >= self.batch_cap {
                    self.flush_filled_blocks()?;
                }
            } else {
                self.used = new_used;
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check_not_poisoned()?;
        // Flush any already-complete blocks; partial trailing block waits for `finish()`.
        if self.used == 0 {
            self.flush_filled_blocks()?;
        }
        self.inner.flush()
    }
}

enum CachedBlockOutcome {
    Ok {
        len: usize,
        repaired: u64,
        counted: bool,
    },
    Invalid,
}

struct RsSeekableInner<R> {
    inner: R,
    blocks: u64,
    pos: u64,
    len: u64,
    slabs: Vec<Vec<u8>>,
    slab_block_counts: Vec<usize>,
    outcomes: Vec<CachedBlockOutcome>,
    pending_io_err: Option<(u64, io::Error)>,
    window_start: u64,
    window_len: usize,
    last_sequential_end: Option<u64>,
    repaired: u64,
    last_block_counted: bool,
    threads: usize,
    batch_cap: usize,
    pool: Option<RsWorkerPool>,
}

impl<R: Read + Seek> RsSeekableInner<R> {
    fn with_threads_and_cancel(
        mut inner: R,
        requested_threads: usize,
        cancel: Option<&AtomicBool>,
    ) -> io::Result<Self> {
        if crate::vault::is_cancelled(cancel) {
            return Err(io::Error::other("operation cancelled"));
        }
        if !probe_rs_header(&mut inner)? {
            return Err(invalid());
        }
        if crate::vault::is_cancelled(cancel) {
            return Err(io::Error::other("operation cancelled"));
        }
        let blocks = block_count(inner.seek(SeekFrom::End(0))?)?;
        inner.rewind()?;
        let mut h = [0; HEADER];
        inner.read_exact(&mut h)?;
        check_profile(&h)?;
        let threads = resolve_pipeline_threads(requested_threads);
        let batch_cap = rs_batch_cap(threads);
        let mut reader = Self {
            inner,
            blocks,
            pos: 0,
            len: 0,
            slabs: Vec::new(),
            slab_block_counts: Vec::new(),
            outcomes: Vec::new(),
            pending_io_err: None,
            window_start: 0,
            window_len: 0,
            last_sequential_end: None,
            repaired: differences(&h),
            last_block_counted: false,
            threads,
            batch_cap,
            pool: None,
        };
        // Pre-inspect only the trailing block to determine exact inner stream length.
        reader.load_window(blocks - 1, 1, cancel)?;
        let last = reader.access_cached_block(blocks - 1)?;
        reader.len = (blocks - 1) * RS_BLOCK_DATA_CAP as u64 + last as u64;
        reader.last_sequential_end = None;
        Ok(reader)
    }

    fn locate_in_slabs(&self, rel: usize) -> (usize, usize) {
        let mut rem = rel;
        for (s_idx, &count) in self.slab_block_counts.iter().enumerate() {
            if rem < count {
                return (s_idx, rem);
            }
            rem -= count;
        }
        unreachable!("rel index out of cached window")
    }

    fn load_window(
        &mut self,
        start_idx: u64,
        requested_count: usize,
        cancel: Option<&AtomicBool>,
    ) -> io::Result<()> {
        self.window_len = 0;
        self.outcomes.clear();
        self.slab_block_counts.clear();
        self.pending_io_err = None;

        if crate::vault::is_cancelled(cancel) {
            return Err(io::Error::other("operation cancelled"));
        }

        let count = (requested_count as u64)
            .min(self.blocks.saturating_sub(start_idx))
            .max(1) as usize;
        self.inner.seek(SeekFrom::Start(
            HEADER as u64 + start_idx * RS_BLOCK_WIRE_SIZE as u64,
        ))?;

        let pool_threads = self
            .threads
            .min(self.blocks.min(MAX_RS_BATCH_BLOCKS as u64) as usize)
            .max(1);
        let worker_count = if count >= 2 && pool_threads >= 2 {
            pool_threads.min(count)
        } else {
            1
        };

        while self.slabs.len() < worker_count {
            self.slabs.push(Vec::new());
        }

        let mut read_blocks = 0usize;
        let mut io_failure: Option<io::Error> = None;
        let mut active_slabs = 0usize;

        for s_idx in 0..worker_count {
            if read_blocks >= count {
                break;
            }
            if crate::vault::is_cancelled(cancel) {
                return Err(io::Error::other("operation cancelled"));
            }
            let want_here = balanced_slab_size(count, worker_count, s_idx);
            let slab = &mut self.slabs[s_idx];
            slab.resize(want_here * RS_BLOCK_WIRE_SIZE, 0);
            let mut got_here = 0usize;
            for b in 0..want_here {
                if crate::vault::is_cancelled(cancel) {
                    return Err(io::Error::other("operation cancelled"));
                }
                let off = b * RS_BLOCK_WIRE_SIZE;
                match self
                    .inner
                    .read_exact(&mut slab[off..off + RS_BLOCK_WIRE_SIZE])
                {
                    Ok(()) => {
                        got_here += 1;
                    }
                    Err(e) => {
                        io_failure = Some(e);
                        break;
                    }
                }
            }
            slab.truncate(got_here * RS_BLOCK_WIRE_SIZE);
            if got_here > 0 {
                self.slab_block_counts.push(got_here);
                active_slabs += 1;
                read_blocks += got_here;
            }
            if io_failure.is_some() {
                break;
            }
        }

        if crate::vault::is_cancelled(cancel) {
            return Err(io::Error::other("operation cancelled"));
        }

        if read_blocks == 0 {
            return Err(io_failure.unwrap_or_else(invalid));
        }

        let decoded = if active_slabs >= 2 && pool_threads >= 2 {
            let needed_threads = active_slabs.min(pool_threads);
            let pool = self
                .pool
                .get_or_insert_with(|| RsWorkerPool::new(needed_threads));
            pool.ensure_threads(needed_threads);
            pool.run_decode_slabs(
                &mut self.slabs[..active_slabs],
                start_idx,
                self.blocks,
                true,
            )?
        } else {
            let mut single = Vec::with_capacity(read_blocks);
            let mut cur = start_idx;
            let reject_empty_multi = self.blocks != 1;
            for slab in self.slabs.iter_mut().take(active_slabs) {
                for blk in slab.as_chunks_mut::<RS_BLOCK_WIRE_SIZE>().0 {
                    if crate::vault::is_cancelled(cancel) {
                        return Err(io::Error::other("operation cancelled"));
                    }
                    let is_last = cur + 1 == self.blocks;
                    match decode_and_validate_block(blk, is_last, reject_empty_multi) {
                        Ok((len, repaired)) => {
                            linearize_decoded_block_in_place(blk, len);
                            single.push(Ok((len, repaired)));
                        }
                        Err(_) => single.push(Err(())),
                    }
                    cur += 1;
                }
            }
            single
        };

        for item in decoded {
            match item {
                Ok((len, repaired)) => self.outcomes.push(CachedBlockOutcome::Ok {
                    len,
                    repaired,
                    counted: false,
                }),
                Err(()) => self.outcomes.push(CachedBlockOutcome::Invalid),
            }
        }

        if let Some(err) = io_failure {
            self.pending_io_err = Some((start_idx + read_blocks as u64, err));
        }

        self.window_start = start_idx;
        self.window_len = self.outcomes.len();
        self.last_sequential_end = Some(start_idx + read_blocks as u64);
        Ok(())
    }

    fn access_cached_block(&mut self, index: u64) -> io::Result<usize> {
        let rel = (index - self.window_start) as usize;
        let is_last = index + 1 == self.blocks;
        match &mut self.outcomes[rel] {
            CachedBlockOutcome::Ok {
                len,
                repaired,
                counted,
            } => {
                if !*counted {
                    *counted = true;
                    if !(is_last && self.last_block_counted) {
                        self.repaired += *repaired;
                    }
                    if is_last {
                        self.last_block_counted = true;
                    }
                }
                Ok(*len)
            }
            CachedBlockOutcome::Invalid => Err(invalid()),
        }
    }

    fn read_with_cancel(
        &mut self,
        out: &mut [u8],
        cancel: Option<&AtomicBool>,
    ) -> io::Result<usize> {
        if crate::vault::is_cancelled(cancel) {
            return Err(io::Error::other("operation cancelled"));
        }
        if self.pos >= self.len || out.is_empty() {
            return Ok(0);
        }
        let index = self.pos / RS_BLOCK_DATA_CAP as u64;
        let start = (self.pos % RS_BLOCK_DATA_CAP as u64) as usize;
        let in_window =
            index >= self.window_start && index < self.window_start + self.window_len as u64;
        if !in_window {
            if self
                .pending_io_err
                .as_ref()
                .is_some_and(|(err_idx, _)| *err_idx == index)
            {
                return Err(self.pending_io_err.take().unwrap().1);
            }
            let needed = start
                .saturating_add(out.len())
                .div_ceil(RS_BLOCK_DATA_CAP)
                .max(1);
            let is_sequential = self.last_sequential_end == Some(index);
            let want = if self.threads <= 1 {
                1
            } else if is_sequential {
                self.batch_cap
            } else if needed > 1 {
                needed.min(self.batch_cap)
            } else {
                1
            };
            self.load_window(index, want, cancel)?;
        }
        let block_len = self.access_cached_block(index)?;
        let n = (out.len().min(block_len.saturating_sub(start)) as u64).min(self.len - self.pos)
            as usize;
        let rel = (index - self.window_start) as usize;
        let (slab_idx, in_slab) = self.locate_in_slabs(rel);
        let blk_off = in_slab * RS_BLOCK_WIRE_SIZE;
        let blk = &self.slabs[slab_idx][blk_off..blk_off + RS_BLOCK_WIRE_SIZE];
        out[..n].copy_from_slice(&blk[start..start + n]);
        self.pos += n as u64;
        Ok(n)
    }

    fn seek_pos(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.pos = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"))?;
        Ok(self.pos)
    }
}

pub struct RsSeekableReader<R> {
    inner: RsSeekableInner<R>,
    cancel: Option<Arc<AtomicBool>>,
}

impl<R: Read + Seek> RsSeekableReader<R> {
    pub fn new(inner: R) -> io::Result<Self> {
        Self::with_threads(inner, 0)
    }

    pub fn with_threads(inner: R, requested_threads: usize) -> io::Result<Self> {
        Self::with_threads_and_cancel(inner, requested_threads, None)
    }

    pub fn with_threads_and_cancel(
        inner: R,
        requested_threads: usize,
        cancel: Option<Arc<AtomicBool>>,
    ) -> io::Result<Self> {
        let inner =
            RsSeekableInner::with_threads_and_cancel(inner, requested_threads, cancel.as_deref())?;
        Ok(Self { inner, cancel })
    }

    /// Corrections encountered during reads (counts the pre-inspected final block once; revisited blocks recount).
    pub fn repaired_bytes(&self) -> u64 {
        self.inner.repaired
    }
}

impl<R: Read + Seek> Read for RsSeekableReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.inner.read_with_cancel(out, self.cancel.as_deref())
    }
}

impl<R: Read + Seek> Seek for RsSeekableReader<R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.inner.seek_pos(from)
    }
}

/// Internal seekable RS reader borrowing a caller-supplied `&AtomicBool` cancellation flag.
pub(crate) struct BorrowedCancelRsReader<'c, R> {
    inner: RsSeekableInner<R>,
    cancel: Option<&'c AtomicBool>,
}

impl<'c, R: Read + Seek> BorrowedCancelRsReader<'c, R> {
    pub(crate) fn with_threads_and_cancel(
        inner: R,
        requested_threads: usize,
        cancel: Option<&'c AtomicBool>,
    ) -> io::Result<Self> {
        let inner = RsSeekableInner::with_threads_and_cancel(inner, requested_threads, cancel)?;
        Ok(Self { inner, cancel })
    }

    pub(crate) fn repaired_bytes(&self) -> u64 {
        self.inner.repaired
    }
}

impl<R: Read + Seek> Read for BorrowedCancelRsReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.inner.read_with_cancel(out, self.cancel)
    }
}

impl<R: Read + Seek> Seek for BorrowedCancelRsReader<'_, R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.inner.seek_pos(from)
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RepairReport {
    pub blocks_checked: u64,
    pub repaired_bytes: u64,
    pub header_repaired: bool,
}

enum ScanOutcome {
    Ok(usize, u64),
    Invalid,
    IoError(Option<io::Error>),
}

// Forward-only batch-parallel decoder shared by passwordless structural scanning and repair.
// Disk bytes can be hashed below this adapter, before any correction.
pub(crate) struct Scan<'c, R> {
    inner: R,
    slabs: Vec<Vec<u8>>,
    slab_block_counts: Vec<usize>,
    outcomes: Vec<ScanOutcome>,
    batch_cursor: usize,
    active_rel: Option<usize>,
    count: u64,
    fetched: u64,
    next: u64,
    offset: usize,
    len: usize,
    threads: usize,
    batch_cap: usize,
    preserve_wire: bool,
    io_failed: bool,
    pool: Option<RsWorkerPool>,
    cancel: Option<&'c AtomicBool>,
    pub report: RepairReport,
}

impl<'c, R: Read> Scan<'c, R> {
    pub fn new_with_options(
        mut inner: R,
        size: u64,
        requested_threads: usize,
        preserve_wire: bool,
        cancel: Option<&'c AtomicBool>,
    ) -> io::Result<Self> {
        if crate::vault::is_cancelled(cancel) {
            return Err(io::Error::other("operation cancelled"));
        }
        let count = block_count(size)?;
        let mut prefix = [0; HEADER];
        inner.read_exact(&mut prefix)?;
        check_profile(&prefix)?;
        let changed = differences(&prefix);
        let threads = resolve_pipeline_threads(requested_threads);
        let batch_cap = rs_batch_cap(threads);
        Ok(Self {
            inner,
            slabs: Vec::new(),
            slab_block_counts: Vec::new(),
            outcomes: Vec::new(),
            batch_cursor: 0,
            active_rel: None,
            count,
            fetched: 0,
            next: 0,
            offset: 0,
            len: 0,
            threads,
            batch_cap,
            preserve_wire,
            io_failed: false,
            pool: None,
            cancel,
            report: RepairReport {
                blocks_checked: 0,
                repaired_bytes: changed,
                header_repaired: changed != 0,
            },
        })
    }

    pub(crate) fn has_io_error(&self) -> bool {
        self.io_failed
    }

    fn fetch_batch(&mut self) -> io::Result<()> {
        if self.io_failed {
            return Err(io::Error::other(
                "Reed-Solomon scan aborted after prior I/O error",
            ));
        }
        self.outcomes.clear();
        self.slab_block_counts.clear();
        self.batch_cursor = 0;
        self.active_rel = None;

        let remaining = self.count - self.fetched;
        if remaining == 0 {
            return Ok(());
        }
        let want = remaining.min(self.batch_cap as u64) as usize;
        let start_idx = self.fetched;

        let pool_threads = self
            .threads
            .min(self.count.min(MAX_RS_BATCH_BLOCKS as u64) as usize)
            .max(1);
        let worker_count = if want >= 2 && pool_threads >= 2 {
            pool_threads.min(want)
        } else {
            1
        };

        while self.slabs.len() < worker_count {
            self.slabs.push(Vec::new());
        }

        let mut read_blocks = 0usize;
        let mut io_failure: Option<io::Error> = None;
        let mut active_slabs = 0usize;

        for s_idx in 0..worker_count {
            if read_blocks >= want {
                break;
            }
            if crate::vault::is_cancelled(self.cancel) {
                self.io_failed = true;
                return Err(io::Error::other("operation cancelled"));
            }
            let want_here = balanced_slab_size(want, worker_count, s_idx);
            let slab = &mut self.slabs[s_idx];
            slab.resize(want_here * RS_BLOCK_WIRE_SIZE, 0);
            let mut got_here = 0usize;
            for b in 0..want_here {
                if crate::vault::is_cancelled(self.cancel) {
                    self.io_failed = true;
                    return Err(io::Error::other("operation cancelled"));
                }
                let off = b * RS_BLOCK_WIRE_SIZE;
                match self
                    .inner
                    .read_exact(&mut slab[off..off + RS_BLOCK_WIRE_SIZE])
                {
                    Ok(()) => got_here += 1,
                    Err(e) => {
                        io_failure = Some(e);
                        break;
                    }
                }
            }
            slab.truncate(got_here * RS_BLOCK_WIRE_SIZE);
            if got_here > 0 {
                self.slab_block_counts.push(got_here);
                active_slabs += 1;
                read_blocks += got_here;
            }
            if io_failure.is_some() {
                break;
            }
        }

        if crate::vault::is_cancelled(self.cancel) {
            self.io_failed = true;
            return Err(io::Error::other("operation cancelled"));
        }

        self.fetched += read_blocks as u64 + u64::from(io_failure.is_some());

        if read_blocks > 0 {
            let linearize = !self.preserve_wire;
            let decoded = if active_slabs >= 2 && pool_threads >= 2 {
                let needed_threads = active_slabs.min(pool_threads);
                let pool = self
                    .pool
                    .get_or_insert_with(|| RsWorkerPool::new(needed_threads));
                pool.ensure_threads(needed_threads);
                match pool.run_decode_slabs(
                    &mut self.slabs[..active_slabs],
                    start_idx,
                    self.count,
                    linearize,
                ) {
                    Ok(res) => res,
                    Err(err) => {
                        self.io_failed = true;
                        return Err(err);
                    }
                }
            } else {
                let mut single = Vec::with_capacity(read_blocks);
                let mut cur = start_idx;
                let reject_empty_multi = self.count != 1;
                for slab in self.slabs.iter_mut().take(active_slabs) {
                    for blk in slab.as_chunks_mut::<RS_BLOCK_WIRE_SIZE>().0 {
                        if crate::vault::is_cancelled(self.cancel) {
                            self.io_failed = true;
                            return Err(io::Error::other("operation cancelled"));
                        }
                        let is_last = cur + 1 == self.count;
                        match decode_and_validate_block(blk, is_last, reject_empty_multi) {
                            Ok((len, repaired)) => {
                                if linearize {
                                    linearize_decoded_block_in_place(blk, len);
                                }
                                single.push(Ok((len, repaired)));
                            }
                            Err(_) => single.push(Err(())),
                        }
                        cur += 1;
                    }
                }
                single
            };

            for item in decoded {
                match item {
                    Ok((len, n)) => self.outcomes.push(ScanOutcome::Ok(len, n)),
                    Err(()) => self.outcomes.push(ScanOutcome::Invalid),
                }
            }
        }

        if let Some(err) = io_failure {
            self.outcomes.push(ScanOutcome::IoError(Some(err)));
        }
        Ok(())
    }

    fn current_block_bytes(&self) -> &[u8] {
        let mut rem = self.active_rel.expect("active block set");
        for (s_idx, &count) in self.slab_block_counts.iter().enumerate() {
            if rem < count {
                let off = rem * RS_BLOCK_WIRE_SIZE;
                return &self.slabs[s_idx][off..off + RS_BLOCK_WIRE_SIZE];
            }
            rem -= count;
        }
        unreachable!("active_rel out of bounds")
    }

    pub fn next_block(&mut self) -> io::Result<bool> {
        if self.io_failed {
            return Err(io::Error::other(
                "Reed-Solomon scan aborted after prior I/O error",
            ));
        }
        if crate::vault::is_cancelled(self.cancel) {
            self.io_failed = true;
            return Err(io::Error::other("operation cancelled"));
        }
        if self.next == self.count {
            return Ok(false);
        }
        if self.batch_cursor >= self.outcomes.len() {
            self.fetch_batch()?;
            if self.outcomes.is_empty() {
                return Ok(false);
            }
        }

        let rel = self.batch_cursor;
        self.batch_cursor += 1;
        self.next += 1;
        self.len = 0;
        self.offset = 0;
        self.active_rel = None;

        match &mut self.outcomes[rel] {
            ScanOutcome::Ok(len, repaired) => {
                self.len = *len;
                self.active_rel = Some(rel);
                self.report.blocks_checked += 1;
                self.report.repaired_bytes += *repaired;
                Ok(true)
            }
            ScanOutcome::Invalid => Err(invalid()),
            ScanOutcome::IoError(err) => {
                self.io_failed = true;
                Err(err
                    .take()
                    .unwrap_or_else(|| io::Error::other("I/O error reading Reed-Solomon block")))
            }
        }
    }
}

impl<R: Read> Read for Scan<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.offset == self.len && !self.next_block()? {
            return Ok(0);
        }
        let n = out.len().min(self.len - self.offset);
        let blk = self.current_block_bytes();
        if self.preserve_wire {
            copy_out_slice(blk, 4 + self.offset, &mut out[..n]);
        } else {
            out[..n].copy_from_slice(&blk[self.offset..self.offset + n]);
        }
        self.offset += n;
        Ok(n)
    }
}

// Feed corrected inner bytes to the existing structural validator while writing
// each corrected wire block exactly once. In particular, dropping a whole RS
// block can leave valid syndromes while truncating the inner v5 container.
struct RepairScan<'a, R, W> {
    scan: Scan<'a, R>,
    writer: &'a mut W,
    cancel: Option<&'a AtomicBool>,
    read_error: Option<io::Error>,
    write_error: Option<io::Error>,
}

impl<R: Read, W: Write> Read for RepairScan<'_, R, W> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if crate::vault::is_cancelled(self.cancel) {
            return Err(io::Error::other("repair cancelled"));
        }
        let before = self.scan.report.blocks_checked;
        let n = match self.scan.read(out) {
            Ok(n) => n,
            Err(e) if e.kind() != io::ErrorKind::InvalidData => {
                self.read_error = Some(e);
                return Err(io::Error::other("cannot read vault block"));
            }
            Err(e) => return Err(e),
        };
        if self.scan.report.blocks_checked != before {
            if let Err(e) = self.writer.write_all(self.scan.current_block_bytes()) {
                self.write_error = Some(e);
                return Err(io::Error::other("cannot write repaired block"));
            }
        }
        Ok(n)
    }
}

pub fn repair_vault_stream<R: Read + Seek, W: Write>(
    reader: &mut R,
    writer: &mut W,
    cancel: Option<&AtomicBool>,
) -> Result<RepairReport, CryptoError> {
    repair_vault_stream_with_threads(reader, writer, cancel, 0)
}

pub fn repair_vault_stream_with_threads<R: Read + Seek, W: Write>(
    reader: &mut R,
    writer: &mut W,
    cancel: Option<&AtomicBool>,
    threads: usize,
) -> Result<RepairReport, CryptoError> {
    if crate::vault::is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }
    if !probe_rs_header(reader)? {
        return Err(CryptoError::UnsupportedOperation(
            "Reed-Solomon protection is required for repair".into(),
        ));
    }
    let size = reader.seek(SeekFrom::End(0))?;
    reader.rewind()?;
    let scan = Scan::new_with_options(reader, size, threads, true, cancel)?;
    if crate::vault::is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }
    writer.write_all(&PREFIX)?;
    let mut repair = RepairScan {
        scan,
        writer,
        cancel,
        read_error: None,
        write_error: None,
    };
    let (ok, _, message, ..) = crate::vault::scan_structure(&mut repair, cancel);
    if let Some(e) = repair.write_error {
        return Err(e.into());
    }
    if crate::vault::is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }
    if let Some(e) = repair.read_error {
        return Err(e.into());
    }
    if !ok {
        return Err(CryptoError::InvalidFormat(message));
    }
    repair.writer.flush()?;
    Ok(repair.scan.report)
}

pub(crate) fn validate_mode(stealth: bool) -> Result<(), CryptoError> {
    if stealth {
        return Err(CryptoError::InvalidFormat(
            "Reed-Solomon parity is incompatible with Stealth mode".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::Ordering;

    #[test]
    fn worker_pool_recovers_from_panicked_helper_without_deadlock_or_lost_slabs() {
        let mut pool = RsWorkerPool::new(4);
        assert_eq!(pool.helpers.len(), 3);

        // Simulate helper 1 having panicked prior to a batch while helper 0 is healthy.
        {
            let (lock, _) = &*pool.helpers[1].state;
            let mut slot = lock.lock().unwrap();
            slot.panicked = true;
        }

        // Use non-zero slab data so partial in-place encoding/decoding of slab 1 is detected!
        let orig_enc_slabs: Vec<Vec<u8>> = (0..4usize)
            .map(|s| {
                (0..RS_BLOCK_WIRE_SIZE)
                    .map(|i| ((i * 13 + s * 37 + 1) % 251) as u8)
                    .collect()
            })
            .collect();
        let mut enc_slabs = orig_enc_slabs.clone();
        let err = pool.run_encode_slabs(&mut enc_slabs).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        // Pre-check must fail before dispatching slab 1 to helper 0 -> ZERO slabs mutated and 0 tasks executed.
        assert_eq!(enc_slabs, orig_enc_slabs);
        assert_eq!(pool.helper_tasks_executed.load(Ordering::Relaxed), 0);
        {
            let (lock, _) = &*pool.helpers[0].state;
            assert!(lock.lock().unwrap().result.is_none());
        }

        // Same invariant for decode slabs with non-zero encoded blocks.
        let mut dec_slabs = orig_enc_slabs.clone();
        for slab in &mut dec_slabs {
            encode_linear_block_in_place(slab);
        }
        let orig_dec_slabs = dec_slabs.clone();
        let derr = pool
            .run_decode_slabs(&mut dec_slabs, 0, 4, true)
            .unwrap_err();
        assert_eq!(derr.kind(), io::ErrorKind::Other);
        assert_eq!(dec_slabs, orig_dec_slabs);
        assert_eq!(pool.helper_tasks_executed.load(Ordering::Relaxed), 0);
        {
            let (lock, _) = &*pool.helpers[0].state;
            assert!(lock.lock().unwrap().result.is_none());
        }

        // Exercise HelperExitGuard directly on a real panicking thread so wait loop wakes cleanly.
        let state = Arc::new((
            Mutex::new(HelperSlot {
                task: None,
                result: None,
                shutdown: false,
                panicked: false,
            }),
            Condvar::new(),
        ));
        let worker_state = Arc::clone(&state);
        let handle = thread::spawn(move || {
            let _guard = HelperExitGuard {
                state: worker_state,
            };
            panic!("injected helper panic");
        });
        let _ = handle.join();
        let (lock, _) = &*state;
        let slot = lock.lock().unwrap();
        assert!(slot.panicked);
        assert!(slot.shutdown);
    }

    #[test]
    fn encoder_poisons_cleanly_after_partial_write_error_without_double_encoding_or_slab_growth() {
        #[derive(Debug)]
        struct FailAfterBytesWriter {
            buf: Vec<u8>,
            limit: usize,
            failed_once: bool,
        }
        impl Write for FailAfterBytesWriter {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                if !self.failed_once && self.buf.len() + data.len() > self.limit {
                    self.failed_once = true;
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "injected partial write failure",
                    ));
                }
                self.buf.extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        // Allow header + slab 0, then fail on slab 1 during a 4-slab flush.
        let writer = FailAfterBytesWriter {
            buf: Vec::new(),
            limit: HEADER + RS_BLOCK_WIRE_SIZE * 2,
            failed_once: false,
        };
        let mut enc = RsEncoderWriter::with_threads(writer, 4).unwrap();
        let payload: Vec<u8> = (0..(RS_BLOCK_DATA_CAP * 16))
            .map(|i| ((i * 29 + 7) % 251) as u8)
            .collect();
        let err = enc.write_all(&payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(enc.poisoned);
        assert_eq!(enc.filled_blocks, 0);
        assert_eq!(enc.used, 0);
        assert!(enc.slabs.iter().all(|s| s.is_empty()));
        let bytes_after_fail = enc.inner.buf.len();

        // Subsequent write, flush, and finish must all reject immediately without writing
        // double-encoded bytes or growing slabs.
        assert_eq!(
            enc.write(&[0x55u8; RS_BLOCK_DATA_CAP]).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(enc.flush().unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(enc.inner.buf.len(), bytes_after_fail);
        assert!(enc.slabs.iter().all(|s| s.is_empty()));
        assert_eq!(enc.finish().unwrap_err().kind(), io::ErrorKind::Other);
    }

    #[test]
    fn balanced_slab_partitioning_utilizes_all_helpers_for_threads_17_to_64() {
        // 65 full RS blocks: encoder flushes a full 64-block batch (blocks 0..64), and
        // sequential reader reads block 0 then fetches a full 64-block batch (blocks 1..65).
        // Every thread count in 17..=64 must partition across ALL `threads` slabs (0 idle helpers).
        let payload: Vec<u8> = (0..(RS_BLOCK_DATA_CAP * (MAX_RS_BATCH_BLOCKS + 1)))
            .map(|i| ((i * 11 + 3) % 251) as u8)
            .collect();
        let mut baseline_enc = RsEncoderWriter::with_threads(Vec::new(), 1).unwrap();
        baseline_enc.write_all(&payload).unwrap();
        let baseline_wire = baseline_enc.finish().unwrap();

        for threads in [17usize, 20, 32, 33, 48, 56, 63, 64] {
            let mut enc = RsEncoderWriter::with_threads(Vec::new(), threads).unwrap();
            enc.write_all(&payload).unwrap();
            {
                let pool = enc.pool.as_ref().expect("64-block flush uses helper pool");
                assert_eq!(
                    pool.helpers.len(),
                    threads - 1,
                    "encoder helper count for threads={threads}"
                );
                assert_eq!(
                    pool.helper_tasks_executed.load(Ordering::Relaxed),
                    threads - 1,
                    "encoder idle helpers detected for threads={threads}"
                );
            }
            let wire = enc.finish().unwrap();
            assert_eq!(wire, baseline_wire, "wire mismatch for threads={threads}");

            let mut reader = RsSeekableReader::with_threads(Cursor::new(&wire), threads).unwrap();
            let mut decoded = Vec::new();
            reader.read_to_end(&mut decoded).unwrap();
            assert_eq!(decoded, payload);
            let rpool = reader
                .inner
                .pool
                .as_ref()
                .expect("64-block sequential read uses helper pool");
            assert_eq!(
                rpool.helpers.len(),
                threads - 1,
                "reader helper count for threads={threads}"
            );
            assert!(
                rpool.helper_tasks_executed.load(Ordering::Relaxed) >= threads - 1,
                "reader idle helpers detected for threads={threads}"
            );

            let mut scan =
                Scan::new_with_options(Cursor::new(&wire), wire.len() as u64, threads, false, None)
                    .unwrap();
            let mut scanned = Vec::new();
            scan.read_to_end(&mut scanned).unwrap();
            assert_eq!(scanned, payload);
            let spool = scan.pool.as_ref().expect("64-block scan uses helper pool");
            assert_eq!(
                spool.helpers.len(),
                threads - 1,
                "scan helper count for threads={threads}"
            );
            assert!(
                spool.helper_tasks_executed.load(Ordering::Relaxed) >= threads - 1,
                "scan idle helpers detected for threads={threads}"
            );
        }
    }

    #[test]
    fn seekable_reader_load_window_honors_cancellation() {
        let payload = vec![0x7Au8; RS_BLOCK_DATA_CAP * 20 + 77];
        let mut enc = RsEncoderWriter::with_threads(Vec::new(), 4).unwrap();
        enc.write_all(&payload).unwrap();
        let wire = enc.finish().unwrap();

        struct CancellingCursor {
            inner: Cursor<Vec<u8>>,
            cancel: Arc<AtomicBool>,
            reads: usize,
            trip_at: usize,
        }
        impl Read for CancellingCursor {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                if self.reads >= self.trip_at {
                    self.cancel.store(true, Ordering::Relaxed);
                }
                self.inner.read(buf)
            }
        }
        impl Seek for CancellingCursor {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                self.inner.seek(pos)
            }
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let src = CancellingCursor {
            inner: Cursor::new(wire),
            cancel: Arc::clone(&cancel),
            reads: 0,
            trip_at: 8,
        };
        let mut r =
            RsSeekableReader::with_threads_and_cancel(src, 8, Some(Arc::clone(&cancel))).unwrap();
        let mut out = vec![0u8; payload.len()];
        let err = r.read_exact(&mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(cancel.load(Ordering::Relaxed));
    }

    #[test]
    fn scan_sets_sticky_io_failed_after_transient_single_shot_eio() {
        let payload = vec![0x42u8; RS_BLOCK_DATA_CAP * 10 + 99];
        let mut enc = RsEncoderWriter::with_threads(Vec::new(), 4).unwrap();
        enc.write_all(&payload).unwrap();
        let wire = enc.finish().unwrap();

        struct SingleShotPartialEio {
            inner: Cursor<Vec<u8>>,
            fail_at: u64,
            armed: bool,
            reads_after_eio: usize,
        }
        impl Read for SingleShotPartialEio {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let pos = self.inner.position();
                if self.armed && pos >= self.fail_at {
                    // Advance 500 bytes first (misaligning the forward stream) then return EIO!
                    self.armed = false;
                    let take = buf.len().min(500);
                    let _ = self.inner.read(&mut buf[..take]);
                    return Err(io::Error::from_raw_os_error(5));
                }
                if !self.armed {
                    self.reads_after_eio += 1;
                }
                self.inner.read(buf)
            }
        }

        let src = SingleShotPartialEio {
            inner: Cursor::new(wire.clone()),
            fail_at: HEADER as u64 + 3 * RS_BLOCK_WIRE_SIZE as u64,
            armed: true,
            reads_after_eio: 0,
        };
        let mut scan = Scan::new_with_options(src, wire.len() as u64, 4, false, None).unwrap();
        // Blocks 0, 1, 2 succeed cleanly.
        assert!(scan.next_block().unwrap());
        assert!(scan.next_block().unwrap());
        assert!(scan.next_block().unwrap());
        // Block 3 surfaces the exact raw OS error 5 and sets sticky io_failed.
        let err = scan.next_block().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(5));
        assert!(scan.has_io_error());
        let reads_right_after = scan.inner.reads_after_eio;

        // Subsequent next_block() must NOT read misaligned bytes or return InvalidData!
        let sticky_err = scan.next_block().unwrap_err();
        assert_eq!(sticky_err.kind(), io::ErrorKind::Other);
        assert_eq!(scan.inner.reads_after_eio, reads_right_after);
    }

    #[test]
    fn worker_pool_mismatched_result_variant_errors_without_deadlock() {
        // Construct a pool with a deterministic slot pre-loaded with a mismatched result
        // variant (no background thread racing `slot.result`) so `run_encode_slabs`
        // deterministically exercises the defensive `Some(_)` branch instead of deadlocking.
        let state = Arc::new((
            Mutex::new(HelperSlot {
                task: None,
                result: Some(SlabResult::Decoded {
                    bytes: vec![0u8; RS_BLOCK_WIRE_SIZE],
                    outcomes: vec![],
                }),
                shutdown: false,
                panicked: false,
            }),
            Condvar::new(),
        ));
        let mut pool = RsWorkerPool {
            helpers: vec![HelperWorker {
                state,
                handle: None,
            }],
            helper_tasks_executed: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let mut slabs = vec![vec![0x11u8; RS_BLOCK_WIRE_SIZE]; 2];
        let err = pool.run_encode_slabs(&mut slabs).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn encoder_skips_worker_pool_spawn_when_only_one_slab_is_active() {
        let payload = vec![0x3Cu8; RS_BLOCK_DATA_CAP * 3 + 100];
        let mut enc = RsEncoderWriter::with_threads(Vec::new(), 16).unwrap();
        enc.write_all(&payload).unwrap();
        // With threads=16, batch_cap=64, balanced slab 0 cap=4 -> 3 filled blocks stay in slab 0.
        assert!(enc.pool.is_none());
        enc.flush().unwrap();
        assert!(enc.pool.is_none());
        let wire = enc.finish().unwrap();

        let mut dec = Vec::new();
        RsSeekableReader::with_threads(Cursor::new(&wire), 16)
            .unwrap()
            .read_to_end(&mut dec)
            .unwrap();
        assert_eq!(dec, payload);
    }

    #[test]
    fn seekable_reader_preserves_os_io_error_and_recovers_on_retry() {
        let payload: Vec<u8> = (0..(RS_BLOCK_DATA_CAP * 12 + 321))
            .map(|i| ((i * 19 + 5) % 251) as u8)
            .collect();
        let mut enc = RsEncoderWriter::with_threads(Vec::new(), 4).unwrap();
        enc.write_all(&payload).unwrap();
        let wire = enc.finish().unwrap();

        struct FaultyReader {
            inner: Cursor<Vec<u8>>,
            fail_offset: u64,
            armed: bool,
        }
        impl Read for FaultyReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let pos = self.inner.position();
                if self.armed
                    && pos >= self.fail_offset
                    && pos < self.fail_offset + RS_BLOCK_WIRE_SIZE as u64
                {
                    self.armed = false;
                    return Err(io::Error::from_raw_os_error(23));
                }
                self.inner.read(buf)
            }
        }
        impl Seek for FaultyReader {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                self.inner.seek(pos)
            }
        }

        // Trigger a one-shot OS error (raw code 23) on block 4 inside a multi-block prefetch window.
        let fail_offset = HEADER as u64 + 4 * RS_BLOCK_WIRE_SIZE as u64;
        let faulty = FaultyReader {
            inner: Cursor::new(wire),
            fail_offset,
            armed: true,
        };
        let mut r = RsSeekableReader::with_threads(faulty, 8).unwrap();

        // Blocks 0..4 must read cleanly despite block 4 failing during prefetch.
        let mut first4 = vec![0u8; 4 * RS_BLOCK_DATA_CAP];
        r.read_exact(&mut first4).unwrap();
        assert_eq!(first4, payload[..first4.len()]);

        // Block 4 surfaces the exact OS error (preserving raw_os_error() == Some(23)).
        let mut blk4 = vec![0u8; RS_BLOCK_DATA_CAP];
        let err = r.read(&mut blk4).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(23));

        // Retrying block 4 after the transient fault clears must re-read from underlying reader and succeed!
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, payload[first4.len()..]);
    }

    #[test]
    fn worker_pool_scales_helpers_on_demand_and_executes_tasks_on_helper_threads() {
        let payload: Vec<u8> = (0..(RS_BLOCK_DATA_CAP * 20 + 123))
            .map(|i| ((i * 7 + 11) % 251) as u8)
            .collect();

        // 1. Encoder with threads=64 flushing 3 blocks spawns only 2 helpers (not 63),
        // then grows on demand when a larger batch arrives.
        let mut enc = RsEncoderWriter::with_threads(Vec::new(), 64).unwrap();
        enc.write_all(&payload[..RS_BLOCK_DATA_CAP * 3]).unwrap();
        enc.flush().unwrap();
        let pool = enc.pool.as_ref().expect("3 slabs should spawn 2 helpers");
        assert_eq!(pool.helpers.len(), 2);
        assert_eq!(pool.helper_tasks_executed.load(Ordering::Relaxed), 2);

        enc.write_all(&payload[RS_BLOCK_DATA_CAP * 3..]).unwrap();
        // Flush remaining 17 full blocks + partial tail -> 18 slabs -> grows to 17 helpers.
        let wire = {
            let used = enc.used;
            let blk = enc.current_block_mut();
            blk[..4].copy_from_slice(&(used as u32).to_be_bytes());
            blk[4 + used..DATA * LANES].fill(0);
            enc.filled_blocks += 1;
            enc.used = 0;
            enc.flush_filled_blocks().unwrap();
            let pool = enc.pool.as_ref().unwrap();
            assert_eq!(pool.helpers.len(), 17);
            assert_eq!(pool.helper_tasks_executed.load(Ordering::Relaxed), 2 + 17);
            enc.inner
        };

        // 2. Single-threaded reader never spawns a worker pool.
        let mut r1 = RsSeekableReader::with_threads(Cursor::new(&wire), 1).unwrap();
        let mut out1 = Vec::new();
        r1.read_to_end(&mut out1).unwrap();
        assert_eq!(out1, payload);
        assert!(r1.inner.pool.is_none());

        // 3. Multi-threaded reader with threads=64 doing a 3-block non-sequential read
        // (such as hidden-compartment manifest inspection) spawns only 2 helpers (not 63),
        // executes 2 helper tasks, then grows on demand when streaming sequentially.
        let mut r64 = RsSeekableReader::with_threads(Cursor::new(&wire), 64).unwrap();
        assert!(r64.inner.pool.is_none());
        let seek_off = (5 * RS_BLOCK_DATA_CAP) as u64;
        r64.seek(SeekFrom::Start(seek_off)).unwrap();
        let mut three_blocks = vec![0u8; 3 * RS_BLOCK_DATA_CAP];
        r64.read_exact(&mut three_blocks).unwrap();
        assert_eq!(
            three_blocks,
            payload[seek_off as usize..seek_off as usize + three_blocks.len()]
        );
        {
            let pool = r64
                .inner
                .pool
                .as_ref()
                .expect("3-block seek read should spawn 2 helpers");
            assert_eq!(pool.helpers.len(), 2);
            assert_eq!(pool.helper_tasks_executed.load(Ordering::Relaxed), 2);
        }

        // Continuing sequentially from block 8 loads remaining 13 blocks (8..21) -> grows to 12 helpers.
        let mut tail = Vec::new();
        r64.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, payload[8 * RS_BLOCK_DATA_CAP..]);
        let pool = r64.inner.pool.as_ref().unwrap();
        assert_eq!(pool.helpers.len(), 12);
        assert_eq!(pool.helper_tasks_executed.load(Ordering::Relaxed), 2 + 12);
    }
}
