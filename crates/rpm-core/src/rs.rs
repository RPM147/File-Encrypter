//! Systematic shortened RS(255,239), first consecutive root 0, primitive element 2.
//! The envelope protects ciphertext against accidental damage; only the inner AEAD authenticates it.
#![forbid(unsafe_code)]

use crate::{CryptoError, VAULT_MAGIC};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::AtomicBool;

pub const NSYM: usize = 16;
const WORD: usize = 255;
const DATA: usize = WORD - NSYM;
const LANES: usize = 64;
pub const RS_BLOCK_DATA_CAP: usize = LANES * DATA - 4;
pub const RS_BLOCK_WIRE_SIZE: usize = LANES * WORD;
const HEADER: usize = 48;

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

/// Append systematic parity in the last 16 bytes (leading zero symbols may be shortened).
pub fn encode_codeword(word: &mut [u8]) -> io::Result<()> {
    if !(NSYM..=WORD).contains(&word.len()) {
        return Err(invalid());
    }
    let (data, parity) = word.split_at_mut(word.len() - NSYM);
    parity.fill(0);
    for &symbol in data.iter() {
        let lead = symbol ^ parity[0];
        for i in 0..NSYM - 1 {
            parity[i] = parity[i + 1] ^ mul(lead, GENERATOR[i + 1]);
        }
        parity[NSYM - 1] = mul(lead, GENERATOR[NSYM]);
    }
    Ok(())
}
fn syndromes(word: &[u8]) -> [u8; NSYM] {
    std::array::from_fn(|i| word.iter().fold(0, |acc, &b| mul(acc, GF.0[i]) ^ b))
}
// Locator/evaluator coefficients are stored in ascending powers.
fn evaluate(poly: &[u8], x: u8) -> u8 {
    poly.iter().rev().fold(0, |acc, &c| mul(acc, x) ^ c)
}

/// Locate and correct unknown symbol errors. A failed word is left untouched.
pub fn correct_codeword(word: &mut [u8]) -> io::Result<usize> {
    if !(NSYM..=WORD).contains(&word.len()) {
        return Err(invalid());
    }
    let s = syndromes(word);
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

// Keep only one interleaved block and a single contiguous codeword as scratch.
struct Block(Vec<u8>);
impl Block {
    fn new() -> Self {
        Self(vec![0; RS_BLOCK_WIRE_SIZE])
    }
    fn offset(inner: usize) -> usize {
        (inner % DATA) * LANES + inner / DATA
    }
    fn copy_out(&self, at: usize, out: &mut [u8]) {
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.0[Self::offset(at + i)];
        }
    }
    fn copy_in(&mut self, at: usize, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            self.0[Self::offset(at + i)] = b;
        }
    }
    fn words(&mut self, encode: bool) -> io::Result<u64> {
        let mut repaired = 0;
        for lane in 0..LANES {
            let mut word: [u8; WORD] = std::array::from_fn(|i| self.0[i * LANES + lane]);
            if encode {
                encode_codeword(&mut word)?;
            } else {
                let n = correct_codeword(&mut word)?;
                if n == 0 {
                    continue;
                }
                repaired += n as u64;
            }
            for (i, b) in word.into_iter().enumerate() {
                self.0[i * LANES + lane] = b;
            }
        }
        Ok(repaired)
    }
    fn read(&mut self, r: &mut impl Read, last: bool) -> io::Result<(usize, u64)> {
        r.read_exact(&mut self.0)?;
        let repaired = self.words(false)?;
        let mut raw = [0; 4];
        self.copy_out(0, &mut raw);
        let len = u32::from_be_bytes(raw) as usize;
        if len > RS_BLOCK_DATA_CAP
            || (!last && len != RS_BLOCK_DATA_CAP)
            || (len + 4..DATA * LANES).any(|i| self.0[Self::offset(i)] != 0)
        {
            return Err(invalid());
        }
        Ok((len, repaired))
    }
}

/// Recognize redundant headers even when the first magic is damaged. A sector
/// overwrite may destroy all three: corroborate the exact physical geometry
/// with a decodable first block carrying the inner v5 magic.
pub(crate) fn probe(r: &mut (impl Read + Seek)) -> io::Result<bool> {
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
    block: Block,
    used: usize,
    wrote: bool,
}
impl<W: Write> RsEncoderWriter<W> {
    pub fn new(mut inner: W) -> io::Result<Self> {
        inner.write_all(&PREFIX)?;
        Ok(Self {
            inner,
            block: Block::new(),
            used: 0,
            wrote: false,
        })
    }
    fn emit(&mut self) -> io::Result<()> {
        self.block.copy_in(0, &(self.used as u32).to_be_bytes());
        self.block.words(true)?;
        self.inner.write_all(&self.block.0)?;
        self.block.0.fill(0);
        self.used = 0;
        self.wrote = true;
        Ok(())
    }
    pub fn finish(mut self) -> io::Result<W> {
        if self.used > 0 || !self.wrote {
            self.emit()?;
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
}
impl<W: Write> Write for RsEncoderWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(RS_BLOCK_DATA_CAP - self.used);
        self.block.copy_in(4 + self.used, &data[..n]);
        self.used += n;
        if self.used == RS_BLOCK_DATA_CAP {
            self.emit()?;
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct RsSeekableReader<R> {
    inner: R,
    blocks: u64,
    pos: u64,
    len: u64,
    cache: Block,
    cached: Option<u64>,
    repaired: u64,
    last_block_counted: bool,
}
impl<R: Read + Seek> RsSeekableReader<R> {
    pub fn new(mut inner: R) -> io::Result<Self> {
        if !probe(&mut inner)? {
            return Err(invalid());
        }
        let blocks = block_count(inner.seek(SeekFrom::End(0))?)?;
        inner.rewind()?;
        let mut h = [0; HEADER];
        inner.read_exact(&mut h)?;
        check_profile(&h)?;
        let mut reader = Self {
            inner,
            blocks,
            pos: 0,
            len: 0,
            cache: Block::new(),
            cached: None,
            repaired: differences(&h),
            last_block_counted: false,
        };
        let last = reader.load(blocks - 1)?;
        reader.len = (blocks - 1) * RS_BLOCK_DATA_CAP as u64 + last as u64;
        Ok(reader)
    }
    fn load(&mut self, index: u64) -> io::Result<usize> {
        self.cached = None;
        let is_last = index + 1 == self.blocks;
        self.inner.seek(SeekFrom::Start(
            HEADER as u64 + index * RS_BLOCK_WIRE_SIZE as u64,
        ))?;
        let (len, count) = self.cache.read(&mut self.inner, is_last)?;
        if len == 0 && self.blocks != 1 {
            return Err(invalid());
        }
        self.cached = Some(index);
        if !(is_last && self.last_block_counted) {
            self.repaired += count;
        }
        if is_last {
            self.last_block_counted = true;
        }
        Ok(len)
    }
    /// Corrections encountered during reads (counts the pre-inspected final block once; revisited blocks recount).
    pub fn repaired_bytes(&self) -> u64 {
        self.repaired
    }
}
impl<R: Read + Seek> Read for RsSeekableReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || out.is_empty() {
            return Ok(0);
        }
        let index = self.pos / RS_BLOCK_DATA_CAP as u64;
        let start = (self.pos % RS_BLOCK_DATA_CAP as u64) as usize;
        if self.cached != Some(index) {
            self.load(index)?;
        }
        let n = (out.len().min(RS_BLOCK_DATA_CAP - start) as u64).min(self.len - self.pos) as usize;
        self.cache.copy_out(4 + start, &mut out[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}
impl<R: Read + Seek> Seek for RsSeekableReader<R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.pos = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"))?;
        Ok(self.pos)
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RepairReport {
    pub blocks_checked: u64,
    pub repaired_bytes: u64,
    pub header_repaired: bool,
}

// Forward-only decoder shared by passwordless structural scanning and repair.
// Disk bytes can be hashed below this adapter, before any correction.
pub(crate) struct Scan<R> {
    inner: R,
    block: Block,
    count: u64,
    next: u64,
    offset: usize,
    len: usize,
    pub report: RepairReport,
}
impl<R: Read> Scan<R> {
    pub fn new(mut inner: R, size: u64) -> io::Result<Self> {
        let count = block_count(size)?;
        let mut prefix = [0; HEADER];
        inner.read_exact(&mut prefix)?;
        check_profile(&prefix)?;
        let changed = differences(&prefix);
        Ok(Self {
            inner,
            block: Block::new(),
            count,
            next: 0,
            offset: 0,
            len: 0,
            report: RepairReport {
                blocks_checked: 0,
                repaired_bytes: changed,
                header_repaired: changed != 0,
            },
        })
    }
    pub fn next_block(&mut self) -> io::Result<bool> {
        if self.next == self.count {
            return Ok(false);
        }
        self.next += 1;
        self.len = 0;
        self.offset = 0;
        let (len, n) = self.block.read(&mut self.inner, self.next == self.count)?;
        if len == 0 && self.count != 1 {
            return Err(invalid());
        }
        self.len = len;
        self.report.blocks_checked += 1;
        self.report.repaired_bytes += n;
        Ok(true)
    }
}
impl<R: Read> Read for Scan<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.offset == self.len && !self.next_block()? {
            return Ok(0);
        }
        let n = out.len().min(self.len - self.offset);
        self.block.copy_out(4 + self.offset, &mut out[..n]);
        self.offset += n;
        Ok(n)
    }
}
// Feed corrected inner bytes to the existing structural validator while writing
// each corrected wire block exactly once. In particular, dropping a whole RS
// block can leave valid syndromes while truncating the inner v5 container.
struct RepairScan<'a, R, W> {
    scan: Scan<R>,
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
            if let Err(e) = self.writer.write_all(&self.scan.block.0) {
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
    if crate::vault::is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }
    if !probe(reader)? {
        return Err(CryptoError::UnsupportedOperation(
            "Reed-Solomon protection is required for repair".into(),
        ));
    }
    let size = reader.seek(SeekFrom::End(0))?;
    reader.rewind()?;
    let scan = Scan::new(reader, size)?;
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
    let (ok, _, message, ..) = crate::vault::scan_structure(&mut repair);
    if let Some(e) = repair.write_error {
        return Err(e.into());
    }
    if let Some(e) = repair.read_error {
        return Err(e.into());
    }
    if crate::vault::is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
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
