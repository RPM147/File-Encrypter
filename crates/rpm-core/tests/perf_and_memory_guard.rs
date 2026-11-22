use rpm_core::*;
use sha2::{Digest, Sha256};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    sync::atomic::{AtomicUsize, Ordering::SeqCst},
    time::Instant,
};

static MEASUREMENT: std::sync::Mutex<()> = std::sync::Mutex::new(());
const MIB: usize = 1024 * 1024;

struct TrackingAllocator;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

// SAFETY: each operation delegates the unchanged pointer/layout to System.
// Accounting performs only atomic operations and never allocates or unwinds.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            PEAK.fetch_max(
                CURRENT.fetch_add(layout.size(), SeqCst) + layout.size(),
                SeqCst,
            );
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), SeqCst);
        unsafe { System.dealloc(p, layout) };
    }
}

fn reset_peak() -> usize {
    let baseline = CURRENT.load(SeqCst);
    PEAK.store(baseline, SeqCst);
    baseline
}

struct RepeatingStreamReader(usize);
impl Read for RepeatingStreamReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.0.min(out.len());
        out[..n].fill(0xa7);
        self.0 -= n;
        Ok(n)
    }
}

#[derive(Default)]
struct Sha256Sink(Sha256);
impl Write for Sha256Sink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CountingSeekReader {
    file: File,
    bytes: u64,
}
impl Read for CountingSeekReader {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read(b)?;
        self.bytes += n as u64;
        Ok(n)
    }
}
impl Seek for CountingSeekReader {
    fn seek(&mut self, s: SeekFrom) -> io::Result<u64> {
        self.file.seek(s)
    }
}

fn disk_hash(file: &mut File) -> [u8; 32] {
    file.rewind().unwrap();
    let mut sink = Sha256Sink::default();
    io::copy(file, &mut sink).unwrap();
    sink.0.finalize().into()
}

fn io_guard(name: &str, read: u64, len: u64) {
    println!(
        "IO  {name:<16} {read}/{len} ({:.5}x)",
        read as f64 / len as f64
    );
    assert!(read <= len + len / 20 + 16384, "{name}: {read} bytes");
}

fn scenario(name: &str, size: usize, guards: bool) {
    let rs = name == "RS";
    let stealth = name == "Stealth";
    let opts = EncryptOptions {
        reed_solomon: rs,
        stealth,
        kdf: if stealth {
            STEALTH_KDF_PARAMS
        } else {
            KdfParams::fast_test()
        },
        compressed: false,
        ..Default::default()
    };
    assert_eq!(opts.chunk_size as usize, MIB);
    let meta = VaultMetadata {
        filename: "sample".into(),
        source_type: "file".into(),
        file_count: 1,
        original_size: size as u64,
        created_at: String::new(),
        compressed: false,
        files: vec![],
    };
    let mut expected = Sha256Sink::default();
    io::copy(&mut RepeatingStreamReader(size), &mut expected).unwrap();
    let expected = expected.0.finalize();
    let mut file = tempfile::tempfile().unwrap();

    let stream_limit = if rs { 12 * MIB } else { 10 * MIB };
    let stealth_encrypt_limit = 64 * MIB + 10 * MIB;
    let record = |op: &str, start: Instant, baseline: usize, limit: usize| {
        let delta = PEAK.load(SeqCst) - baseline;
        let secs = start.elapsed().as_secs_f64();
        let mib_s = size as f64 / MIB as f64 / secs;
        let peak_mib = delta as f64 / MIB as f64;
        println!(
            "{name:<10} | {op:<8} | {:>8.2} | {:>11.2} | {:>8.4} MiB ({delta} B)",
            secs * 1000.,
            mib_s,
            peak_mib
        );
        if guards {
            assert!(delta < limit, "{name} {op}: {delta} >= {limit}");
        }
    };

    let baseline = reset_peak();
    let start = Instant::now();
    encrypt_stream(
        &mut RepeatingStreamReader(size),
        &mut file,
        &meta,
        b"test",
        &opts,
        |_| {},
        None,
    )
    .unwrap();
    record(
        "encrypt",
        start,
        baseline,
        if stealth {
            stealth_encrypt_limit
        } else {
            stream_limit
        },
    );

    let len = file.metadata().unwrap().len();
    let hash = disk_hash(&mut file);
    let mut reader = CountingSeekReader { file, bytes: 0 };
    let auth = Auth::Password {
        password: b"test",
        keyfile_hash: None,
    };

    let baseline = reset_peak();
    let start = Instant::now();
    let unlocked = unlock_seekable(&mut reader, auth).unwrap();
    let baseline = if stealth { reset_peak() } else { baseline };
    let mut output = Sha256Sink::default();
    decrypt_unlocked_stream(&mut reader, &mut output, &unlocked, |_| {}, None).unwrap();
    record("decrypt", start, baseline, stream_limit);
    assert_eq!(output.0.finalize(), expected);
    if guards {
        io_guard(&format!("{name} decrypt"), reader.bytes, len);
    }

    reader.bytes = 0;
    if rs {
        let baseline = reset_peak();
        let start = Instant::now();
        let mut fixed = Sha256Sink::default();
        repair_vault_stream(&mut reader, &mut fixed, None).unwrap();
        record("repair", start, baseline, stream_limit);
        assert_eq!(<[u8; 32]>::from(fixed.0.finalize()), hash);
        if guards {
            io_guard("RS repair", reader.bytes, len);
        }
    } else if stealth && guards {
        let report = rpm_core::vault::check_integrity_reader(&mut reader).unwrap();
        assert!(report.sha256_only);
        assert_eq!(
            report.sha256_hex,
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        io_guard("Stealth verify", reader.bytes, len);
    }
}

#[test]
fn peak_heap_and_single_pass_io() {
    let _guard = MEASUREMENT.lock().unwrap();
    println!("Mode       | Op       |  Time ms |       MiB/s | Peak Heap");
    for mode in ["Standard", "RS", "Stealth"] {
        scenario(mode, 16 * MIB, true);
    }
}

#[test]
#[ignore = "release throughput benchmark"]
fn bench_throughput_summary() {
    let _guard = MEASUREMENT.lock().unwrap();
    println!("Mode       | Op       |  Time ms |       MiB/s | Peak Heap");
    println!("-----------+----------+----------+-------------+----------------------------");
    for mode in ["Standard", "RS", "Stealth"] {
        scenario(mode, 16 * MIB, false);
    }
}
