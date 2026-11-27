use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rpm_core::constants::{DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use rpm_core::{Auth, EncryptOptions, KdfParams};
use rpm_storage::pipe::{bounded_pipe, PIPE_MAX_CHUNK_BYTES};
use rpm_storage::{
    check_vault_integrity_with_parts_threads_and_cancel,
    decrypt_vault_v5_with_stealth_kdf_and_threads, encrypt_sources_v5_with_threads,
    extract_entry_to_memory_v5, extract_entry_to_memory_v5_with_stealth_kdf_and_threads,
    SecureWiper, StorageError,
};

static MEASUREMENT: Mutex<()> = Mutex::new(());
const MIB: usize = 1024 * 1024;

struct TrackingAllocator;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

// SAFETY: delegates unchanged pointer/layout to System; accounting uses atomics only.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            PEAK.fetch_max(
                CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size(),
                Ordering::SeqCst,
            );
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(p, layout) };
    }
}

fn reset_peak() -> usize {
    let baseline = CURRENT.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    baseline
}

fn peak_delta(baseline: usize) -> usize {
    PEAK.load(Ordering::SeqCst).saturating_sub(baseline)
}

#[test]
fn bounded_pipe_caps_peak_heap_on_16mib_chunk_writes() {
    let _guard = MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());

    // Pre-allocate the 16 MiB source payload outside the measured window.
    let payload: Vec<u8> = (0..(16 * MIB)).map(|i| (i % 251) as u8).collect();
    let expected_sum: u64 = payload.iter().map(|&b| u64::from(b)).sum();

    let baseline = reset_peak();
    let (mut tx, mut rx) = bounded_pipe(8);

    // Direct write() must cap each individual message at PIPE_MAX_CHUNK_BYTES (64 KiB).
    let first_written = tx.write(&payload).unwrap();
    assert_eq!(first_written, PIPE_MAX_CHUNK_BYTES);

    let reader = thread::spawn(move || {
        // Brief delay lets the writer completely saturate all 8 sync_channel slots before draining.
        thread::sleep(Duration::from_millis(20));
        let mut buf = [0u8; 32 * 1024];
        let mut total = 0usize;
        let mut sum = 0u64;
        loop {
            let n = rx.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            total += n;
            sum += buf[..n].iter().map(|&b| u64::from(b)).sum::<u64>();
        }
        (total, sum)
    });

    tx.write_all(&payload[first_written..]).unwrap();
    drop(tx);

    let (read_total, read_sum) = reader.join().unwrap();
    let delta = peak_delta(baseline);
    assert_eq!(read_total, payload.len());
    assert_eq!(read_sum, expected_sum);
    // Previously `bounded_pipe(8)` held up to 10 * 16 MiB = 160 MiB in flight!
    // With 64 KiB chunking, peak pipe delta stays well under 2 MiB.
    assert!(
        delta < 2 * MIB,
        "bounded_pipe(8) peak heap amplified to {} bytes (limit 2 MiB)",
        delta
    );
}

#[test]
fn decrypt_and_preview_peak_heap_bounded_for_1mib_and_16mib_chunks() {
    let _guard = MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());

    let dir = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let auth = || Auth::Password {
        password: b"MemGuard!1",
        keyfile_hash: None,
    };

    // 1. 1 MiB default chunk_size on a 6 MiB payload (previously ~19.25 MiB during decrypt).
    let src_1m = dir.path().join("six_mib.bin");
    fs::write(&src_1m, vec![0x3Au8; 6 * MIB]).unwrap();
    let vault_1m = dir.path().join("six_mib.vault");
    encrypt_sources_v5_with_threads(
        std::slice::from_ref(&src_1m),
        &vault_1m,
        b"MemGuard!1",
        &EncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        4,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();

    let out_1m = dir.path().join("out_1m");
    let baseline_1m = reset_peak();
    let dec_1m = decrypt_vault_v5_with_stealth_kdf_and_threads(
        &vault_1m,
        &out_1m,
        auth(),
        None,
        &KdfParams::fast_test(),
        4,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    let delta_1m = peak_delta(baseline_1m);
    assert_eq!(
        fs::metadata(&dec_1m.output_path).unwrap().len(),
        (6 * MIB) as u64
    );
    assert!(
        delta_1m < 13 * MIB,
        "1 MiB chunk decrypt peak heap too high: {} bytes",
        delta_1m
    );

    // 2. 16 MiB MAX_CHUNK_SIZE on a 17 MiB payload (previously ~177 MiB during decrypt!).
    let src_16m = dir.path().join("seventeen_mib.bin");
    {
        let mut f = fs::File::create(&src_16m).unwrap();
        let block = vec![0x7Cu8; MIB];
        for _ in 0..17 {
            f.write_all(&block).unwrap();
        }
    }
    let vault_16m = dir.path().join("seventeen_mib.vault");
    encrypt_sources_v5_with_threads(
        std::slice::from_ref(&src_16m),
        &vault_16m,
        b"MemGuard!1",
        &EncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: MAX_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        4,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();

    let out_16m = dir.path().join("out_16m");
    let baseline_16m = reset_peak();
    let dec_16m = decrypt_vault_v5_with_stealth_kdf_and_threads(
        &vault_16m,
        &out_16m,
        auth(),
        None,
        &KdfParams::fast_test(),
        4,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
    )
    .unwrap();
    let delta_16m = peak_delta(baseline_16m);
    assert_eq!(
        fs::metadata(&dec_16m.output_path).unwrap().len(),
        (17 * MIB) as u64
    );
    // With single-slot 16 MiB AEAD fallback + 64 KiB chunked bounded_pipe, peak heap stays
    // near ~18-24 MiB instead of ~177 MiB!
    assert!(
        delta_16m < 40 * MIB,
        "16 MiB chunk decrypt peak heap amplified: {} bytes (limit 40 MiB)",
        delta_16m
    );

    // 3. RAM preview peak heap on 2 MiB file inside 1 MiB chunk vault stays bounded.
    let src_prev = dir.path().join("preview_2m.bin");
    fs::write(&src_prev, vec![0x55u8; 2 * MIB]).unwrap();
    let vault_prev = dir.path().join("preview_2m.vault");
    encrypt_sources_v5_with_threads(
        std::slice::from_ref(&src_prev),
        &vault_prev,
        b"MemGuard!1",
        &EncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        4,
        Arc::new(|_, _| {}),
        Arc::clone(&cancel),
        |_| {},
    )
    .unwrap();

    let baseline_prev = reset_peak();
    let bytes = extract_entry_to_memory_v5_with_stealth_kdf_and_threads(
        &vault_prev,
        auth(),
        "preview_2m.bin",
        4 * MIB,
        &KdfParams::fast_test(),
        4,
        Arc::new(|_, _| {}),
        cancel,
    )
    .unwrap();
    let delta_prev = peak_delta(baseline_prev);
    assert_eq!(bytes.len(), 2 * MIB);
    assert!(
        delta_prev < 15 * MIB,
        "RAM preview peak heap too high: {} bytes",
        delta_prev
    );
}

#[test]
fn preview_mid_entry_cancellation_and_workflow_and_wiper_cancel_chains() {
    // Serialize with peak-heap tests in this binary so concurrent allocations don't skew
    // the process-wide `TrackingAllocator` peak reading.
    let _guard = MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let big_file = dir.path().join("big_preview.bin");
    fs::write(&big_file, vec![0x91u8; 6 * MIB]).unwrap();
    let vault = dir.path().join("big_preview.vault");

    let no_cancel = Arc::new(AtomicBool::new(false));
    encrypt_sources_v5_with_threads(
        std::slice::from_ref(&big_file),
        &vault,
        b"CancelTest!1",
        &EncryptOptions {
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            compressed: false,
            ..Default::default()
        },
        2,
        Arc::new(|_, _| {}),
        Arc::clone(&no_cancel),
        |_| {},
    )
    .unwrap();

    let auth = || Auth::Password {
        password: b"CancelTest!1",
        keyfile_hash: None,
    };

    // 1. Mid-entry preview cancellation trips inside `read_member` sliced read loop.
    let cancel_prev = Arc::new(AtomicBool::new(false));
    let cancel_cb = Arc::clone(&cancel_prev);
    let last_seen = Arc::new(AtomicU64::new(0));
    let last_cb = Arc::clone(&last_seen);
    let res = extract_entry_to_memory_v5(
        &vault,
        auth(),
        "big_preview.bin",
        8 * MIB,
        Arc::new(move |done, _| {
            last_cb.store(done, Ordering::Relaxed);
            if done >= 256 * 1024 {
                cancel_cb.store(true, Ordering::Relaxed);
            }
        }),
        Arc::clone(&cancel_prev),
    );
    assert!(
        matches!(res, Err(StorageError::Cancelled)),
        "expected Cancelled, got {res:?}"
    );
    assert!(
        last_seen.load(Ordering::Relaxed) < (4 * MIB) as u64,
        "preview failed to abort promptly mid-entry (read {} bytes)",
        last_seen.load(Ordering::Relaxed)
    );

    // 2. Pre-cancelled decrypt leaves output_root uncreated (zero staging dirs).
    let pre_cancel = Arc::new(AtomicBool::new(true));
    let fresh_out = dir.path().join("never_created_out");
    let dec_res = decrypt_vault_v5_with_stealth_kdf_and_threads(
        &vault,
        &fresh_out,
        auth(),
        None,
        &KdfParams::fast_test(),
        4,
        Arc::new(|_, _| {}),
        Arc::clone(&pre_cancel),
    );
    assert!(matches!(dec_res, Err(StorageError::Cancelled)));
    assert!(!fresh_out.exists());

    // 3. Pre-cancelled integrity check aborts cleanly with Cancelled.
    let int_res =
        check_vault_integrity_with_parts_threads_and_cancel(&vault, 4, Some(pre_cancel.as_ref()));
    assert!(matches!(int_res, Err(StorageError::Cancelled)));

    // 4. Cancellable SecureWiper leaves files & folders completely untouched when cancelled.
    let wipe_dir = dir.path().join("keep_me_dir");
    fs::create_dir(&wipe_dir).unwrap();
    let wipe_file = wipe_dir.join("precious.txt");
    fs::write(&wipe_file, b"do not destroy").unwrap();
    let wiper = SecureWiper::new(3);
    assert!(matches!(
        wiper.wipe_file_cancellable(&wipe_file, Some(pre_cancel.as_ref())),
        Err(StorageError::Cancelled)
    ));
    assert_eq!(fs::read(&wipe_file).unwrap(), b"do not destroy");
    assert!(matches!(
        wiper.wipe_folder_cancellable(&wipe_dir, Some(pre_cancel.as_ref())),
        Err(StorageError::Cancelled)
    ));
    assert_eq!(fs::read(&wipe_file).unwrap(), b"do not destroy");

    // 5. Mid-decrypt cancellation on a padded RS vault returns StorageError::Cancelled and
    //    cleans up the freshly created output & staging directories cleanly.
    let small_src = dir.path().join("padded_rs_src.txt");
    fs::write(&small_src, vec![0x4Au8; 64 * 1024]).unwrap();
    let padded_rs_vault = dir.path().join("padded_rs.vault");
    encrypt_sources_v5_with_threads(
        std::slice::from_ref(&small_src),
        &padded_rs_vault,
        b"CancelTest!1",
        &EncryptOptions {
            reed_solomon: true,
            kdf: KdfParams::fast_test(),
            chunk_size: MIN_CHUNK_SIZE,
            compressed: false,
            container_size_bytes: Some(512 * 1024),
            ..Default::default()
        },
        4,
        Arc::new(|_, _| {}),
        Arc::clone(&no_cancel),
        |_| {},
    )
    .unwrap();

    let mid_dec_cancel = Arc::new(AtomicBool::new(false));
    let mid_dec_cb = Arc::clone(&mid_dec_cancel);
    let mid_dec_out = dir.path().join("cancelled_padded_out");
    let mid_dec_res = decrypt_vault_v5_with_stealth_kdf_and_threads(
        &padded_rs_vault,
        &mid_dec_out,
        auth(),
        None,
        &KdfParams::fast_test(),
        4,
        Arc::new(move |done, _| {
            if done >= MIN_CHUNK_SIZE as u64 {
                mid_dec_cb.store(true, Ordering::Relaxed);
            }
        }),
        Arc::clone(&mid_dec_cancel),
    );
    assert!(
        matches!(mid_dec_res, Err(StorageError::Cancelled)),
        "expected StorageError::Cancelled on mid-decrypt padded RS cancel, got {mid_dec_res:?}"
    );
    assert!(
        !mid_dec_out.exists(),
        "cancelled decrypt left behind staging/output directory"
    );
}
