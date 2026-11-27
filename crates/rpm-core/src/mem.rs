//! Deterministic secret zeroization and best-effort OS page locking.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use zeroize::{Zeroize, ZeroizeOnDrop};

#[repr(C, align(32))]
struct AlignedKey([u8; 32]);

fn os_page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: POSIX `sysconf(_SC_PAGESIZE)` is thread-safe and has no preconditions.
        let sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if sz > 0 {
            return sz as usize;
        }
    }
    4096
}

fn page_locks() -> &'static Mutex<HashMap<usize, usize>> {
    static LOCKS: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_key_page(inner: &AlignedKey) -> Option<usize> {
    let page_size = os_page_size();
    let addr = inner.0.as_ptr() as usize;
    let page = addr & !(page_size - 1);
    let mut map = page_locks().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(count) = map.get_mut(&page) {
        *count += 1;
        return Some(page);
    }
    if lock_memory(page as *const u8, page_size) {
        map.insert(page, 1);
        Some(page)
    } else {
        None
    }
}

fn unlock_key_page(page: usize) {
    let page_size = os_page_size();
    let mut map = page_locks().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(count) = map.get_mut(&page) {
        if *count > 1 {
            *count -= 1;
            return;
        }
        // Hold the page-lock mutex across `unlock_memory` (matching `lock_key_page`)
        // so a concurrent allocation on the same OS page cannot be locked and then
        // silently unlocked by this thread.
        map.remove(&page);
        unlock_memory(page as *const u8, page_size);
    }
}

/// 32-byte symmetric key or entropy block stored at a stable 32-byte-aligned
/// heap address, pinned best-effort against swapping (`VirtualLock`/`mlock`)
/// using refcounted OS-page tracking, and scrubbed deterministically on drop.
pub struct SecretKey {
    inner: Box<AlignedKey>,
    locked_page: Option<usize>,
}

impl SecretKey {
    pub fn new(mut bytes: [u8; 32]) -> Self {
        let inner = Box::new(AlignedKey(bytes));
        bytes.zeroize();
        let locked_page = lock_key_page(&inner);
        Self { inner, locked_page }
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut inner = Box::new(AlignedKey([0u8; 32]));
        inner.0.copy_from_slice(slice);
        let locked_page = lock_key_page(&inner);
        Some(Self { inner, locked_page })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.inner.0
    }

    /// Returns `true` if the backing OS page was successfully pinned via `VirtualLock`/`mlock`.
    pub fn is_memory_locked(&self) -> bool {
        self.locked_page.is_some()
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        let inner = Box::new(AlignedKey(self.inner.0));
        let locked_page = lock_key_page(&inner);
        Self { inner, locked_page }
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.inner.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.inner.0.zeroize();
        if let Some(page) = self.locked_page.take() {
            unlock_key_page(page);
        }
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

/// Variable-length secret byte buffer zeroized deterministically on drop.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecretBuf(Vec<u8>);

impl SecretBuf {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBuf([REDACTED])")
    }
}

/// Best-effort OS page locking to reduce swap exposure. Failure is non-fatal
/// (processes may hit RLIMIT_MEMLOCK or working-set quotas on large allocations).
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if len == 0 || ptr.is_null() {
        return false;
    }
    #[cfg(windows)]
    {
        // SAFETY: `ptr` points to a live allocation of `len` bytes checked non-null above.
        unsafe { windows_sys::Win32::System::Memory::VirtualLock(ptr as *const _, len) != 0 }
    }
    #[cfg(all(unix, not(windows)))]
    {
        // SAFETY: `ptr` points to a live allocation of `len` bytes checked non-null above.
        unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

/// Matching best-effort unlock paired with `lock_memory`.
pub fn unlock_memory(ptr: *const u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }
    #[cfg(windows)]
    unsafe {
        let _ = windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *const _, len);
    }
    #[cfg(unix)]
    unsafe {
        let _ = libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn concurrent_secret_key_lock_and_unlock_keeps_page_refcounts_consistent() {
        let threads: Vec<_> = (0..8)
            .map(|tid| {
                thread::spawn(move || {
                    for iter in 0..256usize {
                        let byte = ((tid * 31 + iter) % 251) as u8;
                        let key = SecretKey::new([byte; 32]);
                        assert_eq!(key.as_bytes(), &[byte; 32]);
                        let cloned = key.clone();
                        assert_eq!(cloned.as_bytes(), &[byte; 32]);
                        drop(key);
                        drop(cloned);
                    }
                })
            })
            .collect();
        for handle in threads {
            handle.join().unwrap();
        }
        // Any remaining entry in `page_locks()` must have a positive refcount (from other
        // tests running concurrently in the same binary), never zero.
        let map = page_locks().lock().unwrap_or_else(|e| e.into_inner());
        assert!(map.values().all(|&count| count > 0));
        drop(map);

        // Verify multiple keys sharing the same 4 KiB OS page bump the refcount above 1
        // and keep the page pinned while at least one sibling key remains alive.
        let mut keys: Vec<SecretKey> = (0..128usize)
            .map(|i| SecretKey::new([(i as u8).wrapping_mul(7); 32]))
            .collect();
        let locked_pages: Vec<usize> = keys.iter().filter_map(|k| k.locked_page).collect();
        if locked_pages.len() >= 2 {
            let mut freq: HashMap<usize, usize> = HashMap::new();
            for p in &locked_pages {
                *freq.entry(*p).or_insert(0) += 1;
            }
            if let Some((&shared_page, &local_count)) = freq.iter().find(|(_, &c)| c >= 2) {
                {
                    let map = page_locks().lock().unwrap_or_else(|e| e.into_inner());
                    assert!(
                        map.get(&shared_page).copied().unwrap_or(0) >= local_count,
                        "shared page refcount under-counted"
                    );
                }
                // Drop exactly one key on `shared_page`; the page must remain in `page_locks()`
                // with refcount >= local_count - 1.
                let drop_pos = keys
                    .iter()
                    .position(|k| k.locked_page == Some(shared_page))
                    .unwrap();
                keys.remove(drop_pos);
                let map = page_locks().lock().unwrap_or_else(|e| e.into_inner());
                assert!(
                    map.get(&shared_page).copied().unwrap_or(0) >= local_count - 1,
                    "dropping one sibling key prematurely unlocked shared page"
                );
            }
        }
        drop(keys);
    }
}
