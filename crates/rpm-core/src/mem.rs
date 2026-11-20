//! Deterministic secret zeroization and best-effort OS page locking.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte symmetric key or entropy block stored on the heap, pinned best-effort
/// against swapping (`VirtualLock`/`mlock`) and scrubbed on drop.
#[derive(Clone, Zeroize)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        let s = Self(bytes);
        lock_memory(s.0.as_ptr(), s.0.len());
        s
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        let arr: [u8; 32] = slice.try_into().ok()?;
        Some(Self::new(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
        unlock_memory(self.0.as_ptr(), self.0.len());
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
pub fn lock_memory(ptr: *const u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }
    #[cfg(windows)]
    unsafe {
        let _ = windows_sys::Win32::System::Memory::VirtualLock(ptr as *const _, len);
    }
    #[cfg(unix)]
    unsafe {
        let _ = libc::mlock(ptr as *const libc::c_void, len);
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
